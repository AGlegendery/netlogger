#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for netlogger.  Run with:

    python3 -m unittest discover -s tests -v

Everything here feeds real Ethernet/IP/TCP/UDP frames through the same code
path the live sniffer uses, so no root privileges are required.
"""

import argparse
import csv
import io
import json
import os
import socket
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import netlogger as nl  # noqa: E402

PROC = nl.ProcMap(ttl=1e9)
PROC.refresh(time.time(), force=True)


# --------------------------------------------------------------------------- #
#  frame builders
# --------------------------------------------------------------------------- #

def tcp_frame(payload: bytes, sport: int, dport: int,
              src: str = "10.0.0.2", dst: str = "93.184.216.34",
              flags: int = 0x18, seq: int = 1) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + tcp
    return b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", nl.ETH_P_IP) + ip


def udp_frame(payload: bytes, sport: int, dport: int,
              src: str = "10.0.0.2", dst: str = "10.0.0.1") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + udp
    return b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", nl.ETH_P_IP) + ip


def ipv6_tcp_frame(payload: bytes, sport: int, dport: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 8192, 0, 0) + payload
    src = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    dst = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    ip = struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + src + dst + tcp
    return b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", nl.ETH_P_IPV6) + ip


def vlan_frame(inner: bytes, vid: int = 5) -> bytes:
    return inner[:12] + struct.pack("!HH", 0x8100, vid) + inner[12:]


def sll_frame(inner: bytes) -> bytes:
    """A cooked (SLL) header: 16 bytes, protocol in the last two."""
    return struct.pack("!HHH8s", 0, 1, 6, b"\x00" * 8) + inner[12:]


def client_hello(sni: str = "download.example.com", alpn: str = "h2") -> bytes:
    s = sni.encode()
    ext_sni = b"\x00\x00" + struct.pack("!H", len(s) + 5) + struct.pack("!H", len(s) + 3) + b"\x00" + struct.pack("!H", len(s)) + s
    a = bytes([len(alpn)]) + alpn.encode()
    ext_alpn = b"\x00\x10" + struct.pack("!H", len(a) + 2) + struct.pack("!H", len(a)) + a
    ext_ver = b"\x00\x2b\x00\x03\x02\x03\x04"
    exts = ext_sni + ext_alpn + ext_ver
    hs = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" \
        + struct.pack("!H", len(exts)) + exts
    ch = b"\x01" + len(hs).to_bytes(3, "big") + hs
    return b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch


def client_hello_no_sni() -> bytes:
    hs = b"\x03\x03" + b"\x22" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + b"\x00\x00"
    ch = b"\x01" + len(hs).to_bytes(3, "big") + hs
    return b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch


def dns_query(name: str, qid: int = 0x1234) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def dns_response(name: str, ips, qid: int = 0x1234) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    out = struct.pack("!HHHHHH", qid, 0x8180, 1, len(ips), 0, 0) + qname + struct.pack("!HH", 1, 1)
    for ip in ips:
        out += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return out


REQ = (b"GET /package1.zip?token=abc HTTP/1.1\r\n"
       b"Host: download.example.com\r\n"
       b"User-Agent: curl/8.5.0\r\n"
       b"Accept: */*\r\n\r\n")

RESP_BODY = b"Z" * 5000


def http_response(status: int = 200, length: int = len(RESP_BODY)) -> bytes:
    return (f"HTTP/1.1 {status} OK\r\nContent-Length: {length}\r\n"
            f"Content-Type: application/zip\r\nServer: nginx/1.25\r\n\r\n").encode() + RESP_BODY


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #

def make_cfg(**over) -> argparse.Namespace:
    base = dict(idle=0.2, live=False, dns=False, all=False, domain_only=False)
    base.update(over)
    return argparse.Namespace(**base)


class Capture:
    """Runs frames through an Engine and stores emitted records."""

    def __init__(self, **cfg):
        self.records = []
        self.partials = []
        self.engine = nl.Engine(make_cfg(**cfg), self._emit, proc=PROC, dns=nl.DnsCache())
        self.link = nl.Link("test", None, nl.ARPHRD_ETHER, "eth")

    def _emit(self, rec, partial):
        (self.partials if partial else self.records).append(rec)

    def feed(self, frame: bytes, ts: float = 1000.0) -> None:
        self.engine.process_frame(frame, ts, self.link)

    def finish(self, ts: float = 1100.0):
        self.engine.finish(ts)
        return self.records


def emitter_args(**over):
    base = dict(format="pretty", binary=False, width=110, out=None, quiet=True, log=None,
                host=None, exclude_host=None, app=None, exclude_app=None, pid=None,
                method=None, port=None, min_size=0, max_size=None, full_url=False,
                peer=False, watch=None)
    base.update(over)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------- #
#  tests
# --------------------------------------------------------------------------- #

class TestFormatting(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(nl.human_bytes(0), "0 B")
        self.assertEqual(nl.human_bytes(999), "999 B")
        self.assertEqual(nl.human_bytes(1000), "1.00 KB")
        self.assertEqual(nl.human_bytes(12_612_400), "12.6 MB")
        self.assertEqual(nl.human_bytes(1_500_000_000), "1.50 GB")
        self.assertEqual(nl.human_bytes(1024, binary=True), "1.00 KiB")
        self.assertEqual(nl.human_bytes(None), "-")

    def test_parse_size(self):
        self.assertEqual(nl.parse_size("512"), 512)
        self.assertEqual(nl.parse_size("1K"), 1000)
        self.assertEqual(nl.parse_size("1M"), 1_000_000)
        self.assertEqual(nl.parse_size("2GiB"), 2_000_000_000)
        with self.assertRaises(ValueError):
            nl.parse_size("banana")

    def test_truncate_tail_keeps_filename(self):
        out = nl.truncate_tail("/a/very/long/path/to/package-1.2.3.zip", 30)
        self.assertEqual(len(out), 30)
        self.assertTrue(out.endswith(".zip"))
        self.assertIn("…", out)

    def test_vlen_ignores_ansi(self):
        c = nl.Color(True)
        self.assertEqual(nl.vlen(c.fg("abc", 42)), 3)

    def test_color_off(self):
        self.assertEqual(nl.Color(False).fg("x", 42), "x")

    def test_duration(self):
        self.assertEqual(nl.human_duration(0.5), "500ms")
        self.assertEqual(nl.human_duration(2), "2.00s")
        self.assertEqual(nl.human_duration(75), "1:15")


class TestParsers(unittest.TestCase):
    def test_http_request(self):
        info = nl.parse_http_request(REQ)
        self.assertIsNotNone(info)
        self.assertEqual(info["method"], "GET")
        self.assertEqual(info["host"], "download.example.com")
        self.assertEqual(info["path"], "/package1.zip")
        self.assertEqual(info["query"], "token=abc")
        self.assertEqual(info["app"], "HTTP")

    def test_http_request_with_port_and_host_header(self):
        info = nl.parse_http_request(b"POST /api HTTP/1.1\r\nHost: example.com:8080\r\n"
                                     b"Content-Length: 10\r\n\r\n0123456789")
        self.assertEqual(info["host"], "example.com")
        self.assertEqual(info["port"], "8080")
        self.assertEqual(info["content_length"], 10)
        self.assertEqual(info["method"], "POST")

    def test_websocket_upgrade(self):
        info = nl.parse_http_request(b"GET /feed HTTP/1.1\r\nHost: s.example\r\n"
                                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.assertEqual(info["app"], "WS")
        self.assertEqual(info["scheme"], "ws")

    def test_proxy_absolute_form(self):
        info = nl.parse_http_request(b"GET https://cdn.example.com/x.js?q=1 HTTP/1.1\r\n"
                                     b"Host: cdn.example.com\r\n\r\n")
        self.assertEqual(info["host"], "cdn.example.com")
        self.assertEqual(info["path"], "/x.js")
        self.assertEqual(info["query"], "q=1")
        self.assertEqual(info["scheme"], "https")

    def test_connect(self):
        info = nl.parse_http_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        self.assertEqual(info["method"], "CONNECT")
        self.assertEqual(info["host"], "example.com")
        self.assertEqual(info["port"], "443")

    def test_not_http(self):
        self.assertIsNone(nl.parse_http_request(b"\x16\x03\x01\x00\x05hello"))
        self.assertIsNone(nl.parse_http_request(b"hello world\r\n\r\n"))
        self.assertIsNone(nl.parse_http_request(b""))

    def test_http_response(self):
        info = nl.parse_http_response(http_response(404, 12))
        self.assertEqual(info["status"], 404)
        self.assertEqual(info["content_length"], 12)
        self.assertEqual(info["content_type"], "application/zip")
        self.assertEqual(info["server"], "nginx/1.25")

    def test_chunked(self):
        info = nl.parse_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        self.assertTrue(info["chunked"])

    def test_tls_client_hello(self):
        info = nl.parse_tls_client_hello(client_hello("example.org", "h2"))
        self.assertEqual(info["sni"], "example.org")
        self.assertEqual(info["alpn"], ["h2"])
        self.assertEqual(info["version"], "1.3")

    def test_tls_client_hello_no_sni(self):
        info = nl.parse_tls_client_hello(client_hello_no_sni())
        self.assertIsNone(info["sni"])
        self.assertEqual(info["alpn"], [])

    def test_tls_rejects_garbage(self):
        self.assertIsNone(nl.parse_tls_client_hello(b"\x16\x03\x01\x00\x02\x01\x00"))
        self.assertIsNone(nl.parse_tls_client_hello(b""))

    def test_dns(self):
        info = nl.parse_dns(dns_query("download.example.com"))
        self.assertEqual(info["name"], "download.example.com")
        self.assertFalse(info["response"])
        info = nl.parse_dns(dns_response("cdn.example.com", ["1.2.3.4"]))
        self.assertTrue(info["response"])
        self.assertEqual(info["answers"], ["1.2.3.4"])

    def test_dns_rejects(self):
        self.assertIsNone(nl.parse_dns(b"\x00" * 4))

    def test_hpack_static(self):
        self.assertEqual(nl.parse_h2_method(b"\x82"), "GET")
        self.assertEqual(nl.parse_h2_method(b"\x83"), "POST")
        self.assertIsNone(nl.parse_h2_method(b"\x84"))

    def test_h2_headers_frame(self):
        block = b"\x82"                       # indexed :method: GET
        frame = len(block).to_bytes(3, "big") + b"\x01\x04" + (1).to_bytes(4, "big") + block
        self.assertEqual(nl.parse_h2_headers_frame(frame), "GET")

    def test_hex_ip(self):
        self.assertEqual(nl._hex_ip("0100007F"), "127.0.0.1")
        self.assertEqual(nl._hex_ip("00000000000000000000000001000000"), "::1")

    def test_norm_ip(self):
        self.assertEqual(nl.norm_ip("::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(nl.norm_ip("2001:DB8::1"), "2001:db8::1")


class TestPacketParsing(unittest.TestCase):
    def test_ipv4_tcp(self):
        parsed = nl.parse_ipv4(tcp_frame(b"hello", 1234, 80), 14)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], 4)
        self.assertEqual(parsed[1], "10.0.0.2")
        self.assertEqual(parsed[3], 6)
        seg = nl.parse_tcp(parsed[4])
        self.assertEqual(seg[0], 1234)
        self.assertEqual(seg[1], 80)
        self.assertEqual(seg[5], b"hello")

    def test_ipv6_tcp(self):
        parsed = nl.parse_ipv6(ipv6_tcp_frame(b"hi", 1234, 443), 14)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[1], "2001:db8::1")
        self.assertEqual(parsed[3], 6)
        self.assertEqual(nl.parse_tcp(parsed[4])[5], b"hi")

    def test_ipv4_non_first_fragment_skipped(self):
        frame = bytearray(tcp_frame(b"x", 1, 2))
        struct.pack_into("!H", frame, 14 + 6, 0x0001)   # fragment offset 1
        self.assertIsNone(nl.parse_ipv4(bytes(frame), 14))

    def test_truncated_packets(self):
        self.assertIsNone(nl.parse_ipv4(b"\x45" * 5, 0))
        self.assertIsNone(nl.parse_ipv6(b"\x60" * 10, 0))
        self.assertIsNone(nl.parse_tcp(b"\x00" * 4))
        self.assertIsNone(nl.parse_udp(b"\x00" * 4))

    def test_udp(self):
        parsed = nl.parse_ipv4(udp_frame(b"abc", 5353, 53), 14)
        self.assertEqual(parsed[3], 17)
        self.assertEqual(nl.parse_udp(parsed[4])[2], b"abc")


class TestPipelineHTTP(unittest.TestCase):
    def test_get_download(self):
        cap = Capture()
        cap.feed(tcp_frame(REQ, 52310, 80), 1000.0)
        cap.feed(tcp_frame(http_response(), 80, 52310, src="93.184.216.34", dst="10.0.0.2"), 1000.4)
        cap.feed(tcp_frame(b"", 52310, 80, flags=0x11), 0.5 + 1000.4)  # FIN
        recs = cap.finish(1001.0)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r.badge(), "GET")
        self.assertEqual(r.host, "download.example.com")
        self.assertEqual(r.path, "/package1.zip")
        self.assertEqual(r.query, "token=abc")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.app, "HTTP")
        self.assertEqual(r.bytes_out, len(REQ))
        self.assertEqual(r.bytes_in, len(http_response()))
        self.assertEqual(r.bytes_total, len(REQ) + len(http_response()))
        self.assertEqual(r.content_length, len(RESP_BODY))
        self.assertEqual(r.server_port, 80)
        self.assertFalse(r.show_port)
        self.assertEqual(r.url(), "http://download.example.com/package1.zip?token=abc")

    def test_syn_sets_direction_without_payload(self):
        cap = Capture()
        cap.feed(tcp_frame(b"", 40000, 80, flags=0x02), 1000.0)       # SYN
        cap.feed(tcp_frame(b"", 80, 40000, src="93.184.216.34", dst="10.0.0.2", flags=0x12), 1000.1)
        cap.feed(tcp_frame(REQ, 40000, 80), 1000.2)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].bytes_out, len(REQ))
        self.assertIn("40000", recs[0].client)

    def test_response_first_midstream(self):
        cap = Capture()
        # netlogger started while a download was already running
        cap.feed(tcp_frame(http_response(), 80, 51000, src="93.184.216.34", dst="10.0.0.2"), 1000.0)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].status, 200)
        self.assertEqual(recs[0].app, "HTTP")
        self.assertEqual(recs[0].bytes_in, len(http_response()))
        self.assertEqual(recs[0].bytes_out, 0)

    def test_http_on_unusual_port(self):
        cap = Capture()
        cap.feed(tcp_frame(REQ, 52310, 8080), 1000.0)
        recs = cap.finish(1010.0)
        self.assertEqual(recs[0].badge(), "GET")
        self.assertTrue(recs[0].show_port)
        self.assertIn(":8080", recs[0].url())

    def test_keepalive_second_request_not_duplicated(self):
        cap = Capture()
        cap.feed(tcp_frame(REQ, 52310, 80), 1000.0)
        cap.feed(tcp_frame(REQ, 52310, 80), 1000.2)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].bytes_out, 2 * len(REQ))

    def test_websocket_record(self):
        cap = Capture()
        ws = (b"GET /live/feed HTTP/1.1\r\nHost: stream.example.com\r\n"
              b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
        cap.feed(tcp_frame(ws, 52310, 80), 1000.0)
        cap.feed(tcp_frame(b"\x81\x05hello", 80, 52310, src="93.184.216.34", dst="10.0.0.2"), 1001.0)
        recs = cap.finish(1010.0)
        self.assertEqual(recs[0].badge(), "WS")
        self.assertEqual(recs[0].app, "WS")
        self.assertGreater(recs[0].bytes_in, 0)


class TestPipelineTLS(unittest.TestCase):
    def test_tls_with_sni(self):
        cap = Capture()
        hello = client_hello("cdn.example.org", "h2")
        cap.feed(tcp_frame(hello, 50000, 443), 1000.0)
        cap.feed(tcp_frame(b"\x16\x03\x03\x00\x10" + b"\x00" * 16, 443, 50000,
                           src="93.184.216.34", dst="10.0.0.2"), 1000.1)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r.app, "H2")
        self.assertEqual(r.badge(), "H2")
        self.assertEqual(r.host, "cdn.example.org")
        self.assertEqual(r.sni, "cdn.example.org")
        self.assertEqual(r.tls, "1.3")
        self.assertIn("encrypted", r.notes)
        self.assertTrue(r.url().startswith("https://cdn.example.org"))

    def test_tls_split_across_segments(self):
        hello = client_hello("split.example.net", "http/1.1")
        cap = Capture()
        cap.feed(tcp_frame(hello[:20], 50000, 443), 1000.0)
        cap.feed(tcp_frame(hello[20:60], 50000, 443), 1000.05)
        cap.feed(tcp_frame(hello[60:], 50000, 443), 1000.1)
        recs = cap.finish(1010.0)
        self.assertEqual(recs[0].host, "split.example.net")
        self.assertEqual(recs[0].app, "HTTPS")
        self.assertEqual(recs[0].bytes_out, len(hello))

    def test_tls_no_sni_uses_dns_cache(self):
        cap = Capture(dns=False)
        cap.feed(udp_frame(dns_query("files.example.com"), 40000, 53, dst="10.0.0.1"), 1000.0)
        cap.feed(udp_frame(dns_response("files.example.com", ["10.9.9.9"]), 53, 40000,
                           src="10.0.0.1", dst="10.0.0.2"), 1000.05)
        cap.feed(tcp_frame(client_hello_no_sni(), 50000, 443, src="10.0.0.2", dst="10.9.9.9"), 1000.1)
        recs = cap.finish(1010.0)
        tls_recs = [r for r in recs if r.app == "HTTPS"]
        self.assertEqual(len(tls_recs), 1)
        self.assertEqual(tls_recs[0].host, "files.example.com")

    def test_quic(self):
        cap = Capture()
        quic = b"\xc3\x00\x00\x00\x01" + b"\x00" * 40
        cap.feed(udp_frame(quic, 55000, 443, dst="142.250.185.78"), 1000.0)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].app, "QUIC")
        self.assertEqual(recs[0].badge(), "QUIC")


class TestPipelineDNS(unittest.TestCase):
    def test_dns_hidden_by_default(self):
        cap = Capture(dns=False)
        cap.feed(udp_frame(dns_query("example.com"), 40000, 53, dst="10.0.0.1"), 1000.0)
        self.assertEqual(cap.finish(1010.0), [])

    def test_dns_shown_with_flag(self):
        cap = Capture(dns=True)
        cap.feed(udp_frame(dns_query("example.com"), 40000, 53, dst="10.0.0.1"), 1000.0)
        cap.feed(udp_frame(dns_response("example.com", ["93.184.216.34"]), 53, 40000,
                           src="10.0.0.1", dst="10.0.0.2"), 1000.05)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].badge(), "DNS")
        self.assertEqual(recs[0].host, "example.com")
        self.assertIn("93.184.216.34", recs[0].notes)

    def test_dns_cache_remembers_names(self):
        cap = Capture(dns=False)
        cap.feed(udp_frame(dns_response("cdn.example.com", ["10.1.1.1"]), 53, 40000,
                           src="10.0.0.1", dst="10.0.0.2"), 1000.0)
        self.assertEqual(cap.engine.dns.name_for("10.1.1.1"), "cdn.example.com")


class TestPipelineMisc(unittest.TestCase):
    def test_ipv6_flow(self):
        cap = Capture()
        cap.feed(ipv6_tcp_frame(REQ, 52310, 80), 1000.0)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].badge(), "GET")
        self.assertIn("2001:db8::1", recs[0].client)

    def test_vlan_tagged(self):
        cap = Capture()
        cap.feed(vlan_frame(tcp_frame(REQ, 52310, 80)), 1000.0)
        self.assertEqual(cap.finish(1010.0)[0].badge(), "GET")

    def test_sll_fallback(self):
        cap = Capture()
        link = nl.Link("cooked", None, 1, "auto")
        cap.engine.process_frame(sll_frame(tcp_frame(REQ, 52310, 80)), 1000.0, link)
        self.assertEqual(link.mode, "sll")
        records = cap.finish(1010.0)
        self.assertEqual(records[0].badge(), "GET")

    def test_unknown_small_flow_not_reported(self):
        cap = Capture()
        cap.feed(tcp_frame(b"\x01" * 100, 52310, 9999), 1000.0)
        self.assertEqual(cap.finish(1010.0), [])

    def test_unknown_big_flow_reported(self):
        cap = Capture()
        cap.feed(tcp_frame(b"\x01" * 40000, 52310, 9999), 1000.0)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].badge(), "TCP")
        self.assertEqual(recs[0].bytes_out, 40000)

    def test_unknown_big_flow_with_all(self):
        cap = Capture(all=True)
        cap.feed(tcp_frame(b"\x01" * 10, 52310, 9999), 1000.0)
        self.assertEqual(len(cap.finish(1010.0)), 1)

    def test_h2_prior_knowledge(self):
        cap = Capture()
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        block = b"\x82"
        frame = len(block).to_bytes(3, "big") + b"\x01\x04" + (1).to_bytes(4, "big") + block
        cap.feed(tcp_frame(preface + frame, 52310, 80), 1000.0)
        recs = cap.finish(1010.0)
        self.assertEqual(recs[0].app, "H2")
        self.assertEqual(recs[0].badge(), "GET")

    def test_two_flows_are_separate(self):
        cap = Capture()
        cap.feed(tcp_frame(REQ, 52310, 80), 1000.0)
        cap.feed(tcp_frame(REQ.replace(b"package1", b"package2"), 52311, 80), 1000.1)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 2)
        paths = sorted(r.path for r in recs)
        self.assertEqual(paths, ["/package1.zip", "/package2.zip"])

    def test_live_partial_then_final(self):
        cap = Capture(live=True)
        cap.feed(tcp_frame(REQ, 52310, 80), 1000.0)
        self.assertEqual(len(cap.partials), 1)
        self.assertTrue(cap.partials[0].partial)
        cap.feed(tcp_frame(http_response(), 80, 52310, src="93.184.216.34", dst="10.0.0.2"), 1000.3)
        recs = cap.finish(1010.0)
        self.assertEqual(len(recs), 1)
        self.assertFalse(recs[0].partial)
        self.assertEqual(recs[0].bytes_in, len(http_response()))


class TestFilters(unittest.TestCase):
    def filt(self, **over):
        base = dict(host=None, exclude_host=None, app=None, exclude_app=None, pid=None,
                    method=None, port=None, min_size=0, max_size=None)
        base.update(over)
        return nl.Filters(argparse.Namespace(**base))

    def rec(self, **over):
        base = dict(ts=time.time(), host="download.example.com", path="/package1.zip",
                    method="GET", pname="curl", pid=42, server_port=80, bytes_in=1000,
                    server_ip="1.2.3.4")
        base.update(over)
        return nl.Record(**base)

    def test_host_glob(self):
        f = self.filt(host=["*.example.com"])
        self.assertTrue(f.match(self.rec())[0])
        self.assertFalse(f.match(self.rec(host="other.org", server_ip="9.9.9.9"))[0])

    def test_host_substring(self):
        f = self.filt(host=["example"])
        self.assertTrue(f.match(self.rec())[0])

    def test_exclude_host(self):
        f = self.filt(exclude_host=["ads.*"])
        self.assertFalse(f.match(self.rec(host="ads.tracker.io"))[0])
        self.assertTrue(f.match(self.rec())[0])

    def test_app_and_pid(self):
        f = self.filt(app=["curl"])
        self.assertTrue(f.match(self.rec())[0])
        self.assertFalse(f.match(self.rec(pname="firefox"))[0])
        f = self.filt(pid=[42])
        self.assertTrue(f.match(self.rec())[0])
        self.assertFalse(f.match(self.rec(pid=7))[0])

    def test_method(self):
        f = self.filt(method=["GET", "POST"])
        self.assertTrue(f.match(self.rec())[0])
        self.assertFalse(f.match(self.rec(method="DELETE"))[0])

    def test_min_max_size(self):
        f = self.filt(min_size=2000)
        self.assertFalse(f.match(self.rec(bytes_in=1000))[0])
        self.assertTrue(f.match(self.rec(bytes_in=3000))[0])
        f = self.filt(max_size=2000)
        self.assertFalse(f.match(self.rec(bytes_in=3000))[0])

    def test_port(self):
        f = self.filt(port=[443])
        self.assertFalse(f.match(self.rec(server_port=80))[0])
        self.assertTrue(f.match(self.rec(server_port=443))[0])
        self.assertTrue(f.match(self.rec(server_port=80, client="10.0.0.2:443"))[0])


class TestEmitter(unittest.TestCase):
    def test_pretty_line_contains_everything(self):
        stats = nl.Stats()
        em = nl.Emitter(emitter_args(), nl.Color(True), stats)
        buf = io.StringIO()
        em.sinks = [buf]
        rec = nl.Record(ts=time.time(), method="GET", host="download.example.com",
                        path="/package1.zip", app="HTTP", bytes_in=12_612_400,
                        bytes_out=1240, duration=1.9, pname="curl", pid=2381,
                        server="93.184.216.34:80", server_ip="93.184.216.34",
                        server_port=80, status=200)
        em.emit(rec)
        line = nl.ANSI_RE.sub("", buf.getvalue())
        self.assertIn("[GET  ]", line)
        self.assertIn("download.example.com/package1.zip", line)
        self.assertIn("12.6 MB", line)
        self.assertIn("curl(2381)", line)
        self.assertIn("200", line)
        self.assertLessEqual(len(line.strip()), 111)

    def test_narrow_width_drops_extras(self):
        em = nl.Emitter(emitter_args(width=70), nl.Color(False), nl.Stats())
        rec = nl.Record(ts=time.time(), method="GET", host="download.example.com",
                        path="/a/b/package1.zip", bytes_in=12_612_400, pname="curl",
                        pid=2381, server_port=80, status=200, duration=2.0)
        line = em.format_line(rec)
        self.assertIn("download.", line)
        self.assertLessEqual(len(line), 71)

    def test_json_output(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl", delete=False) as fh:
            path = fh.name
        try:
            em = nl.Emitter(emitter_args(format="json", out=path), nl.Color(False), nl.Stats())
            rec = nl.Record(ts=time.time(), method="GET", host="x.example", path="/a.zip",
                            bytes_in=100, bytes_out=10, pname="curl", pid=1, server_port=443)
            em.emit(rec)
            em.sinks[0].close()
            with open(path) as fh:
                data = json.loads(fh.readline())
            self.assertEqual(data["method"], "GET")
            self.assertEqual(data["url"], "http://x.example/a.zip")
            self.assertEqual(data["bytes_total"], 110)
            self.assertEqual(data["process"], "curl")
        finally:
            os.unlink(path)

    def test_csv_output(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False) as fh:
            path = fh.name
        try:
            em = nl.Emitter(emitter_args(format="csv", out=path), nl.Color(False), nl.Stats())
            em.emit(nl.Record(ts=time.time(), method="GET", host="x.example", path="/a.zip",
                              bytes_in=100, bytes_out=10, server_port=443))
            em.sinks[0].close()
            with open(path, newline="") as fh:
                rows = list(csv.reader(fh))
            self.assertEqual(rows[0], nl.Record.CSV_FIELDS)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1][1], "GET")
        finally:
            os.unlink(path)

    def test_partial_not_counted(self):
        stats = nl.Stats()
        em = nl.Emitter(emitter_args(), nl.Color(False), stats)
        em.sinks = [io.StringIO()]
        rec = nl.Record(ts=time.time(), method="GET", host="h.example", path="/x",
                        bytes_in=1, server_port=80)
        em.emit(rec, partial=True)
        self.assertEqual(stats.records, 0)
        em.emit(rec, partial=False)
        self.assertEqual(stats.records, 1)

    def test_special_characters_do_not_break_formatting(self):
        em = nl.Emitter(emitter_args(), nl.Color(False), nl.Stats())
        rec = nl.Record(ts=time.time(), method="GET", host="h.example",
                        path="/a b/c%20d?x=1&y=2", bytes_in=5, server_port=80)
        line = em.format_line(rec)
        self.assertIn("/a b/c%20d", line)


class TestProcMap(unittest.TestCase):
    def test_available_and_types(self):
        self.assertTrue(isinstance(PROC._sockets, dict))
        for key in list(PROC._sockets)[:50]:
            self.assertEqual(len(key), 3)
            self.assertIn(key[0], ("tcp", "udp"))

    def test_lookup_unknown_endpoint(self):
        self.assertIsNone(PROC.lookup("tcp", "203.0.113.77", 65000))


class TestEngineExtras(unittest.TestCase):
    def test_pcap_writer(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".pcap", delete=False) as fh:
            path = fh.name
        try:
            pw = nl.PcapWriter(path)
            frame = tcp_frame(REQ, 1234, 80)
            pw.write(time.time(), frame)
            pw.close()
            with open(path, "rb") as fh:
                data = fh.read()
            self.assertEqual(struct.unpack("<I", data[:4])[0], 0xA1B2C3D4)
            self.assertEqual(len(data), 24 + 16 + len(frame))
        finally:
            os.unlink(path)

    def test_stats_summary(self):
        stats = nl.Stats()
        stats.add(nl.Record(ts=time.time(), method="GET", host="a.example",
                            path="/x", pname="curl", bytes_in=1000, server_port=80))
        text = nl.ANSI_RE.sub("", stats.summary(nl.Color(False), False, 100))
        self.assertIn("1 fetches", text)
        self.assertIn("curl", text)
        self.assertIn("a.example", text)

    def test_demo_runs(self):
        args = emitter_args(format="pretty", quiet=False)
        args.demo = True
        args.binary = False
        old, olderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        try:
            code = nl.demo(args, nl.Color(False))
            out = sys.stdout.getvalue() + sys.stderr.getvalue()
        finally:
            sys.stdout, sys.stderr = old, olderr
        self.assertEqual(code, 0)
        self.assertIn("demo mode", out)
        self.assertIn("[GET  ]", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
