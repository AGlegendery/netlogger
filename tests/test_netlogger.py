#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for netlogger.  Run with:

    python3 -m unittest discover -s tests -v

Everything here feeds real Ethernet/IP/TCP/UDP frames through the same code
path the live sniffer uses, so no root privileges are required.
"""

import argparse
import csv
import http.server
import io
import json
import os
import queue
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import threading
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


# --------------------------------------------------------------------------- #
#  MITM proxy
# --------------------------------------------------------------------------- #

def _crypto_available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


class _MitmOrigin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    body = b"netlogger-mitm-body-" * 64
    keepalive = False

    def _reply(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if not self.keepalive:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        if not self.keepalive:
            self.close_connection = True

    def do_GET(self):  # noqa: N802
        self._reply(200, self.body, "application/zip")

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n)
        self._reply(201, b"posted:" + data, "text/plain")

    def log_message(self, *_args):
        pass


class _MitmKeepAliveOrigin(_MitmOrigin):
    keepalive = True


def _start_origin(tls_ctx=None, handler=_MitmOrigin):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls_ctx is not None:
        httpd.socket = tls_ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _stop_origin(httpd) -> None:
    httpd.shutdown()
    httpd.server_close()


def _read_all(sock, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(65536)
        except (socket.timeout, ssl.SSLError):
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _read_head(sock) -> bytes:
    out = b""
    while b"\r\n\r\n" not in out:
        chunk = sock.recv(1)
        if not chunk:
            break
        out += chunk
    return out


def _content_length(head: bytes) -> int:
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1])
    return 0


def _read_exact(sock, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out


def _wait_record(q, timeout: float = 5.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            kind, rec = q.get(timeout=0.1)
        except queue.Empty:
            continue
        if kind == "rec":
            return rec
    raise AssertionError("no record was emitted")


def _mitm_cfg(*extra: str):
    return nl.build_parser().parse_args(
        ["--mitm", "--mitm-port", "0", "-q", "--mitm-insecure", *extra])


class TestMitmHelpers(unittest.TestCase):
    def test_split_host_port(self):
        self.assertEqual(nl.split_host_port("example.com"), ("example.com", 443))
        self.assertEqual(nl.split_host_port("example.com:8443"), ("example.com", 8443))
        self.assertEqual(nl.split_host_port("[::1]:9443"), ("::1", 9443))
        self.assertEqual(nl.split_host_port("[2001:db8::1]"), ("2001:db8::1", 443))
        self.assertEqual(nl.split_host_port("example.com:bad", 80), ("example.com", 80))

    def test_absolute_target(self):
        self.assertEqual(nl.absolute_target("https://example.com/a/b?x=1"),
                         ("https", "example.com", "/a/b?x=1", 443))
        self.assertEqual(nl.absolute_target("http://example.com:8080/"),
                         ("http", "example.com", "/", 8080))
        self.assertEqual(nl.absolute_target("http://[::1]:9000/x?y=2"),
                         ("http", "::1", "/x?y=2", 9000))

    def test_build_head_drops_proxy_headers_and_adds_host(self):
        head = nl.build_head(
            "GET /x HTTP/1.1",
            [("Proxy-Connection", "keep-alive"), ("X-Test", "1")],
            host="example.com", default_port=80,
        )
        self.assertIn(b"GET /x HTTP/1.1\r\n", head)
        self.assertNotIn(b"Proxy-Connection", head)
        self.assertIn(b"Host: example.com:80\r\n", head)
        self.assertTrue(head.endswith(b"\r\n\r\n"))

    def test_parse_request_and_response(self):
        method, target, version, hdrs = nl.parse_request_head(
            b"POST /submit?q=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n")
        self.assertEqual((method, target, version), ("POST", "/submit?q=1", "HTTP/1.1"))
        self.assertEqual(nl.header_dict(hdrs)["host"], "h")
        status, reason, rhdrs = nl.parse_response_head(
            b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual((status, reason), (201, "Created"))
        self.assertEqual(nl.header_dict(rhdrs)["content-length"], "0")

    def test_body_framing(self):
        self.assertTrue(nl._body_is_eof(200, {}, "GET"))
        self.assertFalse(nl._body_is_eof(200, {"content-length": "5"}, "GET"))
        self.assertFalse(nl._body_is_eof(200, {"transfer-encoding": "chunked"}, "GET"))
        self.assertFalse(nl._body_is_eof(204, {}, "GET"))
        self.assertFalse(nl._body_is_eof(200, {}, "HEAD"))
        self.assertTrue(nl._connection_close("HTTP/1.0", {}))
        self.assertFalse(nl._connection_close("HTTP/1.1", {}))
        self.assertTrue(nl._connection_close("HTTP/1.1", {"connection": "close"}))

    def test_mitm_env(self):
        ca = nl.CertAuthority("/tmp/netlogger-no-such-ca")
        env = nl.mitm_env(ca, 8080, "127.0.0.1")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:8080")
        self.assertEqual(env["SSL_CERT_FILE"], ca.cert_path)
        self.assertIn("NODE_EXTRA_CA_CERTS", env)
        env6 = nl.mitm_env(ca, 8081, "::1")
        self.assertEqual(env6["HTTPS_PROXY"], "http://[::1]:8081")

    def test_header_sanitise(self):
        clean = nl.sanitise_headers([
            ("Host", "a.example"), ("host", "b.example"),
            ("Content-Length", "1"), ("content-length", "2"),
            ("X-Test", "1"), ("X-Test", "2"),
        ])
        self.assertEqual(clean, [
            ("Host", "a.example"), ("Content-Length", "1"),
            ("X-Test", "1"), ("X-Test", "2"),
        ])

    def test_request_target_host_ports(self):
        ca = nl.CertAuthority("/tmp/netlogger-no-such-ca")
        proxy = nl.MitmProxy(_mitm_cfg(), ca, queue.Queue(), nl.ProcMap())
        self.assertEqual(proxy._request_target("/x", [("Host", "[::1]:8443")]),
                         ("http", "::1", "/x", 8443))
        self.assertEqual(proxy._request_target("/x", [("Host", "example.com:8080")]),
                         ("http", "example.com", "/x", 8080))
        self.assertEqual(proxy._request_target("/x", [("Host", "[2001:db8::1]")]),
                         ("http", "2001:db8::1", "/x", 80))

    def test_record_url_ipv6_port(self):
        rec = nl.Record(ts=0)
        rec.method = "GET"
        rec.scheme = "http"
        rec.host = "::1"
        rec.path = "/x"
        rec.show_port = True
        rec.server_port = 8080
        self.assertEqual(rec.url(), "http://[::1]:8080/x")


class TestCertAuthority(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl") or _crypto_available(),
                         "needs cryptography or the openssl CLI")
    def test_ca_and_leaf(self):
        with tempfile.TemporaryDirectory() as td:
            ca = nl.CertAuthority(td)
            ca.ensure()
            self.assertTrue(os.path.isfile(ca.cert_path))
            self.assertTrue(os.path.isfile(ca.key_path))
            self.assertEqual(os.stat(ca.key_path).st_mode & 0o777, 0o600)
            cert, key = ca.leaf_paths("example.com")
            self.assertTrue(os.path.isfile(cert))
            self.assertTrue(os.path.isfile(key))
            self.assertEqual((cert, key), ca.leaf_paths("example.com"))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.assertIsNotNone(ca.leaf_context("example.com"))
            self.assertRegex(ca.fingerprint(), r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl CLI")
    def test_openssl_backend(self):
        with tempfile.TemporaryDirectory() as td:
            ca = nl.CertAuthority(td)
            ca._backend_name = "openssl"
            ca.ensure()
            cert, key = ca.leaf_paths("127.0.0.1")
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.assertIsNotNone(ca.fingerprint())


@unittest.skipUnless(shutil.which("openssl") or _crypto_available(),
                     "MITM needs cryptography or the openssl CLI")
class TestMitmProxy(unittest.TestCase):
    def test_http_get_and_post(self):
        with tempfile.TemporaryDirectory() as td:
            ca = nl.CertAuthority(td)
            ca.ensure()
            cfg = _mitm_cfg()
            origin = _start_origin()
            proxy = nl.MitmProxy(cfg, ca, queue.Queue(), nl.ProcMap())
            proxy.start()
            try:
                port = origin.server_address[1]
                q = proxy.out
                s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                s.sendall((f"GET http://127.0.0.1:{port}/pkg/thing.zip?token=abc HTTP/1.1\r\n"
                           f"Host: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").encode())
                data = _read_all(s)
                s.close()
                self.assertIn(b"200 OK", data)
                self.assertIn(_MitmOrigin.body, data)
                rec = _wait_record(q)
                self.assertEqual(rec.method, "GET")
                self.assertEqual(rec.scheme, "http")
                self.assertEqual(rec.host, "127.0.0.1")
                self.assertEqual(rec.path, "/pkg/thing.zip")
                self.assertEqual(rec.query, "token=abc")
                self.assertEqual(rec.status, 200)
                self.assertGreater(rec.bytes_in, len(_MitmOrigin.body))

                payload = b"x" * 5000
                s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                s.sendall((f"POST http://127.0.0.1:{port}/submit HTTP/1.1\r\n"
                           f"Host: 127.0.0.1:{port}\r\nContent-Length: {len(payload)}\r\n"
                           "Connection: close\r\n\r\n").encode() + payload)
                data = _read_all(s)
                s.close()
                self.assertIn(b"201 Created", data)
                rec = _wait_record(q)
                self.assertEqual(rec.method, "POST")
                self.assertEqual(rec.status, 201)
                self.assertGreaterEqual(rec.bytes_out, len(payload))
            finally:
                proxy.stop()
                _stop_origin(origin)

    def test_https_interception_full_path(self):
        with tempfile.TemporaryDirectory() as td:
            ca = nl.CertAuthority(td)
            ca.ensure()
            cert, key = ca.leaf_paths("127.0.0.1")
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(cert, key)
            origin = _start_origin(sctx)
            cfg = _mitm_cfg()
            proxy = nl.MitmProxy(cfg, ca, queue.Queue(), nl.ProcMap())
            proxy.start()
            try:
                port = origin.server_address[1]
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                raw.sendall((f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n"
                             f"Host: 127.0.0.1:{port}\r\n\r\n").encode())
                head = _read_head(raw)
                self.assertIn(b"200", head.split(b"\r\n")[0])
                cctx = ssl.create_default_context(cafile=ca.cert_path)
                tls = cctx.wrap_socket(raw, server_hostname="127.0.0.1")
                tls.sendall(b"GET /files/linux.iso?mirror=eu HTTP/1.1\r\n"
                            b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n")
                data = _read_all(tls)
                tls.close()
                self.assertIn(b"200 OK", data)
                self.assertIn(_MitmOrigin.body, data)
                rec = _wait_record(proxy.out)
                self.assertEqual(rec.method, "GET")
                self.assertEqual(rec.scheme, "https")
                self.assertEqual(rec.host, "127.0.0.1")
                self.assertEqual(rec.path, "/files/linux.iso")
                self.assertEqual(rec.query, "mirror=eu")
                self.assertEqual(rec.status, 200)
                self.assertTrue(rec.tls.startswith("1."))
                self.assertEqual(rec.sni, "127.0.0.1")
                self.assertIn("https://127.0.0.1:", rec.url())
            finally:
                proxy.stop()
                _stop_origin(origin)

    def test_tls_keepalive_two_requests_one_connection(self):
        with tempfile.TemporaryDirectory() as td:
            ca = nl.CertAuthority(td)
            ca.ensure()
            cert, key = ca.leaf_paths("127.0.0.1")
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(cert, key)
            origin = _start_origin(sctx, _MitmKeepAliveOrigin)
            cfg = _mitm_cfg()
            proxy = nl.MitmProxy(cfg, ca, queue.Queue(), nl.ProcMap())
            proxy.start()
            try:
                port = origin.server_address[1]
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                raw.sendall((f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n"
                             f"Host: 127.0.0.1:{port}\r\n\r\n").encode())
                self.assertIn(b"200", _read_head(raw).split(b"\r\n")[0])
                cctx = ssl.create_default_context(cafile=ca.cert_path)
                tls = cctx.wrap_socket(raw, server_hostname="127.0.0.1")
                for path in ("/one", "/two"):
                    tls.sendall((f"GET {path} HTTP/1.1\r\n"
                                 f"Host: 127.0.0.1:{port}\r\n"
                                 "Connection: keep-alive\r\n\r\n").encode())
                    head = _read_head(tls)
                    self.assertIn(b"200 OK", head)
                    body = _read_exact(tls, _content_length(head))
                    self.assertEqual(body, _MitmOrigin.body)
                tls.close()
                paths = [_wait_record(proxy.out).path for _ in range(2)]
                self.assertEqual(paths, ["/one", "/two"])
            finally:
                proxy.stop()
                _stop_origin(origin)

    def test_non_tls_connect_is_tunnelled(self):
        echo = socket.socket()
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo.bind(("127.0.0.1", 0))
        echo.listen(1)
        echo_port = echo.getsockname()[1]

        def echo_loop():
            conn, _ = echo.accept()
            with conn:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)

        threading.Thread(target=echo_loop, daemon=True).start()
        with tempfile.TemporaryDirectory() as td:
            ca = nl.CertAuthority(td)
            ca.ensure()
            cfg = _mitm_cfg()
            proxy = nl.MitmProxy(cfg, ca, queue.Queue(), nl.ProcMap())
            proxy.start()
            try:
                s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                s.sendall((f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                           f"Host: 127.0.0.1:{echo_port}\r\n\r\n").encode())
                self.assertIn(b"200", _read_head(s).split(b"\r\n")[0])
                s.sendall(b"ping-pong")
                got = b""
                while len(got) < 9:
                    chunk = s.recv(9 - len(got))
                    if not chunk:
                        break
                    got += chunk
                self.assertEqual(got, b"ping-pong")
                s.close()
                rec = _wait_record(proxy.out)
                self.assertEqual(rec.method, "CONNECT")
                self.assertEqual(rec.app, "TCP")
                self.assertTrue(any("not TLS" in n for n in (rec.notes or [])))
                self.assertGreaterEqual(rec.bytes_out, 9)
                self.assertGreaterEqual(rec.bytes_in, 9)
            finally:
                proxy.stop()
                echo.close()


class TestModeSelection(unittest.TestCase):
    def test_capture_flags_used(self):
        p = nl.build_parser()
        self.assertFalse(nl._capture_flags_used(p.parse_args([])))
        self.assertTrue(nl._capture_flags_used(p.parse_args(["--pcap", "x.pcap"])))
        self.assertTrue(nl._capture_flags_used(p.parse_args(["-i", "eth0"])))
        self.assertTrue(nl._capture_flags_used(p.parse_args(["--dns"])))
        self.assertFalse(nl._capture_flags_used(p.parse_args(["--min-size", "1M"])))

    def _patched_run(self, extra):
        saved = (
            nl.install_ca, nl.ca_trusted_anywhere,
            nl.set_system_proxy, nl.restore_system_proxy,
        )
        log = {"install": [], "system": [], "restore": 0}
        state = {"trusted": False}

        def fake_trusted(_ca):
            return state["trusted"]

        def fake_install(_ca, _color, remove=False, stream=None):
            log["install"].append(remove)
            state["trusted"] = not remove
            return 0

        def fake_set(ca_dir, host, port):
            log["system"].append((host, port))
            return os.path.join(ca_dir, "proxy-state.json"), True

        def fake_restore(_ca_dir, _color=None, stream=None):
            log["restore"] += 1
            return True

        nl.install_ca = fake_install
        nl.ca_trusted_anywhere = fake_trusted
        nl.set_system_proxy = fake_set
        nl.restore_system_proxy = fake_restore
        try:
            with tempfile.TemporaryDirectory() as td:
                rc = nl.main(["--mitm-port", "0", "--duration", "1", "-q",
                              "--mitm-ca-dir", td, *extra])
        finally:
            (nl.install_ca, nl.ca_trusted_anywhere,
             nl.set_system_proxy, nl.restore_system_proxy) = saved
        return rc, log

    def test_default_run_auto_trusts_and_restores(self):
        rc, log = self._patched_run([])
        self.assertEqual(rc, 0)
        self.assertEqual(log["install"], [False, True])   # installed, then removed
        self.assertEqual(len(log["system"]), 1)
        self.assertEqual(log["system"][0][0], "127.0.0.1")
        self.assertEqual(log["restore"], 1)

    def test_no_ca_install_and_no_system_proxy(self):
        rc, log = self._patched_run(["--no-ca-install", "--no-system-proxy"])
        self.assertEqual(rc, 0)
        self.assertEqual(log["install"], [])
        self.assertEqual(log["system"], [])
        self.assertEqual(log["restore"], 0)

    def test_command_mode_skips_auto_system_changes(self):
        rc, log = self._patched_run(["--", "/bin/true"])
        self.assertEqual(rc, 0)
        self.assertEqual(log["install"], [])
        self.assertEqual(log["system"], [])


class TestSystemProxy(unittest.TestCase):
    FAKE = '''#!/usr/bin/env python3
import json, os, sys
db = os.environ["GSETTINGS_FAKE_DB"]
try:
    data = json.load(open(db))
except Exception:
    data = {}
defaults = {
    ("org.gnome.system.proxy", "mode"): "'none'",
    ("org.gnome.system.proxy.http", "host"): "''",
    ("org.gnome.system.proxy.http", "port"): "0",
    ("org.gnome.system.proxy.https", "host"): "''",
    ("org.gnome.system.proxy.https", "port"): "0",
    ("org.gnome.system.proxy", "ignore-hosts"): "['localhost']",
}
argv = sys.argv[1:]
if not argv:
    sys.exit(2)
if argv[0] == "get":
    key = (argv[1], argv[2])
    print(data.get(f"{key[0]} {key[1]}", defaults.get(key, "")))
elif argv[0] == "set":
    data[f"{argv[1]} {argv[2]}"] = " ".join(argv[3:])
    json.dump(data, open(db, "w"))
else:
    sys.exit(2)
'''

    @unittest.skipIf(os.geteuid() == 0 and os.environ.get("SUDO_USER"),
                     "would try to switch to the desktop user")
    def test_set_and_restore(self):
        with tempfile.TemporaryDirectory() as td:
            bindir = Path(td) / "bin"
            bindir.mkdir()
            fake = bindir / "gsettings"
            fake.write_text(self.FAKE, encoding="utf-8")
            fake.chmod(0o755)
            db = Path(td) / "db.json"
            old_path = os.environ.get("PATH", "")
            old_db = os.environ.get("GSETTINGS_FAKE_DB")
            os.environ["PATH"] = str(bindir) + ":" + old_path
            os.environ["GSETTINGS_FAKE_DB"] = str(db)
            try:
                before = {name: nl._gsettings(spec)[1].strip()
                          for name, spec in nl.PROXY_KEYS}
                state, ok = nl.set_system_proxy(td, "127.0.0.1", 8080)
                self.assertTrue(ok)
                self.assertTrue(os.path.isfile(state))
                with open(state, encoding="utf-8") as fh:
                    first_state = json.load(fh)["values"]
                self.assertEqual(first_state, before)
                # calling it again must keep the original values, not capture our proxy
                state2, ok2 = nl.set_system_proxy(td, "127.0.0.1", 8080)
                self.assertTrue(ok2)
                self.assertEqual(state2, state)
                with open(state, encoding="utf-8") as fh:
                    self.assertEqual(json.load(fh)["values"], before)
                during = {name: nl._gsettings(spec)[1].strip()
                          for name, spec in nl.PROXY_KEYS}
                self.assertEqual(during["mode"], "'manual'")
                self.assertEqual(during["http_port"], "8080")
                self.assertIn("127.0.0.1", during["ignore_hosts"])
                self.assertIn("::1", during["ignore_hosts"])
                old_out = sys.stdout
                sys.stdout = io.StringIO()
                try:
                    self.assertTrue(nl.restore_system_proxy(td))
                finally:
                    sys.stdout = old_out
                after = {name: nl._gsettings(spec)[1].strip()
                         for name, spec in nl.PROXY_KEYS}
                self.assertEqual(after, before)
                self.assertFalse(os.path.exists(state))
            finally:
                os.environ["PATH"] = old_path
                if old_db is None:
                    os.environ.pop("GSETTINGS_FAKE_DB", None)
                else:
                    os.environ["GSETTINGS_FAKE_DB"] = old_db


if __name__ == "__main__":
    unittest.main(verbosity=2)
