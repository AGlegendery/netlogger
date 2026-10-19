#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netlogger — watch every fetch your apps make, with the full URL, live and in colour.

By default netlogger runs a local MITM proxy so even HTTPS requests show the
complete path and query.  It builds its own CA (cryptography or the openssl CLI),
trusts it for the duration of the run, and points GNOME's system proxy at itself
so browsers and other apps are covered:

    sudo ./netlogger.py                 # full-path proxy for everything, CA auto-trusted
    ./netlogger.py -- curl https://example.com/file   # proxy just this one command
    ./netlogger.py --no-system-proxy    # proxy only, leave the desktop proxy alone
    sudo ./netlogger.py --no-ca-install # proxy without touching the trust stores

Want the old raw-packet view (every interface, DNS, QUIC, no proxy)?  Use
--capture; it needs root or CAP_NET_RAW and sees traffic that never goes through
a proxy:

    sudo ./netlogger.py --capture       # raw AF_PACKET sniffer on every interface
    sudo ./netlogger.py --capture -i wlan0 --dns --live
    ./netlogger.py --demo               # pretty demo, no root needed
    ./netlogger.py --selftest           # parser self checks, no root needed

Packet capture uses only the Python standard library, /proc, and no eBPF or
libpcap.  The proxy speaks HTTP/1.1 (browsers fall back automatically); apps with
certificate pinning refuse the MITM certificate — pass those hosts through
untouched with --mitm-ignore.  The CA private key lives in
~/.config/netlogger/mitm and is sensitive.

Author: built for you.  License: MIT.
"""

from __future__ import annotations

import argparse
import ast
import csv
import errno
import fnmatch
import glob
import hashlib
import json
import os
import queue
import re
import select
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

__version__ = "1.2.0"
PROG = "netlogger"

# --------------------------------------------------------------------------- #
#  constants
# --------------------------------------------------------------------------- #

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TYPES = (0x8100, 0x88A8, 0x9100)

ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772

SUPPORTED_LINK_TYPES = {ARPHRD_ETHER: "eth", ARPHRD_LOOPBACK: "eth"}

# interfaces we skip by default: bridges/pseudo devices duplicate packets that we
# already saw on the physical link, which would double-count traffic.
VIRTUAL_IFACE_RE = re.compile(
    r"^(?:br-|virbr|veth|docker|vnet|vmnet|vboxnet|tun|tap|wg|zt|utun|ifb|tailscale|dummy|cni)"
)


def is_virtual_iface(name: str) -> bool:
    return bool(VIRTUAL_IFACE_RE.match(name)) or "ifb" in name

HTTP_PORTS = {80, 81, 88, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 3128, 9080, 10080}
TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 9443}
QUIC_PORTS = {443, 8443}

HTTP_METHODS = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
    "TRACE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK",
    "UNLOCK", "REPORT", "SEARCH", "PURGE", "ACL", "BIND", "CHECKOUT", "MERGE",
}

# port -> friendly service name, used only for the badge when nothing deeper
# was sniffed (they are still only reported when big enough or with --all).
SERVICES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
    119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NETBIOS", 138: "NETBIOS",
    139: "SMB", 143: "IMAP", 161: "SNMP", 162: "SNMP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE",
    514: "SYSLOG", 515: "LPD", 587: "SMTP", 631: "IPP", 636: "LDAPS",
    853: "DOT", 873: "RSYNC", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OPENVPN", 1433: "MSSQL", 1521: "ORACLE", 1723: "PPTP",
    1883: "MQTT", 2049: "NFS", 2375: "DOCKER", 2376: "DOCKER", 3128: "PROXY",
    3306: "MYSQL", 3389: "RDP", 3478: "STUN", 5060: "SIP", 5061: "SIP",
    5222: "XMPP", 5353: "MDNS", 5432: "POSTGRES", 5672: "AMQP", 5900: "VNC",
    5985: "WINRM", 6379: "REDIS", 6667: "IRC", 8000: "HTTP", 8080: "HTTP",
    8081: "HTTP", 8086: "INFLUX", 8883: "MQTTS", 8888: "HTTP", 9000: "HTTP",
    9090: "PROMETHEUS", 9100: "IPP", 9200: "ELASTIC", 11211: "MEMCACHED",
    27017: "MONGO", 51820: "WIREGUARD",
}

# badge -> 256 colour index (bold is added on top)
BADGE_COLORS = {
    "GET": 42, "POST": 214, "PUT": 51, "PATCH": 141, "DELETE": 203,
    "HEAD": 250, "OPTIONS": 105, "TRACE": 244, "CONNECT": 220,
    "WS": 170, "WSS": 170, "HTTPS": 39, "H2": 111, "H3": 84, "QUIC": 84,
    "DNS": 178, "HTTP": 45, "TCP": 244, "UDP": 244,
}
APP_PALETTE = [168, 208, 111, 186, 213, 75, 220, 141, 114, 173, 45, 216, 156]

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# --------------------------------------------------------------------------- #
#  tiny helpers
# --------------------------------------------------------------------------- #

def vlen(s: str) -> int:
    """Visible length of a string (ANSI escape sequences not counted)."""
    return len(ANSI_RE.sub("", s))


class Color:
    """Very small ANSI helper."""

    def __init__(self, on: bool = True) -> None:
        self.on = bool(on)

    def paint(self, text: str, codes: str = "") -> str:
        if not self.on or not text or not codes:
            return text
        return "\x1b[" + codes + "m" + text + "\x1b[0m"

    def dim(self, t: str) -> str:
        return self.paint(t, "2")

    def bold(self, t: str) -> str:
        return self.paint(t, "1")

    def italic(self, t: str) -> str:
        return self.paint(t, "3")

    def fg(self, t: str, n: int, bold: bool = False) -> str:
        return self.paint(t, f"{'1;' if bold else ''}38;5;{n}")


def human_bytes(n: Optional[int], binary: bool = False) -> str:
    if n is None:
        return "-"
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "-"
    neg = n < 0
    n = abs(n)
    base = 1024 if binary else 1000
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] if binary else ["B", "KB", "MB", "GB", "TB", "PB"]
    if n < base:
        out = f"{n} B"
    else:
        v = float(n)
        i = 0
        while v >= base and i < len(units) - 1:
            v /= base
            i += 1
        if v >= 100:
            out = f"{v:.0f} {units[i]}"
        elif v >= 10:
            out = f"{v:.1f} {units[i]}"
        else:
            out = f"{v:.2f} {units[i]}"
    return "-" + out if neg else out


def human_duration(secs: float) -> str:
    secs = max(0.0, float(secs))
    if secs < 1:
        return f"{secs * 1000:.0f}ms"
    if secs < 60:
        return f"{secs:.2f}s"
    m, s = divmod(int(secs), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


def parse_size(text: str) -> int:
    """'1M', '1MB', '64k', '1024' -> bytes.  Raises ValueError."""
    s = str(text).strip().lower().replace(" ", "")
    m = re.match(r"^(\d+(?:\.\d+)?)([kmgtp]?)(?:i?b)?$", s)
    if not m:
        raise ValueError(f"bad size: {text!r}")
    val = float(m.group(1))
    mult = {"": 1, "k": 1000, "m": 1000 ** 2, "g": 1000 ** 3, "t": 1000 ** 4, "p": 1000 ** 5}[m.group(2)]
    return int(val * mult)


def size_color(n: int) -> int:
    if n < 1024:
        return 244
    if n < 1024 ** 2:
        return 42
    if n < 100 * 1024 ** 2:
        return 220
    if n < 5 * 1024 ** 3:
        return 208
    return 203


def status_color(code: int) -> int:
    if 200 <= code < 300:
        return 42
    if 300 <= code < 400:
        return 51
    if 400 <= code < 500:
        return 214
    if code >= 500:
        return 203
    return 244


def app_color(name: str) -> int:
    if not name:
        return 244
    h = 0
    for ch in name:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return APP_PALETTE[h % len(APP_PALETTE)]


def truncate_tail(s: str, width: int) -> str:
    """Truncate keeping the head and the tail (filenames stay readable)."""
    if width <= 0:
        return ""
    if len(s) <= width:
        return s
    if width <= 2:
        return s[:width]
    tail_len = min(max(8, width // 2), len(s) - 1)
    head_len = width - tail_len - 1
    if head_len < 4:
        return "…" + s[-(width - 1):]
    return s[:head_len] + "…" + s[-tail_len:]


def norm_ip(ip: str) -> str:
    """Normalise '::ffff:1.2.3.4' to '1.2.3.4' and lowercase."""
    if not ip:
        return ip
    ip = ip.lower()
    if ip.startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


def _hex_ip(hexstr: str) -> Optional[str]:
    """'/proc/net/tcp' style hex address -> printable address."""
    try:
        if len(hexstr) == 8:
            raw = bytes.fromhex(hexstr)[::-1]
            return socket.inet_ntop(socket.AF_INET, raw)
        if len(hexstr) == 32:
            raw = bytes.fromhex(hexstr)
            raw = raw[0:4][::-1] + raw[4:8][::-1] + raw[8:12][::-1] + raw[12:16][::-1]
            return socket.inet_ntop(socket.AF_INET6, raw)
    except (ValueError, OSError):
        return None
    return None


# --------------------------------------------------------------------------- #
#  packet parsing
# --------------------------------------------------------------------------- #

def parse_ipv4(data: bytes, off: int) -> Optional[Tuple[int, str, str, int, bytes]]:
    if len(data) < off + 20:
        return None
    ver_ihl = data[off]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < off + ihl:
        return None
    total_len = struct.unpack_from("!H", data, off + 2)[0]
    frag = struct.unpack_from("!H", data, off + 6)[0]
    proto = data[off + 9]
    if frag & 0x1FFF:                      # non-first fragment: no L4 header
        return None
    if total_len < ihl or off + total_len > len(data):
        end = len(data)
    else:
        end = off + total_len
    try:
        src = socket.inet_ntop(socket.AF_INET, data[off + 12:off + 16])
        dst = socket.inet_ntop(socket.AF_INET, data[off + 16:off + 20])
    except (ValueError, OSError):
        return None
    return 4, src, dst, proto, data[off + ihl:end]


def parse_ipv6(data: bytes, off: int) -> Optional[Tuple[int, str, str, int, bytes]]:
    if len(data) < off + 40:
        return None
    if data[off] >> 4 != 6:
        return None
    payload_len = struct.unpack_from("!H", data, off + 4)[0]
    nxt = data[off + 6]
    if payload_len == 0:
        end = len(data)
    else:
        end = min(len(data), off + 40 + payload_len)
    try:
        src = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
    except (ValueError, OSError):
        return None
    cur = off + 40
    hops = 0
    while nxt in (0, 43, 44, 51, 60) and hops < 8:
        hops += 1
        if len(data) < cur + 8:
            return None
        nxt_next = data[cur]
        if nxt == 44:                       # fragment header
            frag_off = struct.unpack_from("!H", data, cur + 2)[0]
            if frag_off & 0xFFF8:           # not the first fragment
                return None
            cur += 8
        else:
            hlen = (data[cur + 1] + 1) * 8
            cur += hlen
        nxt = nxt_next
    if cur > end:
        return None
    return 6, src, dst, nxt, data[cur:end]


def parse_tcp(seg: bytes) -> Optional[Tuple[int, int, int, int, int, bytes]]:
    """-> (sport, dport, seq, ack, flags, payload)"""
    if len(seg) < 20:
        return None
    sport, dport, seq, ack = struct.unpack_from("!HHII", seg, 0)
    doff = (seg[12] >> 4) * 4
    if doff < 20 or len(seg) < doff:
        return None
    flags = seg[13]
    return sport, dport, seq, ack, flags, seg[doff:]


def parse_udp(seg: bytes) -> Optional[Tuple[int, int, bytes]]:
    """-> (sport, dport, payload)"""
    if len(seg) < 8:
        return None
    sport, dport, ulen = struct.unpack_from("!HHH", seg, 0)
    if ulen < 8 or ulen > len(seg):
        ulen = len(seg)
    return sport, dport, seg[8:ulen]


# --------------------------------------------------------------------------- #
#  application protocol sniffing
# --------------------------------------------------------------------------- #

_REQ_LINE = re.compile(rb"^([A-Za-z]{3,12})[ \t]+(\S+)[ \t]+HTTP/(\d\.\d)[ \t]*$")
_KEEPALIVE_RE = re.compile(rb"(?:^|\r\n)(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|PROPFIND|MKCOL) /")
_RES_LINE = re.compile(rb"^HTTP/(\d\.\d)[ \t]+(\d{3})(?:[ \t]+(.*))?$")


def _header_block(payload: bytes) -> Optional[bytes]:
    end = payload.find(b"\r\n\r\n")
    if end >= 0:
        return payload[:end]
    end = payload.find(b"\n\n")
    if end >= 0:
        return payload[:end]
    return None


def _parse_headers(block: bytes) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in re.split(rb"\r?\n", block)[1:]:
        if not raw or b":" not in raw:
            continue
        k, v = raw.split(b":", 1)
        try:
            out[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
        except UnicodeDecodeError:
            continue
    return out


def parse_http_request(payload: bytes) -> Optional[Dict[str, Any]]:
    if not payload:
        return None
    line_end = payload.find(b"\r\n")
    if line_end < 0:
        line_end = payload.find(b"\n")
    if line_end < 0 or line_end > 8192:
        return None
    m = _REQ_LINE.match(payload[:line_end].rstrip(b"\r"))
    if not m:
        return None
    method = m.group(1).decode("latin-1").upper()
    if method not in HTTP_METHODS:
        return None
    target = m.group(2).decode("latin-1")
    version = m.group(3).decode("latin-1")

    block = _header_block(payload)
    if block is None:                     # headers not all here yet: retry later
        return None
    headers = _parse_headers(block)

    scheme = "http"
    host = headers.get("host", "")
    path = target
    if target.startswith(("http://", "https://")):
        # absolute-form request (proxy)
        rest = target.split("://", 1)
        scheme = rest[0].lower()
        tail = rest[1]
        slash = tail.find("/")
        if slash < 0:
            host = tail
            path = "/"
        else:
            host = tail[:slash]
            path = tail[slash:]
    elif method == "CONNECT":
        host = target
        path = ""
    path, _, query = path.partition("?")
    if not path and method != "CONNECT":
        path = "/"

    upgrade = headers.get("upgrade", "").lower()
    app = "HTTP"
    if upgrade == "websocket":
        app = "WS"
        scheme = "ws"
    if ":" in host and not host.startswith("["):
        host_port = host
        host = host.rsplit(":", 1)[0]
    else:
        host_port = ""
    if host_port and ":" in host_port:
        hp = host_port.rsplit(":", 1)[1]
    else:
        hp = ""

    clen = headers.get("content-length")
    try:
        content_length = int(clen) if clen is not None else None
    except ValueError:
        content_length = None

    return {
        "app": app,
        "method": method,
        "host": host,
        "port": hp,
        "path": path,
        "query": query,
        "scheme": scheme,
        "version": version,
        "headers": headers,
        "content_length": content_length,
    }


def parse_http_response(payload: bytes) -> Optional[Dict[str, Any]]:
    if not payload:
        return None
    line_end = payload.find(b"\r\n")
    if line_end < 0:
        line_end = payload.find(b"\n")
    if line_end < 0 or line_end > 8192:
        return None
    m = _RES_LINE.match(payload[:line_end].rstrip(b"\r"))
    if not m:
        return None
    block = _header_block(payload)
    if block is None:
        return None
    headers = _parse_headers(block)
    clen = headers.get("content-length")
    try:
        content_length = int(clen) if clen is not None else None
    except ValueError:
        content_length = None
    return {
        "status": int(m.group(2)),
        "content_length": content_length,
        "content_type": headers.get("content-type", ""),
        "server": headers.get("server", ""),
        "chunked": "chunked" in headers.get("transfer-encoding", "").lower(),
    }


_TLS_VERSIONS = {0x0304: "1.3", 0x0303: "1.2", 0x0302: "1.1", 0x0301: "1.0", 0x0300: "SSL3"}


def parse_tls_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Best effort: extract SNI, ALPN and version from a TLS ClientHello."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        rec_len = struct.unpack_from("!H", payload, 3)[0]
        if len(payload) < 5 + rec_len:            # record still in flight
            return None
        body = payload[5:5 + rec_len]
        if len(body) < 4 or body[0] != 0x01:
            return None
        hs_len = int.from_bytes(body[1:4], "big")
        if len(body) < 4 + hs_len:                # handshake still in flight
            return None
        hs = body[4:4 + hs_len]
        if len(hs) < 35:
            return None
        i = 2 + 32                                    # legacy version + random
        sid_len = hs[i]
        i += 1 + sid_len
        if i + 2 > len(hs):
            return None
        cs_len = int.from_bytes(hs[i:i + 2], "big")
        i += 2 + cs_len
        if i + 1 > len(hs):
            return None
        comp_len = hs[i]
        i += 1 + comp_len
        if i + 2 > len(hs):
            return None
        ext_total = int.from_bytes(hs[i:i + 2], "big")
        i += 2
        if i + ext_total > len(hs):
            return None
        end = i + ext_total
        sni: Optional[str] = None
        alpn: List[str] = []
        version: Optional[str] = None
        while i + 4 <= end:
            etype = int.from_bytes(hs[i:i + 2], "big")
            elen = int.from_bytes(hs[i + 2:i + 4], "big")
            i += 4
            if i + elen > end:
                return None
            edata = hs[i:i + elen]
            i += elen
            if etype == 0x0000 and len(edata) >= 5:
                nl = int.from_bytes(edata[3:5], "big")
                sni = edata[5:5 + nl].decode("latin-1").rstrip(".") or None
            elif etype == 0x0010 and len(edata) >= 2:
                j = 2
                while j < len(edata):
                    l = edata[j]
                    alpn.append(edata[j + 1:j + 1 + l].decode("latin-1"))
                    j += 1 + l
            elif etype == 0x002B and len(edata) >= 3 and edata[0] == 2:
                v = int.from_bytes(edata[1:3], "big")
                version = _TLS_VERSIONS.get(v)
        if version is None:
            version = _TLS_VERSIONS.get(int.from_bytes(hs[0:2], "big"))
        return {"sni": sni, "alpn": [a for a in alpn if a], "version": version}
    except (IndexError, struct.error, ValueError):
        return None


def _hpack_str(block: bytes, i: int) -> Tuple[Optional[str], int]:
    """Read an HPACK string.  Returns (text_or_None_if_huffman, new_index)."""
    if i >= len(block):
        return None, i
    b = block[i]
    huff = bool(b & 0x80)
    ln = b & 0x7F
    i += 1
    if ln == 0x7F:                                   # multi-byte length: bail out
        return None, min(len(block), i + 0x7F)
    raw = block[i:i + ln]
    i += ln
    if huff:
        return None, i
    try:
        return raw.decode("latin-1"), i
    except UnicodeDecodeError:
        return None, i


def parse_h2_method(block: bytes) -> Optional[str]:
    """Very small HPACK peek: only the static-table shortcut for :method."""
    i = 0
    while i < len(block) and i < 256:
        b = block[i]
        if b & 0x80:                                  # indexed header field
            idx = b & 0x7F
            if idx == 2:
                return "GET"
            if idx == 3:
                return "POST"
            i += 1
            continue
        if b & 0x40:                                  # literal, incremental index
            name_idx = b & 0x3F
            i += 1
            name: Optional[str] = None
            if name_idx == 0:
                name, i = _hpack_str(block, i)
            val, i = _hpack_str(block, i)
            if name_idx in (2, 3) or (name or "").lower() == ":method":
                if val:
                    v = val.upper()
                    if v in HTTP_METHODS:
                        return v
                return None
            continue
        if b & 0x20:                                  # dynamic table size update
            i += 1
            continue
        if b & 0x10:                                  # literal, never indexed
            name_idx = b & 0x0F
            i += 1
        else:                                         # literal, without indexing
            name_idx = b & 0x0F
            i += 1
        if name_idx == 0:
            _, i = _hpack_str(block, i)
        _, i = _hpack_str(block, i)
    return None


def parse_h2_headers_frame(payload: bytes) -> Optional[str]:
    """Given a stream starting after the h2 preface, peek the first HEADERS."""
    i = 0
    guard = 0
    while i + 9 <= len(payload) and guard < 64:
        guard += 1
        ln = int.from_bytes(payload[i:i + 3], "big")
        ftype = payload[i + 3]
        flags = payload[i + 4]
        i += 9
        body = payload[i:i + ln]
        i += ln
        if ftype == 0x01:                             # HEADERS
            b = body
            if flags & 0x08 and b:                    # PADDED
                pad = b[0]
                b = b[1:len(b) - pad]
            if flags & 0x20 and len(b) >= 5:           # PRIORITY
                b = b[5:]
            return parse_h2_method(b)
    return None


def sniff_client(proto: str, payload: bytes, sport: int, dport: int) -> Optional[Dict[str, Any]]:
    """Try to read `payload` as a client -> server application message."""
    if not payload:
        return None
    b0 = payload[0]

    if b0 == 0x16 and len(payload) > 5 and payload[1] == 0x03:
        info = parse_tls_client_hello(payload)
        if not info:
            return None
        alpn = [a.lower() for a in info["alpn"]]
        if "h3" in alpn:
            app = "H3"
        elif "h2" in alpn:
            app = "H2"
        else:
            app = "HTTPS"
        return {
            "app": app,
            "host": info["sni"] or "",
            "sni": info["sni"] or "",
            "tls": info["version"] or "",
            "alpn": ",".join(info["alpn"]),
            "scheme": "https",
        }

    if proto == "udp":
        if (dport in QUIC_PORTS or sport in QUIC_PORTS) and (b0 & 0x80):
            ver = int.from_bytes(payload[1:5], "big") if len(payload) >= 5 else 0
            return {"app": "QUIC", "scheme": "quic", "note": f"quic v{ver:08x}"}
        return None

    if payload.startswith(b"PRI * HTTP/2.0"):
        method = parse_h2_headers_frame(payload[24:])
        return {"app": "H2", "method": method or "", "scheme": "https"}

    if 0x41 <= b0 <= 0x5A:                       # A-Z: a request line may start here
        req = parse_http_request(payload)
        if req:
            return req
    return None


# --------------------------------------------------------------------------- #
#  DNS
# --------------------------------------------------------------------------- #

def _dns_read_name(data: bytes, off: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumps = 0
    start = off
    while True:
        if off >= len(data) or jumps > 64:
            break
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if jumps == 0:
                start = off + 2
            jumps += 1
            off = ptr
            continue
        off += 1
        labels.append(data[off:off + ln].decode("latin-1", "replace"))
        off += ln
    return ".".join(labels), (start if jumps else off)


_QTYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 33: "SRV", 65: "HTTPS"}


def parse_dns(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 12:
        return None
    try:
        flags = struct.unpack_from("!H", payload, 2)[0]
        qd = struct.unpack_from("!H", payload, 4)[0]
        an = struct.unpack_from("!H", payload, 6)[0]
    except struct.error:
        return None
    if qd < 1 or qd > 32 or an > 128:
        return None
    is_resp = bool(flags & 0x8000)
    try:
        name, off = _dns_read_name(payload, 12)
        if off + 4 > len(payload):
            return None
        qtype = struct.unpack_from("!H", payload, off)[0]
        off += 4
    except (struct.error, IndexError):
        return None
    answers: List[str] = []
    if is_resp:
        for _ in range(an):
            if off >= len(payload):
                break
            try:
                _, off = _dns_read_name(payload, off)
                if off + 10 > len(payload):
                    break
                rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", payload, off)
                off += 10
                rdata = payload[off:off + rdlen]
                off += rdlen
                if rtype == 1 and rdlen == 4:
                    answers.append(socket.inet_ntop(socket.AF_INET, rdata))
                elif rtype == 28 and rdlen == 16:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
                elif rtype == 5:
                    answers.append(_dns_read_name(payload, off - rdlen)[0])
            except (struct.error, IndexError, ValueError, OSError):
                break
    if not name:
        return None
    return {
        "name": name,
        "qtype": _QTYPE_NAMES.get(qtype, str(qtype)),
        "response": is_resp,
        "answers": [a for a in answers if a],
    }


class DnsCache:
    """ip -> hostname learned from /etc/hosts and from captured DNS answers."""

    def __init__(self, limit: int = 100000) -> None:
        self.by_ip: Dict[str, str] = {}
        self.limit = limit
        self.load_hosts()

    def load_hosts(self) -> None:
        try:
            with open("/etc/hosts", "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return
        for ln in lines:
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            parts = ln.split()
            if len(parts) < 2:
                continue
            ip = norm_ip(parts[0])
            for nm in parts[1:]:
                self.remember(ip, nm, prefer=True)

    def remember(self, ip: str, name: str, prefer: bool = False) -> None:
        if not ip or not name:
            return
        ip = norm_ip(ip)
        name = name.rstrip(".").lower()
        if not name:
            return
        cur = self.by_ip.get(ip)
        if cur is None or prefer or len(name) < len(cur):
            self.by_ip[ip] = name
        if len(self.by_ip) > self.limit:
            for k in list(self.by_ip.keys())[: self.limit // 2]:
                self.by_ip.pop(k, None)

    def name_for(self, ip: str) -> Optional[str]:
        return self.by_ip.get(norm_ip(ip))


# --------------------------------------------------------------------------- #
#  process attribution (/proc)
# --------------------------------------------------------------------------- #

class ProcMap:
    """Maps open sockets to the (pid, process name) that owns them."""

    INTERESTING = ("python", "python3", "node", "ruby", "perl", "java", "php",
                   "bash", "sh", "deno", "bun", "electron", "chromium")

    def __init__(self, ttl: float = 0.7) -> None:
        self.ttl = ttl
        self._last = 0.0
        self._sockets: Dict[Tuple[str, str, int], int] = {}
        self._inode_proc: Dict[int, Tuple[int, str]] = {}
        self._name_cache: Dict[int, str] = {}
        self.available = os.path.isdir("/proc/self/fd")

    # -- public ------------------------------------------------------------ #
    def refresh(self, now: Optional[float] = None, force: bool = False) -> None:
        if not self.available:
            return
        now = time.time() if now is None else now
        if not force and now - self._last < self.ttl:
            return
        if force and now - self._last < 0.1:      # never scan /proc in a hot loop
            return
        self._last = now
        sockets = self._read_proc_net()
        self._sockets = sockets
        missing = set(sockets.values()) - set(self._inode_proc)
        if missing:
            self._find_inodes(missing)
        if len(self._inode_proc) > 50000:
            for k in list(self._inode_proc.keys())[: 25000]:
                self._inode_proc.pop(k, None)

    def lookup(self, proto: str, ip: str, port: int) -> Optional[Tuple[int, str]]:
        ino = self._sockets.get((proto, norm_ip(ip), port))
        if ino is None:
            return None
        return self._inode_proc.get(ino)

    def lookup_fresh(self, proto: str, ip: str, port: int) -> Optional[Tuple[int, str]]:
        """Like lookup(), but re-reads /proc immediately (MITM connections)."""
        if not self.available:
            return None
        self._last = 0.0
        self.refresh(force=True)
        return self.lookup(proto, ip, port)

    # -- internals --------------------------------------------------------- #
    def _read_proc_net(self) -> Dict[Tuple[str, str, int], int]:
        out: Dict[Tuple[str, str, int], int] = {}
        for name, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
            try:
                with open("/proc/net/" + name, "r", encoding="latin-1") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            for ln in lines[1:]:
                parts = ln.split()
                if len(parts) < 10:
                    continue
                try:
                    local, lport_hex = parts[1].rsplit(":", 1)
                    port = int(lport_hex, 16)
                    ino = int(parts[9])
                except ValueError:
                    continue
                ip = _hex_ip(local)
                if ip is None:
                    continue
                out[(proto, norm_ip(ip), port)] = ino
        return out

    def _find_inodes(self, missing: set) -> None:
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return
        found: Dict[int, Tuple[int, str]] = {}
        for pid_s in pids:
            if not missing:
                break
            fd_dir = "/proc/" + pid_s + "/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    target = os.readlink(fd_dir + "/" + fd)
                except OSError:
                    continue
                if not target.startswith("socket:["):
                    continue
                try:
                    ino = int(target[8:-1])
                except ValueError:
                    continue
                if ino in missing:
                    found[ino] = (int(pid_s), self._proc_name(int(pid_s)))
                    missing.discard(ino)
        self._inode_proc.update(found)

    def _proc_name(self, pid: int) -> str:
        name = self._name_cache.get(pid)
        if name is not None:
            return name
        name = "?"
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            comm = ""
        if comm:
            name = comm
            if comm in self.INTERESTING:
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as fh:
                        argv = fh.read(4096).split(b"\0")
                except OSError:
                    argv = []
                for a in argv[1:]:
                    s = a.decode("utf-8", "replace")
                    if not s or s.startswith("-"):
                        continue
                    base = os.path.basename(s)
                    if base and not base.endswith((".pyc",)):
                        name = f"{comm}({base})"
                        break
        self._name_cache[pid] = name
        return name


# --------------------------------------------------------------------------- #
#  flows + records
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int

    def __str__(self) -> str:
        if ":" in self.ip and not self.ip.startswith("::ffff:"):
            return f"[{self.ip}]:{self.port}"
        return f"{self.ip}:{self.port}"


@dataclass
class Flow:
    key: tuple
    proto: str
    a: Endpoint
    b: Endpoint
    ts: float
    last_seen: float
    bytes: Dict[Endpoint, int] = field(default_factory=dict)
    pkts: Dict[Endpoint, int] = field(default_factory=dict)
    client: Optional[Endpoint] = None
    server: Optional[Endpoint] = None
    app: str = ""
    method: str = ""
    host: str = ""
    path: str = ""
    query: str = ""
    scheme: str = ""
    version: str = ""
    status: int = 0
    content_length: Optional[int] = None
    content_type: str = ""
    server_hdr: str = ""
    tls: str = ""
    alpn: str = ""
    sni: str = ""
    service: str = ""
    requests: int = 0
    chunked: bool = False
    req_parsed: bool = False
    resp_parsed: bool = False
    sniff_left: int = 40
    c2s_buf: bytes = b""
    s2c_buf: bytes = b""
    fin_time: Optional[float] = None
    start_emitted: bool = False
    pid: Optional[int] = None
    pname: str = ""
    resolve_tries: int = 0
    last_resolve: float = 0.0
    notes: List[str] = field(default_factory=list)

    def set_client(self, client: Endpoint, server: Optional[Endpoint] = None) -> None:
        self.client = client
        if server is not None:
            self.server = server
        else:
            self.server = self.b if client == self.a else self.a

    def add_note(self, note: str) -> None:
        if note and note not in self.notes:
            self.notes.append(note)


@dataclass
class Record:
    ts: float
    method: str = ""
    host: str = ""
    path: str = ""
    query: str = ""
    app: str = ""
    scheme: str = ""
    proto: str = "tcp"
    status: int = 0
    content_type: str = ""
    server_hdr: str = ""
    content_length: Optional[int] = None
    bytes_in: int = 0
    bytes_out: int = 0
    pkts_in: int = 0
    pkts_out: int = 0
    duration: float = 0.0
    pid: Optional[int] = None
    pname: str = ""
    client: str = ""
    server: str = ""
    server_ip: str = ""
    server_port: int = 0
    show_port: bool = False
    sni: str = ""
    tls: str = ""
    alpn: str = ""
    service: str = ""
    requests: int = 1
    filtered_reason: str = ""
    notes: List[str] = field(default_factory=list)
    partial: bool = False

    @property
    def bytes_total(self) -> int:
        return int(self.bytes_in) + int(self.bytes_out)

    def badge(self) -> str:
        if self.app in ("WS", "WSS"):
            return self.app
        if self.method and self.method != "CONNECT":
            return self.method
        if self.method == "CONNECT":
            return "CONN"
        for cand in (self.app, self.service):
            if cand:
                return cand
        return self.proto.upper()

    def url(self) -> str:
        host = self.host or self.server_ip or "-"
        if self.show_port and self.server_port:
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            host = f"{host}:{self.server_port}"
        scheme = self.scheme or ("https" if self.app in ("HTTPS", "H2", "H3") else "http")
        if not self.path or self.path == "-":
            if scheme in ("http", "https", "ws", "wss", "quic"):
                return f"{scheme}://{host}"
            return str(host)
        return f"{scheme}://{host}{self.path}" + (("?" + self.query) if self.query else "")

    def to_dict(self) -> Dict[str, Any]:
        return OrderedDict(
            time=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.ts)),
            epoch=round(self.ts, 3),
            method=self.method or self.badge(),
            app=self.app,
            scheme=self.scheme,
            host=self.host,
            path=self.path,
            query=self.query,
            url=self.url(),
            status=self.status or None,
            content_type=self.content_type or None,
            bytes_in=self.bytes_in,
            bytes_out=self.bytes_out,
            bytes_total=self.bytes_total,
            packets=self.pkts_in + self.pkts_out,
            duration=round(self.duration, 4),
            rate=int(self.bytes_total / self.duration) if self.duration > 0 else None,
            pid=self.pid,
            process=self.pname or None,
            client=self.client or None,
            server=self.server or None,
            sni=self.sni or None,
            tls=self.tls or None,
            alpn=self.alpn or None,
            service=self.service or None,
            requests=self.requests,
            partial=self.partial or None,
            notes=self.notes or None,
        )

    CSV_FIELDS = ["time", "method", "app", "scheme", "host", "path", "url", "status",
                  "bytes_in", "bytes_out", "bytes_total", "packets", "duration",
                  "rate", "pid", "process", "client", "server", "tls", "alpn"]


class Filters:
    def __init__(self, args: argparse.Namespace) -> None:
        self.hosts = [h.lower() for h in (args.host or [])]
        self.exclude_hosts = [h.lower() for h in (args.exclude_host or [])]
        self.apps = [a.lower() for a in (args.app or [])]
        self.exclude_apps = [a.lower() for a in (args.exclude_app or [])]
        self.pids = set(args.pid or [])
        self.methods = {m.upper() for m in (args.method or [])}
        self.ports = set(args.port or [])
        self.min_size = args.min_size
        self.max_size = args.max_size if args.max_size is not None else None

    @staticmethod
    def _pat_match(value: str, pats: Sequence[str]) -> bool:
        v = (value or "").lower()
        for p in pats:
            if "*" in p or "?" in p:
                if fnmatch.fnmatch(v, p):
                    return True
            elif p in v:
                return True
        return False

    def match(self, rec: Record) -> Tuple[bool, str]:
        hay_host = rec.host or rec.server_ip
        if self.hosts and not (self._pat_match(hay_host, self.hosts) or self._pat_match(rec.url(), self.hosts)):
            return False, "host"
        if self.exclude_hosts and (self._pat_match(hay_host, self.exclude_hosts) or self._pat_match(rec.url(), self.exclude_hosts)):
            return False, "exclude-host"
        if self.apps and not self._pat_match(rec.pname or "", self.apps):
            return False, "app"
        if self.exclude_apps and self._pat_match(rec.pname or "", self.exclude_apps):
            return False, "exclude-app"
        if self.pids and rec.pid not in self.pids:
            return False, "pid"
        if self.methods and rec.badge().upper() not in self.methods:
            return False, "method"
        if self.ports and rec.server_port not in self.ports:
            cport = 0
            if rec.client and ":" in rec.client:
                try:
                    cport = int(rec.client.rsplit(":", 1)[1])
                except ValueError:
                    cport = 0
            if cport not in self.ports:
                return False, "port"
        if self.min_size and rec.bytes_total < self.min_size:
            return False, "min-size"
        if self.max_size is not None and rec.bytes_total > self.max_size:
            return False, "max-size"
        return True, ""


# --------------------------------------------------------------------------- #
#  tracker
# --------------------------------------------------------------------------- #

class Tracker:
    UNKNOWN_MIN_BYTES = 32 * 1024
    MAX_FLOWS = 20000

    def __init__(self, cfg: argparse.Namespace, proc: ProcMap, dns: DnsCache,
                 emit: Callable[[Record, bool], None]) -> None:
        self.cfg = cfg
        self.proc = proc
        self.dns = dns
        self.emit = emit
        self.flows: Dict[tuple, Flow] = {}
        self.active_peak = 0

    # -- packet entry ------------------------------------------------------ #
    def handle(self, ts: float, proto: str, src: Endpoint, dst: Endpoint,
               payload: bytes, flags: int = 0) -> None:
        key = (proto,) + tuple(sorted(((src.ip, src.port), (dst.ip, dst.port))))
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(key=key, proto=proto, a=src, b=dst, ts=ts, last_seen=ts)
            if len(self.flows) >= self.MAX_FLOWS:
                self._evict_some()
            self.flows[key] = flow
            self._classify(flow, ts, src, dst, payload, flags)
        flow.last_seen = ts

        n = len(payload)
        if n:
            flow.bytes[src] = flow.bytes.get(src, 0) + n
            flow.pkts[src] = flow.pkts.get(src, 0) + 1

        if flags & 0x01 or flags & 0x04:            # FIN or RST
            if flow.fin_time is None:
                flow.fin_time = ts

        if payload and flow.sniff_left > 0:
            self._sniff(flow, ts, src, dst, payload)

        if flow.pid is None:
            self._resolve(flow, ts)

        if self.cfg.live and not flow.start_emitted and self._identified(flow):
            rec = self._build(flow, ts)
            rec.partial = True
            flow.start_emitted = True
            self.emit(rec, True)

    # -- classification ---------------------------------------------------- #
    def _classify(self, flow: Flow, ts: float, src: Endpoint, dst: Endpoint,
                  payload: bytes, flags: int) -> None:
        if flags & 0x02 and not flags & 0x10:                 # bare SYN -> src is client
            flow.set_client(src, dst)
        flow.service = SERVICES.get(dst.port) or SERVICES.get(src.port) or ""
        self._resolve(flow, ts, force=True)
        if flow.client is None and flow.pid is None:
            self._guess_direction(flow)

    def _guess_direction(self, flow: Flow) -> None:
        a, b = flow.a, flow.b
        a_known = a.port in SERVICES or a.port < 1024
        b_known = b.port in SERVICES or b.port < 1024
        if a_known and not b_known:
            flow.set_client(b, a)
        elif b_known and not a_known:
            flow.set_client(a, b)
        elif a.port != b.port:
            flow.set_client(a, b) if a.port > b.port else flow.set_client(b, a)

    def _resolve(self, flow: Flow, now: float, force: bool = False) -> None:
        if flow.pid is not None:
            return
        if flow.resolve_tries >= 8 or now - flow.last_resolve < 0.12:
            return
        flow.resolve_tries += 1
        flow.last_resolve = now
        self.proc.refresh(now, force=force)
        for ep in (flow.a, flow.b):
            hit = self.proc.lookup(flow.proto, ep.ip, ep.port)
            if hit:
                flow.pid, flow.pname = hit
                if flow.client is None:
                    self._guess_direction(flow)
                return

    # -- sniffing ---------------------------------------------------------- #
    def _sniff(self, flow: Flow, ts: float, src: Endpoint, dst: Endpoint, payload: bytes) -> None:
        # DNS first: it is unambiguous and feeds name resolution
        if flow.proto == "udp" and (src.port == 53 or dst.port == 53):
            info = parse_dns(payload)
            if info:
                if not flow.app:
                    flow.app = "DNS"
                    flow.scheme = "dns"
                    flow.method = "DNS"
                if not flow.host:
                    flow.host = info["name"]
                if info["response"]:
                    if info["answers"]:
                        flow.add_note("dns " + info["qtype"])
                        for ip in info["answers"]:
                            self.dns.remember(ip, info["name"])
                        if flow.path == "":
                            flow.path = " → " + ", ".join(info["answers"][:3])
                elif flow.client is None:
                    flow.set_client(src, dst)
                    if flow.server is None:
                        flow.server = dst
                return

        # Direction still unknown: the first payload that looks like a request
        # tells us who the client is.  Otherwise a response tells us the reverse.
        if flow.client is None:
            info = sniff_client(flow.proto, payload, src.port, dst.port)
            if info:
                flow.set_client(src, dst)
                self._apply_client_info(flow, info)
                return
            if parse_http_response(payload) or (payload[0] == 0x16 and len(payload) > 2 and payload[1] == 0x03):
                flow.set_client(dst, src)

        if flow.client is None:
            return

        if src == flow.client:
            if flow.req_parsed:
                # keep-alive: count request lines visible in this segment
                if payload:
                    flow.requests += len(_KEEPALIVE_RE.findall(payload))
                return
            flow.c2s_buf = (flow.c2s_buf + payload)[:16384]
            flow.sniff_left -= 1
            info = sniff_client(flow.proto, flow.c2s_buf, src.port, dst.port)
            if info:
                self._apply_client_info(flow, info)
            elif len(flow.c2s_buf) >= 16384:
                flow.sniff_left = 0
            return

        if flow.resp_parsed:
            return
        flow.s2c_buf = (flow.s2c_buf + payload)[:16384]
        flow.sniff_left -= 1
        # we might have guessed the direction wrong: a real server never sends
        # a client hello or an HTTP request
        if not flow.req_parsed:
            flip = sniff_client(flow.proto, flow.s2c_buf, src.port, dst.port)
            if flip:
                flow.s2c_buf = b""
                flow.set_client(dst, src)
                self._apply_client_info(flow, flip)
                return
        info = parse_http_response(flow.s2c_buf)
        if info:
            flow.resp_parsed = True
            flow.status = info["status"]
            flow.content_type = info["content_type"]
            flow.server_hdr = info["server"]
            flow.chunked = info["chunked"]
            if info["content_length"] is not None:
                flow.content_length = info["content_length"]
            if not flow.app:
                flow.app = "HTTP"
                flow.scheme = "http"
            return

        if not flow.app and flow.s2c_buf[:2] == b"\x16\x03":
            flow.app = "HTTPS"
            flow.scheme = "https"
            flow.add_note("encrypted")
            flow.resp_parsed = True
        elif len(flow.s2c_buf) >= 16384:
            flow.sniff_left = 0

    def _apply_client_info(self, flow: Flow, info: Dict[str, Any]) -> None:
        flow.req_parsed = True
        app = info.get("app") or ""
        if app:
            flow.app = app
        if info.get("method"):
            flow.method = info["method"]
        if info.get("host"):
            flow.host = info["host"]
        for k_field, attr in (("path", "path"), ("query", "query"), ("scheme", "scheme"),
                              ("version", "version"), ("tls", "tls"), ("alpn", "alpn"),
                              ("sni", "sni")):
            v = info.get(k_field)
            if v:
                setattr(flow, attr, v)
        if info.get("content_length") is not None:
            flow.content_length = info["content_length"]
        if info.get("note"):
            flow.add_note(info["note"])
        if flow.app in ("HTTPS", "H2", "H3"):
            flow.add_note("encrypted")
        if flow.app == "HTTPS" and flow.server and flow.server.port in HTTP_PORTS:
            flow.app = "HTTP"
            flow.scheme = "http"
        flow.requests += 1

    # -- emission ---------------------------------------------------------- #
    def _reportable(self, flow: Flow) -> bool:
        total = sum(flow.bytes.values())
        app = flow.app
        if app == "DNS":
            return bool(self.cfg.dns) and (flow.host or total)
        if app in ("HTTP", "WS", "HTTPS", "H2", "H3", "QUIC"):
            return True
        if self.cfg.all:
            return True
        return total >= self.UNKNOWN_MIN_BYTES

    def _identified(self, flow: Flow) -> bool:
        if flow.app in ("DNS", "QUIC"):
            return bool(flow.host) or flow.app == "QUIC"
        if flow.app:
            return bool(flow.host or flow.sni or flow.path)
        return False

    def _build(self, flow: Flow, now: float) -> Record:
        client, server = flow.client, flow.server
        if client is None or server is None:
            self._guess_direction(flow)
            client, server = flow.client, flow.server
        if client is None:
            client, server = flow.a, flow.b
        if server is None:
            server = flow.b if client == flow.a else flow.a

        rec = Record(ts=flow.ts)
        rec.proto = flow.proto
        rec.app = flow.app
        rec.method = flow.method
        rec.scheme = flow.scheme
        rec.path = flow.path
        rec.query = flow.query
        rec.status = flow.status
        rec.content_type = flow.content_type
        rec.server_hdr = flow.server_hdr
        rec.content_length = flow.content_length
        rec.bytes_out = flow.bytes.get(client, 0)
        rec.bytes_in = flow.bytes.get(server, 0)
        rec.pkts_out = flow.pkts.get(client, 0)
        rec.pkts_in = flow.pkts.get(server, 0)
        rec.duration = max(0.0, flow.last_seen - flow.ts)
        rec.pid = flow.pid
        rec.pname = flow.pname
        rec.client = str(client)
        rec.server = str(server)
        rec.server_ip = server.ip
        rec.server_port = server.port
        rec.sni = flow.sni
        rec.tls = flow.tls
        rec.alpn = flow.alpn
        rec.service = flow.service
        rec.requests = max(1, flow.requests)
        rec.notes = list(flow.notes)
        if flow.host:
            rec.host = flow.host
        else:
            name = self.dns.name_for(server.ip)
            rec.host = name or server.ip
        rec.show_port = server.port not in (80, 443, 53)
        if flow.app == "DNS" and flow.path.startswith(" → "):
            rec.notes.append(flow.path[3:])
            rec.path = ""
        return rec

    def _evict_some(self) -> None:
        items = sorted(self.flows.items(), key=lambda kv: kv[1].last_seen)
        for k, _ in items[: max(1, len(items) // 10)]:
            self.flows.pop(k, None)

    def flush(self, now: float) -> None:
        idle = float(self.cfg.idle)
        for key, flow in list(self.flows.items()):
            short_udp = flow.proto == "udp" and flow.app != "QUIC"
            timeout = min(idle, 4.0) if short_udp else idle
            if flow.fin_time is not None and now - flow.fin_time >= 0.35:
                done = True
            elif now - flow.last_seen >= timeout:
                done = True
            else:
                done = False
            if done:
                self.flows.pop(key, None)
                self._resolve(flow, now)
                if self._reportable(flow):
                    self.emit(self._build(flow, now), False)

    def finish(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        for key, flow in list(self.flows.items()):
            self.flows.pop(key, None)
            self._resolve(flow, now)
            if flow.app == "DNS" and not self.cfg.dns:
                continue
            if self._reportable(flow):
                self.emit(self._build(flow, now), False)


# --------------------------------------------------------------------------- #
#  output
# --------------------------------------------------------------------------- #

class Stats:
    def __init__(self) -> None:
        self.start = time.time()
        self.records = 0
        self.filtered = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.by_app: Dict[str, List[int]] = {}
        self.by_host: Dict[str, List[int]] = {}
        self.by_method: Dict[str, int] = {}
        self.errors: List[str] = []

    def add(self, rec: Record) -> None:
        self.records += 1
        self.bytes_in += rec.bytes_in
        self.bytes_out += rec.bytes_out
        app = rec.pname or "-"
        host = rec.host or rec.server_ip or "-"
        a = self.by_app.setdefault(app, [0, 0])
        a[0] += rec.bytes_total
        a[1] += 1
        h = self.by_host.setdefault(host, [0, 0])
        h[0] += rec.bytes_total
        h[1] += 1
        badge = rec.badge()
        self.by_method[badge] = self.by_method.get(badge, 0) + 1

    def _top(self, table: Dict[str, List[int]], n: int) -> List[Tuple[str, int, int]]:
        rows = sorted(table.items(), key=lambda kv: kv[1][0], reverse=True)[:n]
        return [(k, v[0], v[1]) for k, v in rows]

    def summary(self, c: Color, binary: bool, width: int) -> str:
        line = c.dim("─" * min(width, 78))
        dur = time.time() - self.start
        out = [line]
        out.append(
            f" {c.bold(PROG)} {__version__} · {c.dim(human_duration(dur))} · "
            f"{c.bold(str(self.records))} fetches"
            + (f" {c.dim(f'({self.filtered} filtered)')}" if self.filtered else "")
        )
        out.append(
            f" traffic   {c.fg('↓ ' + human_bytes(self.bytes_in, binary), 83)}   "
            f"{c.fg('↑ ' + human_bytes(self.bytes_out, binary), 75)}   "
            f"{c.dim('total ' + human_bytes(self.bytes_in + self.bytes_out, binary))}"
        )
        apps = self._top(self.by_app, 5)
        if apps:
            txt = " · ".join(
                f"{c.fg(name, app_color(name))} {c.dim(human_bytes(b, binary))}" for name, b, _ in apps
            )
            out.append(f" top apps  {txt}")
        hosts = self._top(self.by_host, 5)
        if hosts:
            txt = " · ".join(f"{h} {c.dim(human_bytes(b, binary))}" for h, b, _ in hosts)
            out.append(f" top hosts {txt}")
        if self.by_method:
            methods = sorted(self.by_method.items(), key=lambda kv: kv[1], reverse=True)
            txt = " · ".join(
                f"{c.paint(m, f'1;38;5;{BADGE_COLORS.get(m, 244)}')} {n}" for m, n in methods
            )
            out.append(f" methods   {txt}")
        if self.errors:
            out.append(f" {c.fg('notes', 214)}     " + "; ".join(self.errors[:5]))
        out.append(line)
        return "\n".join(out)


class Emitter:
    def __init__(self, args: argparse.Namespace, color: Color, stats: Stats) -> None:
        self.args = args
        self.c = color
        self.stats = stats
        self.filters = Filters(args) if any([
            args.host, args.exclude_host, args.app, args.exclude_app, args.pid,
            args.method, args.port, args.min_size, args.max_size is not None,
        ]) else None
        self.format = args.format
        self.binary = bool(args.binary)
        self.colorize = color.on and self.format == "pretty"
        self.sinks: List[Any] = []
        self._csv_writers: List[csv.DictWriter] = []
        if args.out:
            self.sinks.append(open(args.out, "w", encoding="utf-8", buffering=1))
        else:
            self.sinks.append(sys.stdout)
        self.log_sink = open(args.log, "a", encoding="utf-8", buffering=1) if args.log else None
        self._width_cache = (0.0, 100)
        self._csv_header_done = False

    # -- output helpers ---------------------------------------------------- #
    def width(self) -> int:
        now = time.time()
        if now - self._width_cache[0] < 2.0:
            return self._width_cache[1]
        w = self.args.width
        if not w:
            if sys.stdout.isatty():
                w = shutil.get_terminal_size((110, 24)).columns
            else:
                w = 110
        w = max(60, min(400, int(w)))
        self._width_cache = (now, w)
        return w

    def _write(self, sinks: Sequence[Any], text: str) -> None:
        for sink in sinks:
            try:
                sink.write(text + "\n")
                sink.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

    def emit(self, rec: Record, partial: bool = False) -> None:
        if partial and self.format != "pretty":
            return
        if self.filters:
            ok, _reason = self.filters.match(rec)
            if not ok:
                if not partial:
                    self.stats.filtered += 1
                return
        if not partial:
            self.stats.add(rec)
            if self.log_sink is not None:
                try:
                    self.log_sink.write(self._plain_line(rec) + "\n")
                    self.log_sink.flush()
                except (OSError, ValueError):
                    pass
        watch = bool(self.args.watch) and any(
            p.lower() in (rec.pname or "").lower() or p.lower() in rec.host.lower()
            for p in self.args.watch
        )
        if self.format == "json":
            self._write(self.sinks, json.dumps(rec.to_dict(), default=str))
            return
        if self.format == "csv":
            self._write_csv(rec)
            return
        self._write(self.sinks, self.format_line(rec, partial=partial, watch=watch))

    def _plain_line(self, rec: Record) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec.ts))
        out = (f"{ts} [{rec.badge():<5}] {rec.url()} - {human_bytes(rec.bytes_total, self.binary)}"
               f"  ↓{human_bytes(rec.bytes_in, self.binary)} ↑{human_bytes(rec.bytes_out, self.binary)}")
        if rec.pname:
            out += f"  {rec.pname}({rec.pid})" if rec.pid else f"  {rec.pname}"
        if rec.status:
            out += f"  {rec.status}"
        return out

    def _write_csv(self, rec: Record) -> None:
        if not self._csv_header_done:
            for sink in self.sinks:
                try:
                    writer = csv.DictWriter(sink, fieldnames=Record.CSV_FIELDS,
                                            extrasaction="ignore")
                    writer.writeheader()
                    self._csv_writers.append(writer)
                except (OSError, ValueError):
                    pass
            self._csv_header_done = True
        row = rec.to_dict()
        clean = {k: ("" if row.get(k) is None else row.get(k)) for k in Record.CSV_FIELDS}
        for w in self._csv_writers:
            try:
                w.writerow(clean)
            except (OSError, ValueError):
                pass
        for sink in self.sinks:
            try:
                sink.flush()
            except (OSError, ValueError):
                pass

    # -- fancy formatting -------------------------------------------------- #
    def _format_url(self, rec: Record, width: int, full: bool) -> str:
        c = self.c
        host = rec.host or rec.server_ip or "-"
        if rec.show_port and rec.server_port:
            host = f"{host}:{rec.server_port}"
        path = rec.path or ""
        if not path or path == "-":
            plain = host
            disp = plain if (full or len(plain) <= width) else truncate_tail(plain, width)
            if not self.colorize:
                return disp
            return c.fg(c.bold(disp), 51)
        plain = host + path + (("?" + rec.query) if rec.query else "")
        disp = plain if (full or len(plain) <= width) else truncate_tail(plain, width)
        if not self.colorize:
            return disp
        n = 0
        while n < len(disp) and n < len(host) and disp[n] == host[n]:
            n += 1
        out = c.paint(disp[:n], "1;38;5;51") if n else ""
        rest = disp[n:]
        q = rest.find("?")
        if q >= 0:
            main, query = rest[:q], rest[q:]
        else:
            main, query = rest, ""
        if "/" in main[:-1]:
            idx = main.rstrip("/").rfind("/")
            directory, base = main[:idx + 1], main[idx + 1:]
        else:
            directory, base = "", main
        out += c.fg(directory, 245)
        out += c.paint(base, "1;38;5;226")
        if query:
            out += c.fg(query, 213)
        return out

    def format_line(self, rec: Record, partial: bool = False, watch: bool = False) -> str:
        args = self.args
        c = self.c if self.colorize else Color(False)
        width = self.width()
        ts = time.strftime("%H:%M:%S", time.localtime(rec.ts))
        badge = rec.badge()
        bcol = BADGE_COLORS.get(badge, 244)
        badge_txt = c.paint(f"[{badge:<5}]", f"1;38;5;{bcol}") if self.colorize else f"[{badge:<5}]"
        prefix = (c.dim(ts) if self.colorize else ts) + " " + badge_txt + " "
        total = rec.bytes_total
        if partial:
            size_txt = c.dim(human_bytes(total, self.binary)) if self.colorize else human_bytes(total, self.binary)
        else:
            size_txt = c.paint(human_bytes(total, self.binary), f"1;38;5;{size_color(total)}") if self.colorize \
                else human_bytes(total, self.binary)
        sep = c.dim(" - ") if self.colorize else " - "

        # -- extras, highest value first: they are dropped on narrow terms --
        optional: List[Tuple[str, int]] = []
        if rec.pname:
            optional.append((f"{rec.pname}({rec.pid})" if rec.pid else rec.pname,
                             app_color(rec.pname)))
        elif rec.pid:
            optional.append((f"pid {rec.pid}", 244))
        if rec.status:
            optional.append((str(rec.status), status_color(rec.status)))
        if rec.duration >= 0.05:
            optional.append((human_duration(rec.duration), 244))
        if rec.duration >= 0.2 and total:
            optional.append((human_bytes(int(total / rec.duration), self.binary) + "/s", 244))
        if rec.bytes_in:
            optional.append(("↓" + human_bytes(rec.bytes_in, self.binary), 83))
        if rec.bytes_out:
            optional.append(("↑" + human_bytes(rec.bytes_out, self.binary), 75))
        if rec.tls and rec.app in ("HTTPS", "H2", "H3"):
            optional.append(("tls" + rec.tls, 244))
        if rec.alpn and rec.alpn != "http/1.1" and rec.badge() not in ("H2", "H3", "QUIC"):
            optional.append((rec.alpn, 244))
        if rec.requests > 1:
            optional.append((f"×{rec.requests}", 244))
        if rec.content_length and rec.content_length > rec.bytes_in + (rec.content_length // 50):
            optional.append((f"cl {human_bytes(rec.content_length, self.binary)}", 214))
        if args.peer:
            optional.append((f"→ {rec.server}", 244))
        optional.extend((n, 244) for n in rec.notes)
        if partial:
            optional.append(("in progress…", 214))

        fixed = vlen(prefix) + vlen(sep) + vlen(size_txt)
        min_url = 30 if width < 100 else 42
        host_disp = rec.host or rec.server_ip or "-"
        if rec.show_port and rec.server_port:
            host_disp = f"{host_disp}:{rec.server_port}"
        url_full_len = len(host_disp) + (len(rec.path) if rec.path not in ("", "-") else 0)
        if rec.query:
            url_full_len += 1 + len(rec.query)
        # a short URL leaves room for more extras, a long one takes what it needs
        url_alloc = min(url_full_len, max(min_url, width - fixed - 4))
        room = width - fixed - url_alloc - 4
        chosen: List[str] = []
        for text, col in optional:
            need = vlen(text) + 3
            if need > room:
                continue
            chosen.append(c.fg(text, col) if self.colorize else text)
            room -= need
        joiner = c.dim(" · ") if self.colorize else " · "
        tail = ("  " + joiner.join(chosen)) if chosen else ""

        full_url = bool(args.full_url) or self.format == "plain"
        if full_url:
            url_budget = url_full_len
        else:
            url_budget = min(url_full_len, max(min_url, width - fixed - vlen(tail) - 4))
        url_txt = self._format_url(rec, url_budget, full_url)
        line = f"{prefix}{url_txt}{sep}{size_txt}{tail}"
        if watch and self.colorize:
            line = "\x1b[7m" + line + "\x1b[0m"
        return line

    def banner(self, text: str) -> None:
        if not self.args.quiet:
            try:
                sys.stderr.write(self.c.dim(f"[{PROG}] ") + text + "\n")
                sys.stderr.flush()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
#  pcap writer
# --------------------------------------------------------------------------- #

class PcapWriter:
    def __init__(self, path: str, snaplen: int = 262144, linktype: int = 1) -> None:
        self.path = path
        self.linktype = linktype
        self.warned = False
        self.fh = open(path, "wb", buffering=1 << 16)
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts: float, data: bytes, linktype: int = 1) -> None:
        if linktype != self.linktype and not self.warned:
            self.warned = True
            sys.stderr.write(f"[{PROG}] pcap: mixing link types (wanted {self.linktype}, got {linktype}); "
                             "captured frame may be unreadable\n")
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self.fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self.fh.write(data)

    def close(self) -> None:
        try:
            self.fh.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
#  capture engine
# --------------------------------------------------------------------------- #

class Link:
    __slots__ = ("name", "sock", "hwtype", "mode", "misses", "down_warned", "pcap_linktype")

    def __init__(self, name: str, sock: Any, hwtype: int, mode: str = "eth") -> None:
        self.name = name
        self.sock = sock
        self.hwtype = hwtype
        self.mode = mode
        self.misses = 0
        self.down_warned = False
        self.pcap_linktype = 113 if mode == "sll" else 1


class Engine:
    """Turns raw frames into Records.  Usable without sockets (see --selftest)."""

    def __init__(self, cfg: argparse.Namespace, emit: Callable[[Record, bool], None],
                 proc: Optional[ProcMap] = None, dns: Optional[DnsCache] = None,
                 pcap: Optional[PcapWriter] = None, on_error: Optional[Callable[[str], None]] = None) -> None:
        self.cfg = cfg
        self.dns = dns or DnsCache()
        self.proc = proc or ProcMap()
        self.pcap = pcap
        self.on_error = on_error or (lambda msg: None)
        self.tracker = Tracker(cfg, self.proc, self.dns, emit)
        self.packets = 0

    def process_frame(self, data: bytes, ts: float, link: Link) -> None:
        if self.pcap is not None:
            self.pcap.write(ts, data, getattr(link, "pcap_linktype", 1))
        self.packets += 1
        if link.mode == "sll":
            if len(data) < 16:
                return
            etype = struct.unpack_from("!H", data, 14)[0]
            off = 16
        else:
            if len(data) < 14:
                return
            etype = struct.unpack_from("!H", data, 12)[0]
            off = 14
            while etype in VLAN_TYPES and len(data) >= off + 4:
                etype = struct.unpack_from("!H", data, off + 2)[0]
                off += 4
            if etype not in (ETH_P_IP, ETH_P_IPV6) and link.mode == "auto":
                if len(data) >= 16:
                    alt = struct.unpack_from("!H", data, 14)[0]
                    if alt in (ETH_P_IP, ETH_P_IPV6):
                        link.mode = "sll"
                        etype, off = alt, 16
                    else:
                        link.misses += 1
                        if link.misses > 64:
                            link.mode = "eth"
                if etype not in (ETH_P_IP, ETH_P_IPV6):
                    return
        if etype == ETH_P_IP:
            parsed = parse_ipv4(data, off)
        elif etype == ETH_P_IPV6:
            parsed = parse_ipv6(data, off)
        else:
            return
        if not parsed:
            return
        _ver, src_ip, dst_ip, proto, payload = parsed
        if proto == 6:
            seg = parse_tcp(payload)
            if not seg:
                return
            sport, dport, _seq, _ack, flags, app_data = seg
            # ignore pure ACKs / window updates: no payload, no state change
            if not app_data and not (flags & (0x01 | 0x02 | 0x04)):
                return
            self.tracker.handle(ts, "tcp",
                                Endpoint(norm_ip(src_ip), sport),
                                Endpoint(norm_ip(dst_ip), dport),
                                app_data, flags)
        elif proto == 17:
            seg = parse_udp(payload)
            if not seg:
                return
            sport, dport, app_data = seg
            self.tracker.handle(ts, "udp",
                                Endpoint(norm_ip(src_ip), sport),
                                Endpoint(norm_ip(dst_ip), dport),
                                app_data, 0)

    def tick(self, now: Optional[float] = None) -> None:
        self.tracker.flush(time.time() if now is None else now)

    def finish(self, now: Optional[float] = None) -> None:
        self.tracker.finish(now)


class Sniffer:
    def __init__(self, cfg: argparse.Namespace, engine: Engine, emit_banner: Callable[[str], None]) -> None:
        self.cfg = cfg
        self.engine = engine
        self.banner = emit_banner
        self.links: List[Link] = []
        self.skipped: List[str] = []

    @staticmethod
    def interfaces() -> List[Tuple[str, int, str]]:
        out = []
        for _idx, name in socket.if_nameindex():
            hwtype = 1
            try:
                with open(f"/sys/class/net/{name}/type", "r") as fh:
                    hwtype = int(fh.read().strip())
            except (OSError, ValueError):
                pass
            state = "?"
            try:
                with open(f"/sys/class/net/{name}/operstate", "r") as fh:
                    state = fh.read().strip()
            except OSError:
                pass
            out.append((name, hwtype, state))
        return out

    def open(self) -> None:
        wanted = self.cfg.interface or []
        ifaces = self.interfaces()
        for name, hwtype, state in ifaces:
            if name == "lo" and self.cfg.no_loopback:
                continue
            if wanted and name not in wanted:
                continue
            if not wanted:
                if not self.cfg.all_ifaces and is_virtual_iface(name):
                    self.skipped.append(f"{name} (virtual, use --all-ifaces)")
                    continue
                if state not in ("up", "unknown") and state != "?":
                    self.skipped.append(f"{name} ({state})")
                    continue
            if hwtype not in SUPPORTED_LINK_TYPES and not self.cfg.force_hwtype:
                self.skipped.append(f"{name} (link type {hwtype}, use -i {name} --force-hwtype)")
                continue
            mode = SUPPORTED_LINK_TYPES.get(hwtype, "auto")
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            except PermissionError:
                raise
            except OSError as exc:
                self.skipped.append(f"{name} ({exc.strerror})")
                continue
            try:
                sock.bind((name, 0))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
                if self.cfg.promisc:
                    mreq = struct.pack("IHH8s", 0, socket.PACKET_MR_PROMISC, 0, b"")
                    sock.setsockopt(socket.SOL_PACKET, socket.PACKET_ADD_MEMBERSHIP, mreq)
                sock.setblocking(False)
            except OSError as exc:
                self.skipped.append(f"{name} ({exc.strerror})")
                try:
                    sock.close()
                except OSError:
                    pass
                continue
            link = Link(name, sock, hwtype, mode)
            link.pcap_linktype = 113 if mode == "sll" else 1
            self.links.append(link)
        if not self.links:
            raise RuntimeError(
                "no capturable interfaces"
                + (f" (skipped: {', '.join(self.skipped)})" if self.skipped else "")
            )

    def drain(self, link: Link, ts: float, budget: int = 4000) -> int:
        n = 0
        while n < budget:
            try:
                data = link.sock.recv(self.cfg.snaplen)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                if exc.errno == errno.ENETDOWN and not link.down_warned:
                    link.down_warned = True
                    self.banner(f"{link.name}: interface went down")
                break
            if not data:
                break
            n += 1
            try:
                self.engine.process_frame(data, ts, link)
            except Exception as exc:                       # never die on a weird frame
                self.engine.on_error(f"frame on {link.name}: {exc!r}")
        return n

    def close(self) -> None:
        for link in self.links:
            try:
                link.sock.close()
            except OSError:
                pass
        self.links = []

    def names(self) -> List[str]:
        return [lnk.name for lnk in self.links]


# --------------------------------------------------------------------------- #
#  demo + selftest
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#  MITM proxy — full URLs for TLS, no mitmproxy needed
# --------------------------------------------------------------------------- #

MITM_CA_DIRNAME = "mitm"
MITM_CA_NAME = "netlogger MITM CA"
_PROXY_HOP = {"proxy-connection", "proxy-authorization", "proxy-authenticate"}


class _ProtocolError(Exception):
    pass


def _target_home() -> str:
    """Home of the human who invoked us (not /root when using sudo)."""
    user = os.environ.get("SUDO_USER") or ""
    if os.geteuid() == 0 and user and user != "root":
        try:
            import pwd
            return pwd.getpwnam(user).pw_dir
        except (KeyError, ImportError):
            pass
    return os.path.expanduser("~")


def _target_uid_gid() -> Optional[Tuple[int, int, str]]:
    user = os.environ.get("SUDO_USER") or ""
    if os.geteuid() != 0 or not user or user == "root":
        return None
    try:
        import pwd
        pw = pwd.getpwnam(user)
        return pw.pw_uid, pw.pw_gid, pw.pw_dir
    except (KeyError, ImportError):
        return None


def mitm_default_dir() -> str:
    if os.geteuid() == 0 and _target_uid_gid() is not None:
        base = os.path.join(_target_home(), ".config")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "netlogger", MITM_CA_DIRNAME)


def split_host_port(authority: str, default_port: int = 443) -> Tuple[str, int]:
    """'example.com:8443', '[::1]:443' or 'example.com' -> (host, port)."""
    authority = (authority or "").strip()
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return authority, default_port
        host = authority[1:end]
        rest = authority[end + 1:]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return host, default_port
        return host, default_port
    if authority.count(":") == 1:
        host, maybe_port = authority.rsplit(":", 1)
        try:
            return host, int(maybe_port)
        except ValueError:
            return host, default_port
    return authority, default_port


def absolute_target(target: str) -> Tuple[str, str, str, int]:
    """http://host:port/path?q -> (scheme, host, path?q, port)."""
    try:
        sp = urllib.parse.urlsplit(target)
    except ValueError:
        return "http", "", target, 80
    scheme = (sp.scheme or "http").lower()
    host = sp.hostname or ""
    try:
        port = sp.port or (443 if scheme in ("https", "wss") else 80)
    except ValueError:
        port = 443 if scheme in ("https", "wss") else 80
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    return scheme, host, path, port


def _split_head(head: bytes) -> Tuple[str, List[Tuple[str, str]]]:
    text = head.split(b"\r\n\r\n", 1)[0]
    lines = re.split(rb"\r?\n", text)
    if not lines:
        raise _ProtocolError("empty head")
    try:
        first = lines[0].decode("latin-1")
        hdrs: List[Tuple[str, str]] = []
        for raw in lines[1:]:
            if not raw or b":" not in raw:
                continue
            k, v = raw.split(b":", 1)
            hdrs.append((k.decode("latin-1").strip(), v.decode("latin-1").strip()))
        return first, hdrs
    except UnicodeDecodeError as exc:
        raise _ProtocolError("bad header encoding") from exc


def parse_request_head(head: bytes) -> Tuple[str, str, str, List[Tuple[str, str]]]:
    first, hdrs = _split_head(head)
    parts = first.split(" ")
    if len(parts) < 2:
        raise _ProtocolError("bad request line")
    method = parts[0].upper()
    target = parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.0"
    if not method or not target:
        raise _ProtocolError("bad request line")
    return method, target, version, hdrs


def parse_response_head(head: bytes) -> Tuple[int, str, List[Tuple[str, str]]]:
    first, hdrs = _split_head(head)
    parts = first.split(" ", 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise _ProtocolError("bad status line")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise _ProtocolError("bad status code") from exc
    return status, (parts[2] if len(parts) > 2 else ""), hdrs


def header_dict(hdrs: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in hdrs:
        out[k.lower()] = v
    return out


def sanitise_headers(hdrs: Sequence[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Keep the first Host/Content-Length/Transfer-Encoding, drop duplicates."""
    once = {"host", "content-length", "transfer-encoding"}
    seen = set()
    out: List[Tuple[str, str]] = []
    for k, v in hdrs:
        kl = k.lower()
        if kl in once:
            if kl in seen:
                continue
            seen.add(kl)
        out.append((k, v))
    return out


def build_head(first_line: str, hdrs: Sequence[Tuple[str, str]], *,
               host: str = "", default_port: int = 0, drop: Sequence[str] = ()) -> bytes:
    drop_l = {d.lower() for d in drop} | _PROXY_HOP
    out = [first_line]
    have_host = False
    for k, v in hdrs:
        kl = k.lower()
        if kl in drop_l:
            continue
        if kl == "host":
            have_host = True
        out.append(f"{k}: {v}")
    if not have_host and host:
        h = f"[{host}]" if ":" in host and not host.startswith("[") else host
        if default_port:
            h += f":{default_port}"
        out.append(f"Host: {h}")
    return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1", "replace")


def _origin_form(target: str) -> str:
    """Split proxy request target into (origin path, query)."""
    if target.startswith(("http://", "https://")):
        _scheme, _host, path, _port = absolute_target(target)
        return path
    return target or "/"


def _split_path_query(path: str) -> Tuple[str, str]:
    p, _, q = (path or "/").partition("?")
    return (p or "/"), q


class _Reader:
    """Buffered reader over a blocking socket (plain or TLS)."""

    def __init__(self, sock: Any, initial: bytes = b"") -> None:
        self.sock = sock
        self.buf = bytearray(initial)

    def _fill(self, n: int = 65536) -> bool:
        data = self.sock.recv(n)
        if not data:
            return False
        self.buf += data
        return True

    def read_until(self, delim: bytes, limit: int = 131072) -> bytes:
        while True:
            idx = self.buf.find(delim)
            if idx >= 0:
                end = idx + len(delim)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            if len(self.buf) > limit:
                raise _ProtocolError("header too large")
            if not self._fill():
                out = bytes(self.buf)
                self.buf.clear()
                return out

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill(max(65536, n - len(self.buf))):
                raise EOFError("unexpected eof")
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_some(self, n: int = 65536) -> bytes:
        if self.buf:
            out = bytes(self.buf[:n])
            del self.buf[:n]
            return out
        return self.sock.recv(n)


def _relay_exact(reader: _Reader, writer: Any, n: int) -> int:
    left = n
    done = 0
    while left > 0:
        chunk = reader.read_some(min(left, 65536))
        if not chunk:
            raise EOFError("short body")
        writer.sendall(chunk)
        left -= len(chunk)
        done += len(chunk)
    return done


def _relay_chunked(reader: _Reader, writer: Any) -> int:
    total = 0
    while True:
        line = reader.read_until(b"\r\n", 16384)
        if not line.endswith(b"\r\n"):
            raise EOFError("short chunk")
        writer.sendall(line)
        total += len(line)
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError as exc:
            raise _ProtocolError("bad chunk size") from exc
        if size == 0:
            while True:
                trailer = reader.read_until(b"\r\n", 16384)
                if not trailer.endswith(b"\r\n"):
                    raise EOFError("short trailer")
                writer.sendall(trailer)
                total += len(trailer)
                if trailer == b"\r\n":
                    return total
        data = reader.read_exact(size + 2)
        writer.sendall(data)
        total += len(data)


def _relay_to_eof(reader: _Reader, writer: Any) -> int:
    total = 0
    while True:
        chunk = reader.read_some(65536)
        if not chunk:
            return total
        writer.sendall(chunk)
        total += len(chunk)


class CertAuthority:
    """Local CA + on-demand per-host leaf certificates.

    Uses ``cryptography`` when present and falls back to the openssl CLI, so
    MITM mode adds no mandatory Python dependency.
    """

    def __init__(self, directory: str) -> None:
        self.dir = os.path.abspath(os.path.expanduser(directory))
        self.cert_path = os.path.join(self.dir, "ca.pem")
        self.key_path = os.path.join(self.dir, "ca-key.pem")
        self.certs_dir = os.path.join(self.dir, "certs")
        self._backend_name: Optional[str] = None
        self._lock = threading.Lock()
        self._contexts: Dict[str, ssl.SSLContext] = {}
        self._paths: Dict[str, Tuple[str, str]] = {}

    # -- setup ------------------------------------------------------------- #
    def backend(self) -> str:
        if self._backend_name:
            return self._backend_name
        try:
            import cryptography  # noqa: F401
            self._backend_name = "cryptography"
        except ImportError:
            if shutil.which("openssl"):
                self._backend_name = "openssl"
            else:
                raise RuntimeError(
                    "MITM needs the python 'cryptography' module or the openssl CLI.\n"
                    "  Arch:   sudo pacman -S python-cryptography openssl\n"
                    "  Debian: sudo apt install python3-cryptography openssl"
                )
        return self._backend_name

    def exists(self) -> bool:
        return os.path.isfile(self.cert_path) and os.path.isfile(self.key_path)

    def ensure(self) -> None:
        if self.exists():
            for path in (self.cert_path, self.key_path):
                try:
                    with open(path, "rb") as fh:
                        fh.read(1)
                except OSError as exc:
                    raise RuntimeError(
                        f"CA in {self.dir} is not readable ({exc}).\n"
                        f"  run with the same user that created it, as root, or use --mitm-ca-dir"
                    ) from exc
            self._fix_perms()
            return
        with self._lock:
            if self.exists():
                return
            if os.path.exists(self.cert_path) or os.path.exists(self.key_path):
                raise RuntimeError(
                    f"incomplete CA in {self.dir} (cert or key missing).\n"
                    f"  remove {self.dir} and run again, or use --mitm-ca-reset"
                )
            os.makedirs(self.dir, exist_ok=True)
            os.makedirs(self.certs_dir, exist_ok=True)
            try:
                self._generate_ca()
            except Exception:
                for p in (self.cert_path, self.key_path):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
                raise
            self._fix_perms()

    def _fix_perms(self) -> None:
        try:
            os.chmod(self.dir, 0o711)
        except OSError:
            pass
        try:
            os.chmod(self.cert_path, 0o644)
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        try:
            os.chmod(self.certs_dir, 0o700)
        except OSError:
            pass
        info = _target_uid_gid()
        if info is not None:
            uid, gid, _home = info
            for path in (self.dir, self.cert_path, self.key_path, self.certs_dir):
                try:
                    os.chown(path, uid, gid)
                except OSError:
                    pass

    def reset(self) -> None:
        for path in (self.cert_path, self.key_path):
            try:
                os.unlink(path)
            except OSError:
                pass
        shutil.rmtree(self.certs_dir, ignore_errors=True)
        self._contexts.clear()
        self._paths.clear()

    # -- CA generation ----------------------------------------------------- #
    def _generate_ca(self) -> None:
        if self.backend() == "cryptography":
            self._ca_cryptography()
        else:
            self._ca_openssl()

    def _ca_cryptography(self) -> None:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, MITM_CA_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "netlogger"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self._write_private(self.key_path, key_pem)
        with open(self.cert_path, "wb") as fh:
            fh.write(cert_pem)

    def _ca_openssl(self) -> None:
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
            "-keyout", self.key_path, "-out", self.cert_path, "-days", "3650",
            "-subj", f"/CN={MITM_CA_NAME}/O=netlogger",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]
        old_umask = os.umask(0o077)
        try:
            self._run_openssl(cmd)
        finally:
            os.umask(old_umask)
        os.chmod(self.key_path, 0o600)

    # -- leaf certificates ------------------------------------------------- #
    def _safe_name(self, host: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", host)[:80] or "host"
        digest = hashlib.sha256(host.encode("utf-8", "replace")).hexdigest()[:8]
        return f"{safe}-{digest}"

    def leaf_paths(self, host: str) -> Tuple[str, str]:
        host = self._normalise_host(host)
        with self._lock:
            hit = self._paths.get(host)
            if hit and os.path.isfile(hit[0]) and os.path.isfile(hit[1]):
                return hit
        os.makedirs(self.certs_dir, exist_ok=True)
        base = os.path.join(self.certs_dir, self._safe_name(host))
        cert_path, key_path = base + ".pem", base + "-key.pem"
        with self._lock:
            hit = self._paths.get(host)
            if hit and os.path.isfile(hit[0]) and os.path.isfile(hit[1]):
                return hit
            if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
                if self.backend() == "cryptography":
                    self._leaf_cryptography(host, cert_path, key_path)
                else:
                    self._leaf_openssl(host, cert_path, key_path)
                info = _target_uid_gid()
                if info is not None:
                    for p in (cert_path, key_path, self.certs_dir):
                        try:
                            os.chown(p, info[0], info[1])
                        except OSError:
                            pass
            self._paths[host] = (cert_path, key_path)
            return cert_path, key_path

    @staticmethod
    def _normalise_host(host: str) -> str:
        host = (host or "").strip().strip("[]")
        if not host:
            return "localhost"
        try:
            if not host.isascii():
                return host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        return host

    def _leaf_cryptography(self, host: str, cert_path: str, key_path: str) -> None:
        import datetime
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        with open(self.cert_path, "rb") as fh:
            ca_cert = x509.load_pem_x509_certificate(fh.read())
        with open(self.key_path, "rb") as fh:
            ca_key = serialization.load_pem_private_key(fh.read(), password=None)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            san: Any = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cn = host if len(host) <= 64 else host[:64]
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        self._write_private(key_path, key_pem)
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))

    def _leaf_openssl(self, host: str, cert_path: str, key_path: str) -> None:
        import ipaddress
        base = cert_path[:-4]
        cnf = base + ".cnf"
        csr = base + ".csr"
        old_umask = os.umask(0o077)
        try:
            is_ip = False
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                pass
            san_line = f"IP.1 = {host}" if is_ip else f"DNS.1 = {host}"
            with open(cnf, "w", encoding="utf-8") as fh:
                fh.write(
                    "[req]\ndistinguished_name=dn\nprompt=no\n"
                    f"[dn]\nCN={host[:64]}\n"
                    "[ext]\nbasicConstraints=critical,CA:FALSE\n"
                    "keyUsage=critical,digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\n"
                    f"subjectAltName=@alt\n[alt]\n{san_line}\n"
                )
            self._run_openssl([
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", csr, "-config", cnf,
            ])
            self._run_openssl([
                "openssl", "x509", "-req", "-in", csr,
                "-CA", self.cert_path, "-CAkey", self.key_path, "-CAcreateserial",
                "-days", "825", "-sha256", "-extfile", cnf, "-extensions", "ext",
                "-out", cert_path,
            ])
            os.chmod(key_path, 0o600)
        finally:
            for path in (cnf, csr):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            os.umask(old_umask)

    @staticmethod
    def _write_private(path: str, data: bytes) -> None:
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    @staticmethod
    def _run_openssl(cmd: Sequence[str]) -> None:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"openssl failed: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise RuntimeError("openssl failed: " + (detail[-1] if detail else "unknown error"))

    # -- TLS contexts ------------------------------------------------------ #
    def leaf_context(self, host: str) -> ssl.SSLContext:
        host = self._normalise_host(host)
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is not None:
                return ctx
        cert_path, key_path = self.leaf_paths(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except (AttributeError, ValueError):
            pass
        ctx.load_cert_chain(cert_path, key_path)
        ctx.set_alpn_protocols(["http/1.1"])
        with self._lock:
            if len(self._contexts) > 1000:
                self._contexts.clear()
            self._contexts[host] = ctx
        return ctx

    def fingerprint(self) -> str:
        try:
            if self.backend() == "cryptography":
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes
                with open(self.cert_path, "rb") as fh:
                    cert = x509.load_pem_x509_certificate(fh.read())
                digest = cert.fingerprint(hashes.SHA256()).hex()
            else:
                proc = subprocess.run(
                    ["openssl", "x509", "-in", self.cert_path, "-noout",
                     "-fingerprint", "-sha256"],
                    capture_output=True, text=True, timeout=20,
                )
                digest = (proc.stdout or "").split("=", 1)[-1].strip().replace(":", "")
            return ":".join(digest[i:i + 2].upper() for i in range(0, len(digest), 2))
        except Exception:
            return ""


# --------------------------------------------------------------------------- #
#  CA trust installation
# --------------------------------------------------------------------------- #

def _sudo_prefix() -> List[str]:
    if os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    return [sudo] if sudo else []


def _run_cmd(cmd: Sequence[str], *, capture: bool = False, timeout: float = 120) -> Tuple[int, str]:
    try:
        proc = subprocess.run(
            list(cmd), text=True, timeout=timeout,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
        )
        return proc.returncode, (proc.stdout or "") if capture else ""
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def system_anchor() -> Tuple[Optional[str], Optional[List[str]]]:
    if os.path.isdir("/etc/ca-certificates/trust-source/anchors") and shutil.which("update-ca-trust"):
        return "/etc/ca-certificates/trust-source/anchors/netlogger.crt", ["update-ca-trust"]
    if os.path.isdir("/usr/local/share/ca-certificates") and shutil.which("update-ca-certificates"):
        return "/usr/local/share/ca-certificates/netlogger.crt", ["update-ca-certificates"]
    if os.path.isdir("/etc/pki/ca-trust/source/anchors") and shutil.which("update-ca-trust"):
        return "/etc/pki/ca-trust/source/anchors/netlogger.crt", ["update-ca-trust"]
    return None, None


def nss_dirs() -> List[str]:
    home = _target_home()
    found: List[str] = []
    for path in (os.path.join(home, ".pki", "nssdb"),):
        if os.path.isdir(path):
            found.append(path)
    patterns = [
        os.path.join(home, ".mozilla", "firefox", "*"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox", "*"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox", "*"),
    ]
    for pattern in patterns:
        for profile in glob.glob(pattern):
            if os.path.isfile(os.path.join(profile, "cert9.db")):
                found.append(profile)
    seen = set()
    out = []
    for d in found:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _session_prefix() -> List[str]:
    """Prefix to run a desktop command as the invoking user (for gsettings/NSS)."""
    user = os.environ.get("SUDO_USER") or ""
    if os.geteuid() != 0 or not user or user == "root":
        return []
    try:
        import pwd
        pw = pwd.getpwnam(user)
    except (KeyError, ImportError):
        return []
    runtime = f"/run/user/{pw.pw_uid}"
    env = [f"HOME={pw.pw_dir}", f"USER={user}", f"LOGNAME={user}"]
    if os.path.isdir(runtime):
        env += [f"XDG_RUNTIME_DIR={runtime}", f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"]
    if shutil.which("runuser"):
        return ["runuser", "-u", user, "--", "env"] + env
    if shutil.which("sudo"):
        return ["sudo", "-u", user, "--", "env"] + env
    return []


def ca_trusted_anywhere(ca: CertAuthority) -> bool:
    """True if this exact CA is already trusted system-wide or in any NSS store."""
    try:
        with open(ca.cert_path, "rb") as fh:
            cert = fh.read().strip()
    except OSError:
        return False
    if not cert:
        return False
    anchor, _ = system_anchor()
    if anchor and os.path.isfile(anchor):
        try:
            with open(anchor, "rb") as fh:
                if fh.read().strip() == cert:
                    return True
        except OSError:
            pass
    if shutil.which("certutil"):
        prefix = _session_prefix()
        for db in nss_dirs():
            code, out = _run_cmd(prefix + ["certutil", "-L", "-d", "sql:" + db],
                                 capture=True, timeout=20)
            if code == 0 and MITM_CA_NAME in out:
                return True
    return False


def install_ca(ca: CertAuthority, color: Color, remove: bool = False,
               stream: Optional[Any] = None) -> int:
    sink = stream or sys.stdout
    rc = 0
    anchor, update = system_anchor()
    prefix = _sudo_prefix()
    action = "remove" if remove else "install"
    if not anchor:
        sys.stderr.write(f"[{PROG}] no known system CA directory; skipping system trust\n")
        rc = 2
    else:
        if remove:
            code, _ = _run_cmd(prefix + ["rm", "-f", anchor])
        else:
            code, _ = _run_cmd(prefix + ["install", "-d", os.path.dirname(anchor)])
            if code == 0:
                code, _ = _run_cmd(prefix + ["install", "-m", "0644", ca.cert_path, anchor])
        if code != 0:
            sys.stderr.write(f"[{PROG}] could not {action} {anchor} (exit {code})\n")
            rc = 2
        elif update:
            code, _ = _run_cmd(prefix + update)
            if code != 0:
                sys.stderr.write(f"[{PROG}] {update[0]} failed (exit {code})\n")
                rc = 2
        if code == 0:
            verb = "removed from" if remove else "installed in"
            sink.write(color.fg(f"  system trust: {verb} {anchor}", 42) + "\n")
    if shutil.which("certutil"):
        dirs = nss_dirs()
        if dirs:
            user_prefix = _session_prefix()
            for db in dirs:
                _run_cmd(user_prefix + ["certutil", "-d", "sql:" + db, "-D", "-n", MITM_CA_NAME],
                         capture=True, timeout=30)
                if not remove:
                    code, out = _run_cmd(
                        user_prefix + ["certutil", "-d", "sql:" + db, "-A", "-t", "C,,", "-n",
                                       MITM_CA_NAME, "-i", ca.cert_path],
                        capture=True, timeout=30,
                    )
                    if code != 0:
                        sys.stderr.write(f"[{PROG}] certutil {db} failed: {out.strip()[:200]}\n")
                        rc = 2
                    else:
                        sink.write(color.fg(f"  browser trust: {db}", 42) + "\n")
        else:
            sys.stderr.write(f"[{PROG}] no NSS database found (Firefox/Chromium not set up yet)\n")
    else:
        sys.stderr.write(f"[{PROG}] certutil not installed — Firefox/Chrome may need the CA manually\n")
    if remove:
        sink.write(color.dim("  restart browsers for the change to take effect") + "\n")
    else:
        sink.write(color.dim("  restart browsers; apps with certificate pinning will still refuse") + "\n")
    return rc


def show_ca(ca: CertAuthority, color: Color, stream: Optional[Any] = None) -> int:
    sink = stream or sys.stdout
    if not ca.exists():
        sink.write(f"  CA not created yet: {ca.cert_path}\n")
        sink.write(f"  it is created automatically by: {PROG} --mitm\n")
        return 0
    fp = ca.fingerprint()
    sink.write(f"  CA certificate: {ca.cert_path}\n")
    sink.write(f"  CA private key: {ca.key_path}  (keep this secret)\n")
    if fp:
        sink.write(f"  SHA-256:        {fp}\n")
    sink.write(f"  trust it with:  {PROG} --mitm-ca-install\n")
    return 0


# --------------------------------------------------------------------------- #
#  GNOME system proxy
# --------------------------------------------------------------------------- #

PROXY_KEYS = (
    ("mode", "org.gnome.system.proxy mode"),
    ("http_host", "org.gnome.system.proxy.http host"),
    ("http_port", "org.gnome.system.proxy.http port"),
    ("https_host", "org.gnome.system.proxy.https host"),
    ("https_port", "org.gnome.system.proxy.https port"),
    ("ignore_hosts", "org.gnome.system.proxy ignore-hosts"),
)


def proxy_state_path(ca_dir: str) -> str:
    return os.path.join(ca_dir, "proxy-state.json")


def _gsettings(spec: str, value: Optional[str] = None) -> Tuple[int, str]:
    schema, key = spec.rsplit(" ", 1)
    cmd = _session_prefix() + ["gsettings"]
    cmd += ["get", schema, key] if value is None else ["set", schema, key, value]
    return _run_cmd(cmd, capture=True, timeout=15)


def set_system_proxy(ca_dir: str, host: str, port: int) -> Tuple[Optional[str], bool]:
    """Point GNOME's proxy at us, saving the previous values. Returns (state path, ok)."""
    path = proxy_state_path(ca_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    values: Dict[str, str] = {}
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                saved = json.load(fh).get("values", {})
            if isinstance(saved, dict) and all(name in saved for name, _ in PROXY_KEYS):
                values = {str(k): str(v) for k, v in saved.items()}
        except (OSError, ValueError, AttributeError):
            values = {}
    if not values:
        for name, spec in PROXY_KEYS:
            code, out = _gsettings(spec)
            if code != 0:
                return None, False
            values[name] = out.strip()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"created": time.time(), "values": values}, fh, indent=2)
        except OSError:
            return None, False
    ignore = values.get("ignore_hosts", "[]").strip()
    if ignore.startswith("@as "):
        ignore = ignore[4:].strip()
    try:
        items = ast.literal_eval(ignore)
        if not isinstance(items, list):
            items = []
    except (ValueError, SyntaxError):
        items = []
    for local in ("localhost", "127.0.0.1", "::1"):
        if local not in items:
            items.append(local)
    quoted = "[" + ", ".join("'" + str(x).replace("'", "\\'") + "'" for x in items) + "]"
    sets = [
        ("org.gnome.system.proxy.http host", f"'{host}'"),
        ("org.gnome.system.proxy.http port", str(port)),
        ("org.gnome.system.proxy.https host", f"'{host}'"),
        ("org.gnome.system.proxy.https port", str(port)),
        ("org.gnome.system.proxy ignore-hosts", quoted),
        ("org.gnome.system.proxy mode", "'manual'"),
    ]
    for spec, value in sets:
        code, _ = _gsettings(spec, value)
        if code != 0:
            return path, False
    return path, True


def restore_system_proxy(ca_dir: str, color: Optional[Color] = None,
                         stream: Optional[Any] = None) -> bool:
    out = stream or sys.stdout
    path = proxy_state_path(ca_dir)
    if not os.path.isfile(path):
        msg = "no saved proxy state to restore"
        if color:
            out.write(color.dim("  " + msg) + "\n")
        else:
            out.write("  " + msg + "\n")
        return False
    try:
        with open(path, "r", encoding="utf-8") as fh:
            values = json.load(fh).get("values", {})
    except (OSError, ValueError, AttributeError):
        return False
    if not isinstance(values, dict):
        return False
    ok = True
    # restore mode last, so intermediate host values are not live
    for name, spec in reversed(PROXY_KEYS):
        value = values.get(name)
        if value is None:
            continue
        code, _ = _gsettings(spec, value)
        if code != 0:
            ok = False
    if ok:
        try:
            os.unlink(path)
        except OSError:
            pass
        out.write((color.fg("  system proxy restored", 42) if color else "  system proxy restored") + "\n")
    else:
        sys.stderr.write(f"[{PROG}] could not restore some proxy keys; state kept at {path}\n")
    return ok


# --------------------------------------------------------------------------- #
#  the proxy itself
# --------------------------------------------------------------------------- #

class MitmProxy:
    MAX_HEAD = 131072
    MAX_CONNS = 512

    def __init__(self, cfg: argparse.Namespace, ca: CertAuthority,
                 out: "queue.Queue[Tuple[str, Any]]", proc: ProcMap) -> None:
        self.cfg = cfg
        self.ca = ca
        self.out = out
        self.proc = proc
        self.listen = cfg.mitm_listen or "127.0.0.1"
        self.port = int(cfg.mitm_port) if cfg.mitm_port is not None else 8080
        self.timeout = max(1.0, float(cfg.mitm_timeout))
        self.stop_event = threading.Event()
        self.server: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self._conns: set = set()
        self._conn_lock = threading.Lock()
        self._proc_lock = threading.Lock()
        self._client_cache: Dict[Tuple[str, int], Tuple[float, Optional[int], str]] = {}
        self._ignore = [p.lower() for p in (cfg.mitm_ignore or [])]

    # -- lifecycle --------------------------------------------------------- #
    def start(self) -> None:
        family = socket.AF_INET6 if ":" in self.listen else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        sock.bind((self.listen, self.port))
        self.port = sock.getsockname()[1]
        sock.listen(128)
        sock.settimeout(0.4)
        self.server = sock
        self.thread = threading.Thread(target=self._accept_loop, name="mitm-accept", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.server is not None:
            try:
                self.server.close()
            except OSError:
                pass
        with self._conn_lock:
            conns = list(self._conns)
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=1.0)

    # -- accept / dispatch ------------------------------------------------- #
    def _accept_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, addr = self.server.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            with self._conn_lock:
                too_many = len(self._conns) >= self.MAX_CONNS
                if not too_many:
                    self._conns.add(conn)
            if too_many:
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._handle_safe, args=(conn, addr),
                             name="mitm-conn", daemon=True).start()

    def _handle_safe(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            conn.settimeout(self.timeout)
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self._handle(conn, addr)
        except (ssl.SSLError, _ProtocolError, EOFError, socket.timeout, OSError) as exc:
            if self.cfg.verbose:
                sys.stderr.write(f"[{PROG}] mitm: {type(exc).__name__}: {exc}\n")
        except Exception as exc:                       # a proxy thread must never take the app down
            if self.cfg.verbose:
                sys.stderr.write(f"[{PROG}] mitm: unexpected {type(exc).__name__}: {exc}\n")
        finally:
            with self._conn_lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _handle(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        reader = _Reader(conn)
        head = reader.read_until(b"\r\n\r\n", self.MAX_HEAD)
        if not head.endswith(b"\r\n\r\n"):
            return
        method, target, version, headers = parse_request_head(head)
        client_info = self._client_info(addr)

        if method == "CONNECT":
            host, port = split_host_port(target, 443)
            if not host:
                return
            self._send(conn, b"HTTP/1.1 200 Connection established\r\nProxy-Agent: netlogger\r\n\r\n")
            if self._ignored(host):
                self._tunnel(conn, addr, host, port, client_info, method="CONNECT", scheme="tcp",
                             notes=["pass-through (not decrypted)"])
                return
            try:
                first = conn.recv(1, socket.MSG_PEEK)
            except OSError:
                return
            if not first:
                return
            if first[0] not in (0x16, 0x80):
                self._tunnel(conn, addr, host, port, client_info, method="CONNECT", scheme="tcp",
                             notes=["not TLS — tunneled"])
                return
            try:
                tls = self._wrap_client(conn, host)
            except ssl.SSLError:
                self._emit(method="CONNECT", scheme="tcp", host=host, port=port,
                           path="-", query="", status=0, client_info=client_info,
                           client_addr=addr, bytes_in=0, bytes_out=0, duration=0.0,
                           tls="", alpn="", app="TCP",
                           notes=["TLS handshake failed — certificate pinning?"])
                return
            try:
                self._serve_http(_Reader(tls), tls, addr, client_info, "https", host, port, fixed=True)
            finally:
                try:
                    tls.close()
                except OSError:
                    pass
            return

        scheme, host, path, port = self._request_target(target, headers)
        if not host:
            raise _ProtocolError("no host in request")
        self._serve_http(reader, conn, addr, client_info, scheme, host, port, fixed=False,
                         first=(method, target, version, headers, head))

    def _request_target(self, target: str, headers: Sequence[Tuple[str, str]]) -> Tuple[str, str, str, int]:
        hdrs = header_dict(headers)
        if target.startswith(("http://", "https://")):
            scheme, host, path, port = absolute_target(target)
        else:
            scheme = "http"
            host = hdrs.get("host", "")
            path = target
            port = 80
            if host:
                host, port = split_host_port(host, 80)
        if not host and hdrs.get("host"):
            host, port = split_host_port(hdrs["host"], 80)
        return scheme, host, path, port

    def _serve_http(self, reader: _Reader, sock: Any, client_addr: Tuple[str, int],
                    client_info: Tuple[Optional[int], str],
                    scheme: str, host: str, port: int, *, fixed: bool,
                    first: Optional[Tuple[str, str, str, List[Tuple[str, str]], bytes]] = None) -> None:
        req = first
        for _ in range(10000):
            if req is None:
                head = reader.read_until(b"\r\n\r\n", self.MAX_HEAD)
                if not head.endswith(b"\r\n\r\n"):
                    return
                method, target, version, headers = parse_request_head(head)
                req = (method, target, version, headers, head)
            method, target, version, headers, head = req
            req = None
            if fixed:
                if target.startswith(("http://", "https://")):
                    _sch, host, path, port = absolute_target(target)
                else:
                    path = target
                h, p = host, port
                req_scheme = scheme
            else:
                req_scheme, h, path, p = self._request_target(target, headers)
            keep = self._handle_request(reader, sock, client_addr, client_info, req_scheme, h, p,
                                        method, path, version, headers, head)
            if not keep:
                return

    # -- one HTTP exchange ------------------------------------------------- #
    def _handle_request(self, reader: _Reader, client: Any, client_addr: Tuple[str, int],
                        client_info: Tuple[Optional[int], str],
                        scheme: str, host: str, port: int, method: str, path: str,
                        version: str, headers: List[Tuple[str, str]], head: bytes) -> bool:
        t0 = time.time()
        hdrs = header_dict(headers)
        ws = hdrs.get("upgrade", "").lower() == "websocket"
        app_name = ("WSS" if scheme == "wss" else "WS") if ws else ""
        tls_ver = _socket_tls_version(client) if scheme in ("https", "wss") else ""
        alpn = _socket_alpn(client) if tls_ver else ""
        notes: List[str] = []
        origin = _origin_form(path)
        bytes_out = len(head)
        bytes_in = 0
        status = 0
        server_ip = ""

        if self.cfg.live:
            op, oq = _split_path_query(origin)
            self.out.put(("partial", self._record(
                t0, method, scheme, host, port, op, oq, 0, "", None,
                bytes_in=0, bytes_out=len(head), client_info=client_info,
                client_addr=client_addr, server_ip="", tls=tls_ver, alpn=alpn,
                notes=[], app=app_name,
            )))

        # strip Expect and answer it ourselves, avoiding a 100-continue deadlock
        expect = "100-continue" in hdrs.get("expect", "").lower()
        fwd_headers = [(k, v) for k, v in headers if k.lower() != "expect"] if expect else list(headers)
        fwd_headers = sanitise_headers(fwd_headers)
        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            fwd_headers = [(k, v) for k, v in fwd_headers if k.lower() != "content-length"]
        upstream = None
        try:
            upstream = self._connect_upstream(host, port, scheme in ("https", "wss"))
            server_ip = upstream.getpeername()[0]
            out_head = build_head(f"{method} {origin} {version}", fwd_headers,
                                  host=host, default_port=port)
            upstream.sendall(out_head)
            if expect:
                self._send(client, b"HTTP/1.1 100 Continue\r\n\r\n")
            bytes_out += self._relay_request_body(reader, upstream, header_dict(fwd_headers))

            up_reader = _Reader(upstream)
            reason = ""
            rhdrs: List[Tuple[str, str]] = []
            resp_version = "HTTP/1.1"
            while True:
                resp_head = up_reader.read_until(b"\r\n\r\n", self.MAX_HEAD)
                if not resp_head.endswith(b"\r\n\r\n"):
                    raise _ProtocolError("short response head")
                try:
                    resp_version = resp_head.split(b" ", 1)[0].decode("latin-1")
                except Exception:
                    resp_version = "HTTP/1.1"
                status, reason, rhdrs = parse_response_head(resp_head)
                self._send(client, resp_head)
                bytes_in += len(resp_head)
                if 100 <= status < 200 and status != 101:
                    continue
                break
            resp_hdrs = header_dict(rhdrs)

            if status == 101:
                # bytes that arrived together with the 101 / request head are
                # already buffered in the _Reader objects; do not lose them.
                if reader.buf:
                    early = bytes(reader.buf)
                    reader.buf.clear()
                    self._send(upstream, early)
                    bytes_out += len(early)
                if up_reader.buf:
                    early = bytes(up_reader.buf)
                    up_reader.buf.clear()
                    self._send(client, early)
                    bytes_in += len(early)
                op, oq = _split_path_query(origin)
                self._tunnel_sockets(
                    client, upstream, client_addr=client_addr, client_info=client_info,
                    host=host, port=port,
                    scheme=("wss" if scheme in ("https", "wss") else "ws") if ws else scheme,
                    method=method, app=app_name or "TCP", t0=t0,
                    bytes_in=bytes_in, bytes_out=bytes_out,
                    notes=notes + ["upgraded"], server_ip=server_ip, tls=tls_ver, alpn=alpn,
                    path=op, query=oq, status=status,
                    content_type=resp_hdrs.get("content-type", ""),
                    content_length=_int_or_none(resp_hdrs.get("content-length")),
                )
                try:
                    upstream.close()
                except OSError:
                    pass
                upstream = None
                return False

            eof_delimited = _body_is_eof(status, resp_hdrs, method)
            bytes_in += self._relay_response_body(up_reader, client, method, status, resp_hdrs)
            op, oq = _split_path_query(origin)
            self._emit(
                method=method, scheme=scheme, host=host, port=port, path=op, query=oq,
                status=status, client_info=client_info, client_addr=client_addr,
                bytes_in=bytes_in, bytes_out=bytes_out,
                duration=time.time() - t0, tls=tls_ver, alpn=alpn,
                content_type=resp_hdrs.get("content-type", ""),
                content_length=_int_or_none(resp_hdrs.get("content-length")),
                notes=notes, server_ip=server_ip, app=app_name,
            )

            close = _connection_close(version, hdrs) or _connection_close(resp_version, resp_hdrs)
            if eof_delimited:
                close = True
            return not close
        except (OSError, EOFError, _ProtocolError, ssl.SSLError) as exc:
            notes.append(f"error: {_short_err(exc)}")
            if not status:
                self._reply_error(client, 502, "Bad Gateway")
            op, oq = _split_path_query(origin)
            self._emit(
                method=method, scheme=scheme, host=host, port=port, path=op, query=oq,
                status=status, client_info=client_info, client_addr=client_addr,
                bytes_in=bytes_in, bytes_out=bytes_out,
                duration=time.time() - t0, tls=tls_ver, alpn=alpn,
                notes=notes, server_ip=server_ip, app=app_name,
            )
            return False
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    def _relay_request_body(self, reader: _Reader, upstream: Any, hdrs: Dict[str, str]) -> int:
        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            return _relay_chunked(reader, upstream)
        raw_cl = hdrs.get("content-length")
        if raw_cl is not None:
            n = _int_or_none(raw_cl)
            if n is None or n < 0:
                raise _ProtocolError("bad content-length")
            return _relay_exact(reader, upstream, n) if n else 0
        return 0

    def _relay_response_body(self, reader: _Reader, client: Any, method: str,
                             status: int, hdrs: Dict[str, str]) -> int:
        if method == "HEAD" or status in (204, 205, 304) or 100 <= status < 200:
            return 0
        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            return _relay_chunked(reader, client)
        n = _int_or_none(hdrs.get("content-length"))
        if n is not None:
            if n < 0:
                raise _ProtocolError("bad content-length")
            return _relay_exact(reader, client, n)
        return _relay_to_eof(reader, client)

    # -- tunnels ----------------------------------------------------------- #
    def _tunnel(self, client: Any, client_addr: Tuple[str, int], host: str, port: int,
                client_info: Tuple[Optional[int], str], *, method: str, scheme: str,
                notes: List[str]) -> None:
        t0 = time.time()
        try:
            upstream = self._connect_upstream(host, port, False)
        except OSError as exc:
            self._emit(method=method, scheme=scheme, host=host, port=port,
                       path="-", query="", status=0, client_info=client_info,
                       client_addr=client_addr, bytes_in=0, bytes_out=0, duration=0.0,
                       tls="", alpn="", app="TCP",
                       notes=notes + [f"error: {_short_err(exc)}"])
            return
        try:
            if self.cfg.live:
                self.out.put(("partial", self._record(
                    t0, method, scheme, host, port, "-", "", 0, "", None,
                    bytes_in=0, bytes_out=0, client_info=client_info,
                    client_addr=client_addr, server_ip=upstream.getpeername()[0],
                    tls="", alpn="", notes=notes, app="TCP",
                )))
            self._tunnel_sockets(client, upstream, client_addr=client_addr,
                                 client_info=client_info, host=host, port=port,
                                 scheme=scheme, method=method, app="TCP", t0=t0,
                                 bytes_in=0, bytes_out=0, notes=notes,
                                 server_ip=upstream.getpeername()[0], tls="", alpn="",
                                 path="-", query="", status=0)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _tunnel_sockets(self, client: Any, upstream: Any, *, client_addr: Tuple[str, int],
                        client_info: Tuple[Optional[int], str],
                        host: str, port: int, scheme: str, method: str, app: str, t0: float,
                        bytes_in: int, bytes_out: int, notes: List[str],
                        server_ip: str, tls: str, alpn: str,
                        path: str = "-", query: str = "", status: int = 0,
                        content_type: str = "", content_length: Optional[int] = None) -> None:
        sockets = [client, upstream]
        idle = self.timeout
        try:
            while not self.stop_event.is_set():
                try:
                    ready, _, _ = select.select(sockets, [], [], idle)
                except (OSError, ValueError):
                    break
                if not ready:
                    notes.append("idle timeout")
                    break
                for src in ready:
                    try:
                        data = src.recv(65536)
                    except ssl.SSLWantReadError:
                        continue
                    except OSError:
                        data = b""
                    if not data:
                        return
                    dst = upstream if src is client else client
                    try:
                        dst.sendall(data)
                    except OSError:
                        return
                    if src is client:
                        bytes_out += len(data)
                    else:
                        bytes_in += len(data)
        finally:
            self._emit(method=method, scheme=scheme, host=host, port=port, path=path,
                       query=query, status=status, client_info=client_info,
                       client_addr=client_addr, bytes_in=bytes_in, bytes_out=bytes_out,
                       duration=time.time() - t0, tls=tls, alpn=alpn, notes=notes,
                       server_ip=server_ip, app=app,
                       content_type=content_type, content_length=content_length)

    # -- helpers ----------------------------------------------------------- #
    def _wrap_client(self, conn: socket.socket, host: str) -> ssl.SSLSocket:
        ctx = self.ca.leaf_context(host)

        def _sni(sslobj: Any, server_name: Optional[str], _ctx: Any) -> None:
            if server_name:
                try:
                    sslobj.context = self.ca.leaf_context(server_name)
                except Exception:
                    pass

        ctx.set_servername_callback(_sni)
        return ctx.wrap_socket(conn, server_side=True)

    def _connect_upstream(self, host: str, port: int, tls: bool) -> Any:
        raw = socket.create_connection((host, port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if not tls:
            return raw
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        if self.cfg.mitm_insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            return ctx.wrap_socket(raw, server_hostname=host)
        except Exception:
            try:
                raw.close()
            except OSError:
                pass
            raise

    def _ignored(self, host: str) -> bool:
        if not self._ignore:
            return False
        return Filters._pat_match(host, self._ignore)

    def _send(self, sock: Any, data: bytes) -> None:
        sock.sendall(data)

    def _reply_error(self, client: Any, code: int, text: str) -> None:
        body = f"{code} {text}\n".encode()
        try:
            client.sendall(
                f"HTTP/1.1 {code} {text}\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
            )
        except OSError:
            pass

    def _client_info(self, addr: Tuple[str, int]) -> Tuple[Optional[int], str]:
        ip = norm_ip(addr[0])
        port = int(addr[1])
        key = (ip, port)
        now = time.time()
        hit = self._client_cache.get(key)
        if hit and now - hit[0] < 30.0:
            return hit[1], hit[2]
        found: Optional[Tuple[int, str]] = None
        if self.proc.available:
            with self._proc_lock:
                found = self.proc.lookup_fresh("tcp", ip, port)
        info = found or (None, "")
        if len(self._client_cache) > 2000:
            self._client_cache.clear()
        self._client_cache[key] = (now, info[0], info[1])
        return info

    def _record(self, t0: float, method: str, scheme: str, host: str, port: int,
                path: str, query: str, status: int, content_type: str,
                content_length: Optional[int], *, bytes_in: int, bytes_out: int,
                client_info: Tuple[Optional[int], str], client_addr: Tuple[str, int],
                server_ip: str, tls: str, alpn: str, notes: List[str], app: str = "") -> Record:
        rec = Record(ts=t0)
        rec.method = method
        rec.scheme = scheme
        rec.host = host
        rec.path = path
        rec.query = query
        rec.status = status
        rec.content_type = content_type
        rec.content_length = content_length
        rec.bytes_in = int(bytes_in)
        rec.bytes_out = int(bytes_out)
        rec.duration = max(0.0, time.time() - t0)
        rec.pid, rec.pname = client_info
        if client_addr and client_addr[0]:
            rec.client = str(Endpoint(norm_ip(client_addr[0]), int(client_addr[1])))
        rec.server_ip = server_ip
        if server_ip:
            rec.server = str(Endpoint(norm_ip(server_ip), int(port)))
        rec.server_port = port
        rec.show_port = port not in (80, 443, 53)
        rec.tls = tls
        rec.alpn = alpn
        rec.sni = host if scheme in ("https", "wss") else ""
        rec.notes = list(notes)
        if app:
            rec.app = app
        elif scheme == "https":
            rec.app = "HTTPS"
        else:
            rec.app = "HTTP"
        return rec

    def _emit(self, *, method: str, scheme: str, host: str, port: int, path: str, query: str,
              status: int, client_info: Tuple[Optional[int], str],
              client_addr: Tuple[str, int], bytes_in: int, bytes_out: int,
              duration: float, tls: str, alpn: str, notes: List[str],
              content_type: str = "", content_length: Optional[int] = None,
              server_ip: str = "", app: str = "") -> None:
        rec = self._record(time.time() - max(0.0, duration), method, scheme, host, port,
                           path, query, status, content_type, content_length,
                           bytes_in=bytes_in, bytes_out=bytes_out, client_info=client_info,
                           client_addr=client_addr, server_ip=server_ip,
                           tls=tls, alpn=alpn, notes=notes, app=app)
        rec.duration = max(0.0, duration)
        self.out.put(("rec", rec))


def _socket_tls_version(sock: Any) -> str:
    try:
        v = sock.version() or ""
    except (AttributeError, OSError):
        return ""
    return v.replace("TLSv", "").replace("SSLv", "")


def _socket_alpn(sock: Any) -> str:
    try:
        return sock.selected_alpn_protocol() or ""
    except (AttributeError, OSError):
        return ""


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _connection_close(version: str, hdrs: Dict[str, str]) -> bool:
    conn = hdrs.get("connection", "").lower()
    if "close" in conn:
        return True
    if str(version).upper().startswith("HTTP/1.0") and "keep-alive" not in conn:
        return True
    return False


def _body_is_eof(status: int, hdrs: Dict[str, str], method: str) -> bool:
    if method == "HEAD" or status in (204, 205, 304) or 100 <= status < 200:
        return False
    if "chunked" in hdrs.get("transfer-encoding", "").lower():
        return False
    return _int_or_none(hdrs.get("content-length")) is None


def _short_err(exc: BaseException) -> str:
    text = str(exc).strip().replace("\n", " ")
    if not text:
        text = type(exc).__name__
    return text[:120]


def mitm_env(ca: CertAuthority, port: int, listen: str) -> Dict[str, str]:
    host = listen
    if host in ("0.0.0.0", "", "::"):
        host = "::1" if ":" in listen else "127.0.0.1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    url = f"http://{host}:{port}"
    no_proxy = "localhost,127.0.0.1,::1"
    cert = ca.cert_path
    return {
        "http_proxy": url, "https_proxy": url, "all_proxy": url,
        "HTTP_PROXY": url, "HTTPS_PROXY": url, "ALL_PROXY": url,
        "no_proxy": no_proxy, "NO_PROXY": no_proxy,
        "SSL_CERT_FILE": cert, "CURL_CA_BUNDLE": cert, "REQUESTS_CA_BUNDLE": cert,
        "NODE_EXTRA_CA_CERTS": cert, "GIT_SSL_CAINFO": cert, "PIP_CERT": cert,
    }


def _pump(out: "queue.Queue[Tuple[str, Any]]", emitter: Emitter, stats: Stats,
          cfg: argparse.Namespace, timeout: float = 0.15) -> None:
    deadline = time.time() + timeout
    while True:
        try:
            kind, payload = out.get(timeout=max(0.0, deadline - time.time()))
        except queue.Empty:
            return
        if kind == "rec":
            emitter.emit(payload, False)
        elif kind == "partial":
            emitter.emit(payload, True)
        elif kind == "note":
            if len(stats.errors) < 20:
                stats.errors.append(str(payload))
            if cfg.verbose:
                sys.stderr.write(f"[{PROG}] {payload}\n")


def _child_env(env: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Environment and Popen kwargs that run the child as the invoking user."""
    run_env = os.environ.copy()
    run_env.update(env)
    info = _target_uid_gid()
    if info is None or sys.version_info < (3, 9):
        return run_env, {}
    uid, gid, home = info
    try:
        groups = os.getgrouplist(os.environ.get("SUDO_USER", ""), gid)
    except (OSError, KeyError):
        groups = None
    run_env.update({"HOME": home, "USER": os.environ.get("SUDO_USER", ""),
                    "LOGNAME": os.environ.get("SUDO_USER", "")})
    runtime = f"/run/user/{uid}"
    if os.path.isdir(runtime):
        run_env["XDG_RUNTIME_DIR"] = runtime
        run_env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={runtime}/bus"
    kwargs: Dict[str, Any] = {"user": uid, "group": gid}
    if groups:
        kwargs["extra_groups"] = groups
    return run_env, kwargs


def _run_child(cfg: argparse.Namespace, envinfo: Dict[str, str],
               emitter: Emitter, out: "queue.Queue[Tuple[str, Any]]", stats: Stats,
               stop: Dict[str, bool], deadline: Optional[float]) -> int:
    cmd = [str(x) for x in (cfg.command or [])]
    while cmd and cmd[0] == "--":
        cmd.pop(0)
    if not cmd:
        return 0
    run_env, kwargs = _child_env(envinfo)
    try:
        proc = subprocess.Popen(cmd, env=run_env, **kwargs)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"[{PROG}] cannot run {cmd[0]}: {exc}\n")
        return 2
    code = 0
    stop_reason = ""
    try:
        while proc.poll() is None:
            if stop["stop"]:
                stop_reason = "signal"
                break
            if deadline and time.time() >= deadline:
                stop_reason = "duration"
                emitter.banner("duration reached — stopping the app")
                break
            if cfg.count and stats.records >= cfg.count:
                stop_reason = "count"
                emitter.banner("count reached — stopping the app")
                break
            _pump(out, emitter, stats, cfg, 0.1)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        code = proc.returncode or 0
        if stop_reason == "signal":
            code = 130
        elif stop_reason:
            code = 0
        elif code < 0:
            code = 128 - code
        end = time.time() + 0.4
        while time.time() < end:
            _pump(out, emitter, stats, cfg, 0.1)
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
    return code


def mitm_capture(cfg: argparse.Namespace, color: Color, ca: CertAuthority) -> int:
    stats = Stats()
    emitter = Emitter(cfg, color, stats)
    try:
        ca.ensure()
    except RuntimeError as exc:
        sys.stderr.write(f"[{PROG}] error: {exc}\n")
        return 2

    command = [str(x) for x in (cfg.command or [])]
    while command and command[0] == "--":
        command.pop(0)
    use_system = bool(cfg.mitm_system) or ((not cfg.no_system_proxy) and not command)
    auto_ca = (not cfg.no_ca_install) and not command
    ca_installed_here = False
    already_trusted = ca_trusted_anywhere(ca) if auto_ca else False
    if auto_ca and not already_trusted:
        rc = install_ca(ca, color, stream=sys.stderr)
        ca_installed_here = ca_trusted_anywhere(ca)
        if not ca_installed_here:
            sys.stderr.write(
                f"[{PROG}] could not trust the CA automatically (rc {rc}); "
                f"apps may refuse HTTPS\n")

    out: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
    proc = ProcMap()
    proxy = MitmProxy(cfg, ca, out, proc)
    try:
        proxy.start()
    except OSError as exc:
        sys.stderr.write(f"[{PROG}] cannot listen on {cfg.mitm_listen}:{cfg.mitm_port}: {exc}\n")
        return 2

    state = {"stop": False}
    restored = {"done": False}
    saved_state: Optional[str] = None

    def cleanup() -> None:
        if restored["done"]:
            return
        restored["done"] = True
        proxy.stop()
        if saved_state:
            restore_system_proxy(ca.dir, color, stream=sys.stderr)
        if ca_installed_here:
            install_ca(ca, color, remove=True, stream=sys.stderr)

    def on_signal(_signum: int, _frame: Any) -> None:
        if state["stop"]:
            cleanup()
            os._exit(130)
        state["stop"] = True
        emitter.banner("stopping…")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    env = mitm_env(ca, proxy.port, proxy.listen)
    if use_system:
        proxy_host = {"0.0.0.0": "127.0.0.1", "::": "::1", "": "127.0.0.1"}.get(
            proxy.listen, proxy.listen)
        saved_state, system_ok = set_system_proxy(ca.dir, proxy_host, proxy.port)
        if system_ok:
            emitter.banner("system proxy switched to manual — restored on exit")
        else:
            emitter.banner("could not change the GNOME proxy; use the env below")

    if not cfg.quiet:
        emitter.banner(f"MITM proxy on {env['https_proxy']} · CA {ca.cert_path}")
        emitter.banner("TLS is terminated locally · full paths are logged")
        if auto_ca and ca_installed_here:
            emitter.banner("CA trusted system-wide — removed again when netlogger exits")
        emitter.banner("this shell:  export " +
                       " ".join(f"{k}={shlex.quote(v)}" for k, v in
                                ((k, env[k]) for k in ("HTTPS_PROXY", "HTTP_PROXY", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"))))
        if use_system:
            emitter.banner(f"if this process is killed hard: {PROG} --mitm-restore")
        if cfg.mitm_insecure:
            emitter.banner("warning: upstream TLS certificates are NOT verified (--mitm-insecure)")
        if proxy.listen in ("0.0.0.0", "::"):
            emitter.banner("warning: listening on every interface — anyone who can reach this port can use it")
        if cfg.pcap:
            emitter.banner("--pcap is ignored in MITM mode (no raw packets are captured)")
        emitter.banner("the CA private key is sensitive; undo trust with: " + f"{PROG} --mitm-ca-remove")
        emitter.banner("certificate pinning will make some apps refuse the connection")
        if not command and not ca_installed_here and not already_trusted:
            emitter.banner(f"to trust the CA for other apps: {PROG} --mitm-ca-install")
        if not command:
            emitter.banner("press Ctrl-C to stop")

    deadline = time.time() + cfg.duration if cfg.duration > 0 else None
    last_stats = time.time()
    exit_code = 0
    try:
        if command:
            emitter.banner("running: " + " ".join(command))
            exit_code = _run_child(cfg, env, emitter, out, stats, state, deadline)
        else:
            while not state["stop"]:
                _pump(out, emitter, stats, cfg, 0.15)
                if deadline and time.time() >= deadline:
                    break
                if cfg.count and stats.records >= cfg.count:
                    break
                if cfg.stats_interval > 0 and time.time() - last_stats >= cfg.stats_interval:
                    last_stats = time.time()
                    sys.stderr.write(
                        f"[{PROG}] {stats.records} fetches · ↓ {human_bytes(stats.bytes_in, cfg.binary)}"
                        f" ↑ {human_bytes(stats.bytes_out, cfg.binary)} · port {proxy.port}\n"
                    )
                    sys.stderr.flush()
    finally:
        cleanup()
        _pump(out, emitter, stats, cfg, 0.3)
        if not cfg.quiet and not cfg.no_summary:
            dest = sys.stderr if cfg.format in ("json", "csv") else sys.stdout
            dest.write(stats.summary(color, cfg.binary, emitter.width()) + "\n")
            dest.flush()
    return exit_code


def demo(args: argparse.Namespace, color: Color) -> int:
    """Offline preview; needs no root and no traffic."""
    stats = Stats()
    emit_args = argparse.Namespace(**vars(args))
    emit_args.out = None
    emit_args.quiet = False
    if emit_args.format in ("json", "csv"):
        emit_args.format = "pretty"
    emitter = Emitter(emit_args, color, stats)
    now = time.time()
    c = color
    emitter.banner("demo mode — synthetic traffic, nothing is captured")

    rows = [
        dict(badge="GET", host="download.example.com", path="/package1.zip", query="",
             app="HTTP", bytes_in=12_612_400, bytes_out=1_240, duration=1.9, pname="curl", pid=2381,
             client="192.168.1.24:52310", server="93.184.216.34:80", status=200, tls="", alpn="", scheme="http"),
        dict(badge="HTTPS", host="registry.npmjs.org", path="/lodash/-/lodash-4.17.21.tgz", query="",
             app="H2", bytes_in=1_402_000, bytes_out=3_100, duration=0.61, pname="node(npm)", pid=9124,
             client="192.168.1.24:52344", server="104.16.25.34:443", status=0, tls="1.3", alpn="h2", scheme="https"),
        dict(badge="POST", host="api.github.com", path="/repos/octocat/hello/issues",
             query="", app="H2", bytes_in=820, bytes_out=4_512, duration=0.22, pname="git", pid=7781,
             client="192.168.1.24:52390", server="140.82.121.6:443", status=201, tls="1.3", alpn="h2", scheme="https"),
        dict(badge="WS", host="stream.example.com", path="/live/feed", query="channel=7",
             app="WS", bytes_in=284_100, bytes_out=12_400, duration=12.4, pname="firefox", pid=3311,
             client="192.168.1.24:52410", server="203.0.113.9:80", status=101, tls="", alpn="", scheme="ws"),
        dict(badge="GET", host="cdn.jsdelivr.net", path="/npm/chart.js@4.4.0/dist/chart.umd.js",
             query="", app="H2", bytes_in=208_400, bytes_out=940, duration=0.18, pname="firefox", pid=3311,
             client="192.168.1.24:52466", server="151.101.1.229:443", status=200, tls="1.3", alpn="h2", scheme="https"),
        dict(badge="QUIC", host="www.youtube.com", path="", query="", app="QUIC",
             bytes_in=48_220_000, bytes_out=704_000, duration=22.8, pname="chrome", pid=5510,
             client="192.168.1.24:52500", server="142.250.185.78:443", status=0, tls="1.3", alpn="h3", scheme="quic"),
        dict(badge="GET", host="archive.ubuntu.com", path="/ubuntu/dists/noble/InRelease", query="",
             app="HTTP", bytes_in=284_900, bytes_out=420, duration=0.94, pname="apt", pid=12987,
             client="192.168.1.24:52610", server="91.189.91.82:80", status=200, tls="", alpn="", scheme="http"),
        dict(badge="DNS", host="download.example.com", path="", query="", app="DNS",
             bytes_in=96, bytes_out=64, duration=0.03, pname="curl", pid=2381,
             client="192.168.1.24:38212", server="192.168.1.1:53", status=0, tls="", alpn="",
             scheme="dns", notes=["93.184.216.34"], service="DNS"),
        dict(badge="SSH", host="git.internal", path="", query="", app="", service="SSH",
             bytes_in=1_820_000, bytes_out=88_200, duration=9.6, pname="ssh", pid=4412,
             client="192.168.1.24:52744", server="10.0.0.5:22", status=0, tls="", alpn="", scheme=""),
    ]
    for i, row in enumerate(rows):
        rec = Record(ts=now + i * 0.7)
        rec.method = row["badge"] if row["badge"] in HTTP_METHODS | {"WS", "WSS"} else ""
        rec.host = row["host"]
        rec.path = row["path"]
        rec.query = row["query"]
        rec.app = row["app"]
        rec.scheme = row["scheme"]
        rec.bytes_in = row["bytes_in"]
        rec.bytes_out = row["bytes_out"]
        rec.duration = row["duration"]
        rec.pname = row["pname"]
        rec.pid = row["pid"]
        rec.client = row["client"]
        rec.server = row["server"]
        rec.server_ip = row["server"].split(":")[0]
        try:
            rec.server_port = int(row["server"].rsplit(":", 1)[1])
        except ValueError:
            rec.server_port = 0
        rec.status = row.get("status", 0)
        rec.tls = row.get("tls", "")
        rec.alpn = row.get("alpn", "")
        rec.service = row.get("service", "")
        rec.notes = list(row.get("notes", []))
        rec.show_port = rec.server_port not in (80, 443, 53)
        emitter.emit(rec)
        time.sleep(0.12)
    sys.stdout.write(stats.summary(color, args.binary, emitter.width()) + "\n")
    return 0


def selftest(verbose: bool = False) -> int:
    """Parser sanity checks that need no privileges."""
    failures: List[str] = []
    checks = 0

    # human_bytes
    checks += 1
    if human_bytes(0) != "0 B" or human_bytes(12612400) != "12.6 MB" or human_bytes(1536) != "1.54 KB":
        failures.append(f"human_bytes: {human_bytes(12612400)} / {human_bytes(1536)}")

    # size parsing
    checks += 1
    try:
        if parse_size("1M") != 1_000_000 or parse_size("2KiB") != 2000 or parse_size("512") != 512:
            failures.append("parse_size")
    except ValueError as exc:
        failures.append(f"parse_size raised {exc}")

    # HTTP request
    req = (b"GET /package1.zip?x=1 HTTP/1.1\r\nHost: download.example.com\r\n"
           b"User-Agent: curl/8.5.0\r\n\r\n")
    checks += 1
    info = parse_http_request(req)
    if not info or info["method"] != "GET" or info["host"] != "download.example.com" \
            or info["path"] != "/package1.zip" or info["query"] != "x=1":
        failures.append(f"parse_http_request -> {info}")

    # WebSocket upgrade
    checks += 1
    ws = (b"GET /live/feed HTTP/1.1\r\nHost: stream.example.com\r\nUpgrade: websocket\r\n"
          b"Connection: Upgrade\r\n\r\n")
    info = parse_http_request(ws)
    if not info or info["app"] != "WS":
        failures.append(f"websocket sniff -> {info}")

    # absolute-form (proxy) request
    checks += 1
    info = parse_http_request(b"GET http://cdn.example.com/a/b.js HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n")
    if not info or info["host"] != "cdn.example.com" or info["path"] != "/a/b.js":
        failures.append(f"proxy form -> {info}")

    # HTTP response
    checks += 1
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 12612400\r\nContent-Type: application/zip\r\nServer: nginx\r\n\r\n"
    info = parse_http_response(resp)
    if not info or info["status"] != 200 or info["content_length"] != 12612400:
        failures.append(f"parse_http_response -> {info}")

    # TLS ClientHello with SNI + ALPN
    checks += 1
    sni = b"download.example.com"
    ext_sni = b"\x00\x00" + struct.pack("!H", len(sni) + 5) + struct.pack("!H", len(sni) + 3) + b"\x00" + struct.pack("!H", len(sni)) + sni
    alpn_data = b"\x02h2"
    ext_alpn = b"\x00\x10" + struct.pack("!H", len(alpn_data) + 2) + struct.pack("!H", len(alpn_data)) + alpn_data
    ext_ver = b"\x00\x2b\x00\x03\x02\x03\x04"
    exts = ext_sni + ext_alpn + ext_ver
    hs = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + \
         struct.pack("!H", len(exts)) + exts
    ch = b"\x01" + len(hs).to_bytes(3, "big") + hs
    rec_bytes = b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch
    info = parse_tls_client_hello(rec_bytes)
    if not info or info["sni"] != "download.example.com" or "h2" not in info["alpn"] or info["version"] != "1.3":
        failures.append(f"parse_tls_client_hello -> {info}")

    # DNS query + response
    checks += 1
    qname = b"\x08download\x07example\x03com\x00"
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    info = parse_dns(q)
    if not info or info["name"] != "download.example.com" or info["response"]:
        failures.append(f"parse_dns query -> {info}")
    checks += 1
    ans = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + qname + struct.pack("!HH", 1, 1) + \
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    info = parse_dns(ans)
    if not info or not info["response"] or info["answers"] != ["93.184.216.34"]:
        failures.append(f"parse_dns response -> {info}")

    # packet parsing: build a full ethernet frame
    def frame(payload: bytes, sport: int, dport: int, src="10.0.0.2", dst="93.184.216.34") -> bytes:
        tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 8192, 0, 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                         socket.inet_aton(src), socket.inet_aton(dst)) + tcp
        eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", ETH_P_IP)
        return eth + ip

    checks += 1
    parsed = parse_ipv4(frame(b"x", 1, 2), 14)
    if not parsed or parsed[1] != "10.0.0.2" or parsed[3] != 6:
        failures.append(f"parse_ipv4 -> {parsed}")

    checks += 1
    seg = parse_tcp(parsed[4]) if parsed else None
    if not seg or seg[0] != 1 or seg[1] != 2 or seg[5] != b"x":
        failures.append(f"parse_tcp -> {seg}")

    # HPACK static shortcut
    checks += 1
    if parse_h2_method(b"\x82") != "GET":
        failures.append("parse_h2_method GET")
    checks += 1
    if parse_h2_method(b"\x83") != "POST":
        failures.append("parse_h2_method POST")

    # _hex_ip
    checks += 1
    if _hex_ip("0100007F") != "127.0.0.1":
        failures.append(f"_hex_ip v4 -> {_hex_ip('0100007F')}")

    # end to end through the Engine (no sockets involved)
    checks += 1
    records: List[Record] = []

    def collect(rec: Record, partial: bool) -> None:
        if not partial:
            records.append(rec)

    cfg = argparse.Namespace(idle=0.1, live=False, dns=True, all=False, domain_only=False)
    engine = Engine(cfg, collect, proc=ProcMap(ttl=999))
    link = Link("test", None, ARPHRD_ETHER, "eth")
    engine.process_frame(frame(req, 52310, 80), 1000.0, link)
    engine.process_frame(frame(resp + b"Z" * 100, 80, 52310, src="93.184.216.34", dst="10.0.0.2"), 1000.1, link)
    engine.process_frame(frame(b"", 52310, 80), 1000.2, link)
    engine.finish(1010.0)
    if not records:
        failures.append("engine: no record emitted")
    else:
        r = records[0]
        if r.method != "GET" or r.host != "download.example.com" or r.path != "/package1.zip":
            failures.append(f"engine record -> {r.method} {r.host}{r.path}")
        if r.status != 200 or r.bytes_out != len(req) or r.bytes_in < 100:
            failures.append(f"engine sizes -> status={r.status} out={r.bytes_out} in={r.bytes_in}")

    # tracker direction + websocket over a vlan-tagged frame
    checks += 1
    records2: List[Record] = []
    engine2 = Engine(cfg, lambda rec, partial: records2.append(rec), proc=ProcMap(ttl=999))
    vlan = bytearray(frame(ws, 4444, 80))
    vtag = bytearray(b"\xaa" * 12 + struct.pack("!HH", 0x8100, 5) + struct.pack("!H", ETH_P_IP))
    engine2.process_frame(bytes(vtag) + bytes(vlan[14:]), 2000.0, Link("test", None, 1, "eth"))
    engine2.finish(2010.0)
    if not records2 or records2[0].badge() != "WS" or records2[0].bytes_out != len(ws):
        failures.append(f"vlan/ws record -> {[ (r.badge(), r.bytes_out) for r in records2 ]}")

    # filters
    checks += 1
    ns = argparse.Namespace(host=["*.zip"], exclude_host=None, app=None, exclude_app=None, pid=None,
                            method=["GET"], port=None, min_size=0, max_size=None)
    filt = Filters(ns)
    ok, why = filt.match(Record(ts=time.time(), host="download.example.com", path="/package1.zip",
                                method="GET", bytes_in=10))
    if not ok:
        failures.append(f"filter should match ({why})")
    ok, _ = filt.match(Record(ts=time.time(), host="download.example.com", path="/a.txt", method="GET"))
    if ok:
        failures.append("filter should not match")
    checks += 1
    ns2 = argparse.Namespace(host=None, exclude_host=["ads.*"], app=None, exclude_app=None, pid=None,
                             method=None, port=None, min_size=2048, max_size=None)
    if Filters(ns2).match(Record(ts=time.time(), host="cdn.ads.example", bytes_in=10))[0]:
        failures.append("exclude-host should reject")
    if Filters(ns2).match(Record(ts=time.time(), host="good.example", bytes_in=100))[0]:
        failures.append("min-size should reject")

    # record formatting
    checks += 1
    colors = Color(True)
    emitter = Emitter(argparse.Namespace(format="pretty", binary=False, width=110, out=None, quiet=True,
                                         log=None, host=None, exclude_host=None, app=None, exclude_app=None,
                                         pid=None, method=None, port=None, min_size=0, max_size=None,
                                         full_url=False, peer=False, watch=None),
                      colors, Stats())
    rec = Record(ts=time.time(), method="GET", host="download.example.com", path="/package1.zip",
                 app="HTTP", bytes_in=12_612_400, bytes_out=1_240, duration=1.9, pname="curl", pid=2381,
                 server="93.184.216.34:80", server_ip="93.184.216.34", server_port=80, status=200)
    line = emitter.format_line(rec)
    if "download.example.com/package1.zip" not in ANSI_RE.sub("", line) or "12.6 MB" not in ANSI_RE.sub("", line):
        failures.append(f"format_line -> {ANSI_RE.sub('', line)!r}")
    checks += 1
    if vlen(line) > 132:
        failures.append(f"format_line too long: {vlen(line)}")

    # truncation keeps the tail
    checks += 1
    t = truncate_tail("/very/long/path/to/some/file-name-here.zip", 30)
    if len(t) != 30 or not t.endswith("zip"):
        failures.append(f"truncate_tail -> {t!r}")

    # proc map reads something sane
    checks += 1
    pm = ProcMap(ttl=0)
    pm.refresh(time.time(), force=True)
    if pm.available and not isinstance(pm._sockets, dict):
        failures.append("ProcMap._sockets")

    # MITM helpers
    checks += 1
    if split_host_port("example.com:8443") != ("example.com", 8443) or \
            split_host_port("[::1]:9443") != ("::1", 9443) or \
            split_host_port("example.com:bad", 80) != ("example.com", 80):
        failures.append("split_host_port")
    checks += 1
    if absolute_target("https://example.com/a/b?x=1") != ("https", "example.com", "/a/b?x=1", 443):
        failures.append(f"absolute_target -> {absolute_target('https://example.com/a/b?x=1')}")
    checks += 1
    _m, _t, _v, _h = parse_request_head(
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n")
    if (_m, _t, header_dict(_h).get("host")) != ("POST", "/x", "h"):
        failures.append("parse_request_head (proxy)")
    checks += 1
    if _body_is_eof(200, {}, "GET") is not True or \
            _body_is_eof(200, {"content-length": "2"}, "GET") is not False or \
            _body_is_eof(204, {}, "GET") is not False:
        failures.append("_body_is_eof")

    total = checks + len(failures)
    if failures:
        print(f"selftest: {checks} passed, {len(failures)} FAILED")
        for f in failures:
            print("  ✗ " + f)
        return 1
    print(f"selftest: all {checks} checks passed")
    if verbose:
        print(f"  python {sys.version.split()[0]} · {socket.gethostname()}")
    return 0


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def color_mode_enabled(mode: str) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("CLICOLOR_FORCE"):
        return True
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{PROG} {__version__} — full URLs for every fetch: a local MITM "
                    f"proxy by default, raw packet capture with --capture.",
        epilog="""\
examples:
  sudo netlogger.py                          full-path proxy for everything (default)
  netlogger.py -- curl https://x/y           proxy just this one command
  sudo netlogger.py --no-ca-install          proxy without touching the trust stores
  sudo netlogger.py --no-system-proxy        proxy only, leave GNOME's proxy alone
  netlogger.py --mitm-ca-show                show the CA path + fingerprint

  sudo netlogger.py --capture                raw packet capture (the old default)
  sudo netlogger.py --capture -i wlan0 -l    one interface, live "starting" lines
  sudo netlogger.py --capture --host '*.zip' --app curl
  sudo netlogger.py --capture -f json | jq . machine readable
  sudo netlogger.py --capture --pcap dump.pcap   also save the raw frames
  netlogger.py --demo                        preview without root
  netlogger.py --selftest                    check the parsers

badges:
  GET/POST/PUT/…  HTTP method (full path in the default proxy mode)
  WS / WSS        websocket
  HTTPS           TLS session, host from SNI (path is encrypted)
  H2 / H3 / QUIC  HTTP/2 or HTTP/3
  CONN            a raw tunnel (CONNECT / SSH / ignored pinned host)
  DNS             name lookup (capture mode with --dns)
  SSH/SMB/…       guessed from the port, shown for big enough flows

modes:
  Default (MITM proxy): netlogger terminates TLS locally with its own CA, so you
  get the full URL, method, status and sizes. It trusts the CA for the run and
  points GNOME's proxy at itself, then undoes both on exit. Apps that pin
  certificates refuse the connection (use --mitm-ignore for those).

  --capture: the raw AF_PACKET sniffer (needs root or CAP_NET_RAW). Without a
  proxy, HTTPS paths cannot be seen — TLS hides them — but you get every
  interface, DNS and QUIC traffic that never goes through the proxy.

notes:
  · traffic numbers count application payload (what the app sent/received),
    HTTP headers are included, IP/TCP framing is not.
  · virtual bridge interfaces are skipped by default so packets seen on both
    eth0 and docker0 are not counted twice.
""")
    p.add_argument("-i", "--interface", action="append", metavar="IFACE",
                   help="capture only this interface (repeatable)")
    p.add_argument("--all-ifaces", action="store_true",
                   help="include virtual/bridge/tunnel interfaces too")
    p.add_argument("--no-loopback", action="store_true", help="skip the lo interface")
    p.add_argument("--promisc", action="store_true",
                   help="put interfaces in promiscuous mode (sees other hosts)")
    p.add_argument("-n", "--count", type=int, default=0, metavar="N",
                   help="stop after N fetches")
    p.add_argument("-d", "--duration", type=float, default=0.0, metavar="SECS",
                   help="stop after SECS seconds")
    p.add_argument("--idle", type=float, default=8.0, metavar="SECS",
                   help="close a flow after SECS without packets (default 8)")
    p.add_argument("--snaplen", type=int, default=262144, metavar="BYTES",
                   help="max bytes captured per frame (default 262144)")
    p.add_argument("--force-hwtype", action="store_true",
                   help="also try interfaces with unusual link types")

    g = p.add_argument_group("what to show")
    g.add_argument("--all", action="store_true",
                   help="also report non-fetch traffic (needs min-size or --all)")
    g.add_argument("--dns", action="store_true", help="report DNS lookups too")
    g.add_argument("--host", action="append", metavar="PATTERN",
                   help="only hosts matching PATTERN (glob or substring, repeatable)")
    g.add_argument("--exclude-host", action="append", metavar="PATTERN",
                   help="drop hosts matching PATTERN")
    g.add_argument("--app", action="append", metavar="NAME",
                   help="only processes whose name matches NAME")
    g.add_argument("--exclude-app", action="append", metavar="NAME",
                   help="drop processes whose name matches NAME")
    g.add_argument("--pid", action="append", type=int, metavar="PID",
                   help="only this process id (repeatable)")
    g.add_argument("--method", action="append", default=None, metavar="LIST",
                   help="only these badges, e.g. GET,POST,WS")
    g.add_argument("--port", action="append", type=int, metavar="PORT",
                   help="only flows touching this port (repeatable)")
    g.add_argument("--min-size", type=parse_size, default=0, metavar="SIZE",
                   help="only fetches with at least SIZE traffic (e.g. 1M)")
    g.add_argument("--max-size", type=parse_size, default=None, metavar="SIZE",
                   help="only fetches with at most SIZE traffic")
    g.add_argument("-w", "--watch", action="append", metavar="PATTERN",
                   help="highlight lines whose app or host matches PATTERN")

    g = p.add_argument_group("output")
    g.add_argument("-f", "--format", choices=["pretty", "plain", "json", "csv"], default="pretty",
                   help="output format (default pretty)")
    g.add_argument("-o", "--out", metavar="FILE", help="write records to FILE instead of stdout")
    g.add_argument("--log", metavar="FILE", help="also append plain lines to FILE")
    g.add_argument("-l", "--live", action="store_true",
                   help="print a line when a fetch starts, and the final size when it ends")
    g.add_argument("-q", "--quiet", action="store_true", help="no banner, no summary")
    g.add_argument("--no-summary", action="store_true", help="no summary on exit")
    g.add_argument("--peer", action="store_true", help="show remote ip:port on every line")
    g.add_argument("--full-url", action="store_true", help="never truncate URLs")
    g.add_argument("--width", type=int, default=0, help="output width override")
    g.add_argument("--binary", action="store_true", help="use KiB/MiB/GiB (1024 based)")
    g.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    g.add_argument("--no-color", action="store_true", help="alias for --color never")
    g.add_argument("--stats-interval", type=float, default=0.0, metavar="SECS",
                   help="print a one line running total to stderr every SECS")
    g.add_argument("--pcap", metavar="FILE", help="also write raw frames to a pcap file")

    g = p.add_argument_group("modes and MITM proxy — full URLs for HTTPS")
    g.add_argument("--capture", action="store_true",
                   help="use the raw AF_PACKET sniffer (the pre-1.2 default) instead of the proxy")
    g.add_argument("--mitm", action="store_true",
                   help="run the local TLS-terminating proxy (this is the default mode)")
    g.add_argument("--mitm-port", type=int, default=8080, metavar="PORT",
                   help="proxy port (default 8080; 0 = pick a free one)")
    g.add_argument("--mitm-listen", default="127.0.0.1", metavar="ADDR",
                   help="proxy listen address (default 127.0.0.1)")
    g.add_argument("--mitm-system", action="store_true", default=None,
                   help="point GNOME's system proxy at it (default: on when no command is given)")
    g.add_argument("--no-system-proxy", action="store_true",
                   help="do not touch GNOME's system proxy automatically")
    g.add_argument("--no-ca-install", action="store_true",
                   help="do not auto-install/remove the CA in the system and browser stores")
    g.add_argument("--mitm-restore", action="store_true",
                   help="restore the system proxy saved by --mitm-system, then exit")
    g.add_argument("--mitm-ca-install", action="store_true",
                   help="trust the generated CA system-wide and in Firefox/Chrome")
    g.add_argument("--mitm-ca-remove", action="store_true",
                   help="remove the generated CA from system and browser stores")
    g.add_argument("--mitm-ca-show", action="store_true",
                   help="show the CA certificate path and SHA-256 fingerprint")
    g.add_argument("--mitm-ca-reset", action="store_true",
                   help="delete the generated CA and cached leaf certificates")
    g.add_argument("--mitm-ca-dir", metavar="DIR", default="",
                   help="CA directory (default ~/.config/netlogger/mitm)")
    g.add_argument("--mitm-insecure", action="store_true",
                   help="do not verify upstream TLS certificates (testing only)")
    g.add_argument("--mitm-ignore", action="append", metavar="PATTERN",
                   help="pass hosts matching PATTERN through untouched (certificate pinning)")
    g.add_argument("--mitm-timeout", type=float, default=60.0, metavar="SECS",
                   help="idle timeout for proxy connections (default 60)")

    g = p.add_argument_group("misc")
    g.add_argument("--list-interfaces", action="store_true", help="show interfaces and exit")
    g.add_argument("--demo", action="store_true", help="synthetic colourful demo, no root needed")
    g.add_argument("--selftest", action="store_true", help="run offline parser checks and exit")
    g.add_argument("-v", "--verbose", action="store_true", help="more chatter on stderr")
    g.add_argument("-V", "--version", action="version", version=f"{PROG} {__version__}")
    p.add_argument("command", nargs=argparse.REMAINDER, metavar="-- CMD",
                   help="run CMD with the proxy environment and CA exported (MITM mode only)")
    return p


def fix_method_arg(args: argparse.Namespace) -> None:
    """--method GET,POST as well as --method GET --method POST."""
    if not args.method:
        args.method = None
        return
    out: List[str] = []
    for item in args.method:
        out.extend(part.strip() for part in str(item).split(",") if part.strip())
    args.method = [m.upper() for m in out] or None


def cmd_list_interfaces(color: Color) -> int:
    rows = Sniffer.interfaces()
    print(f"{'iface':<16} {'link':>6}  {'state':<8} capture")
    for name, hwtype, state in rows:
        kind = SUPPORTED_LINK_TYPES.get(hwtype)
        if name == "lo":
            note = "yes (loopback)"
            ok = True
        elif is_virtual_iface(name):
            note = "skipped (virtual) — use --all-ifaces"
            ok = False
        elif kind:
            note = "yes"
            ok = True
        else:
            note = f"skipped (link type {hwtype})"
            ok = False
        name_s = color.fg(f"{name:<16}", 51) if ok else color.dim(f"{name:<16}")
        note_s = color.fg(note, 42) if ok else color.dim(note)
        state_s = state if state == "up" else color.dim(f"{state:<8}")
        print(f"{name_s} {hwtype:>6}  {state_s:<8} {note_s}")
    return 0


def print_sudo_hint() -> None:
    sys.stderr.write(
        "\n"
        "  Permission denied opening the capture socket.\n"
        "  netlogger needs raw packet access. Options:\n"
        "\n"
        f"      sudo {sys.argv[0]} ...              run it as root (simplest)\n"
        f"      sudo -E {sys.argv[0]} ...           keep NO_COLOR / SSLKEYLOGFILE etc.\n"
        "\n"
        "  (setcap on a script does not work — the kernel applies capabilities to\n"
        "   the interpreter, not the script. Running as root is the clean way.)\n"
        "\n"
        f"  No root right now?  {sys.argv[0]} --demo   shows what the output looks like.\n"
        "\n"
    )


def capture(cfg: argparse.Namespace, color: Color) -> int:
    stats = Stats()
    emitter = Emitter(cfg, color, stats)
    state = {"stop": False}

    def on_signal(_signum: int, _frame: Any) -> None:
        if state["stop"]:                              # second Ctrl-C: get out now
            os._exit(130)
        state["stop"] = True
        emitter.banner("stopping…")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    pcap = PcapWriter(cfg.pcap, snaplen=cfg.snaplen) if cfg.pcap else None

    def on_error(msg: str) -> None:
        if len(stats.errors) < 20:
            stats.errors.append(msg)
        if cfg.verbose:
            sys.stderr.write(f"[{PROG}] {msg}\n")

    engine = Engine(cfg, emitter.emit, pcap=pcap, on_error=on_error)
    sniffer = Sniffer(cfg, engine, emitter.banner)
    try:
        sniffer.open()
    except PermissionError:
        if pcap:
            pcap.close()
        print_sudo_hint()
        return 2
    except RuntimeError as exc:
        sys.stderr.write(f"[{PROG}] error: {exc}\n")
        if cfg.verbose:
            sys.stderr.write(f"[{PROG}] available interfaces:\n")
            for name, hwtype, st in Sniffer.interfaces():
                sys.stderr.write(f"    {name} (link {hwtype}, {st})\n")
        if pcap:
            pcap.close()
        return 2

    if not cfg.quiet:
        pieces = [f"version {__version__}", "interfaces " + ", ".join(sniffer.names())]
        if engine.proc.available:
            pieces.append("process attribution on")
        else:
            pieces.append("no /proc — process names unavailable")
        if cfg.dns:
            pieces.append("dns shown")
        if cfg.pcap:
            pieces.append(f"pcap → {cfg.pcap}")
        emitter.banner(" · ".join(pieces))
        if sniffer.skipped and cfg.verbose:
            emitter.banner("skipped: " + ", ".join(sniffer.skipped))
        emitter.banner("press Ctrl-C to stop")

    deadline = time.time() + cfg.duration if cfg.duration > 0 else None
    last_stats = time.time()
    next_flush = time.time()
    try:
        while not state["stop"]:
            timeout = 0.2
            if next_flush - time.time() <= 0:
                engine.tick()
                next_flush = time.time() + 0.25
                timeout = 0.05
            try:
                ready, _, _ = select.select([lnk.sock for lnk in sniffer.links], [], [], timeout)
            except InterruptedError:
                continue
            except OSError:
                break
            if state["stop"]:
                break
            ts = time.time()
            for sock in ready:
                for lnk in sniffer.links:
                    if lnk.sock is sock:
                        sniffer.drain(lnk, ts)
                        break
            if deadline and time.time() >= deadline:
                break
            if cfg.count and stats.records >= cfg.count:
                break
            if cfg.stats_interval > 0 and time.time() - last_stats >= cfg.stats_interval:
                last_stats = time.time()
                sys.stderr.write(
                    f"[{PROG}] {stats.records} fetches · ↓ {human_bytes(stats.bytes_in, cfg.binary)}"
                    f" ↑ {human_bytes(stats.bytes_out, cfg.binary)}"
                    f" · {len(engine.tracker.flows)} open\n"
                )
                sys.stderr.flush()
    finally:
        engine.finish()
        sniffer.close()
        if pcap:
            pcap.close()
        if not cfg.quiet and not cfg.no_summary:
            dest = sys.stderr if cfg.format in ("json", "csv") else sys.stdout
            dest.write(stats.summary(color, cfg.binary, emitter.width()) + "\n")
            dest.flush()
    return 0


def _capture_flags_used(args: argparse.Namespace) -> bool:
    """True when options that only affect the packet sniffer were given."""
    return bool(
        args.interface or args.all_ifaces or args.no_loopback or args.promisc
        or args.force_hwtype or args.dns or args.all or args.pcap
        or args.snaplen != 262144 or args.idle != 8.0
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fix_method_arg(args)
    if args.no_color:
        args.color = "never"
    color = Color(color_mode_enabled(args.color))

    if args.selftest:
        return selftest(verbose=args.verbose)
    if args.list_interfaces:
        return cmd_list_interfaces(color)
    if args.demo:
        return demo(args, color)

    ca = CertAuthority(args.mitm_ca_dir or mitm_default_dir())

    if args.mitm_restore:
        ok = restore_system_proxy(ca.dir, color)
        # nothing to restore is not an error; a state file we could not apply is
        return 0 if ok or not os.path.exists(proxy_state_path(ca.dir)) else 2

    # MITM is the default mode; --capture brings back the raw packet sniffer.
    # Passing capture-only flags without a mode also selects --capture.
    capture_mode = bool(args.capture)
    if not capture_mode and not args.mitm and _capture_flags_used(args):
        capture_mode = True
        if not args.quiet:
            sys.stderr.write(
                f"[{PROG}] packet-capture flags given: using --capture mode "
                f"(add --mitm for full HTTPS paths)\n")
    mitm_mode = not capture_mode
    run_after = bool(args.mitm or args.command or args.mitm_system)
    ca_stream = sys.stderr if mitm_mode and args.format in ("json", "csv") else None

    if args.mitm_ca_show:
        show_ca(ca, color, stream=ca_stream)
        if not run_after:
            return 0
    if args.mitm_ca_reset:
        ca.reset()
        reset_out = ca_stream or sys.stdout
        reset_out.write(f"[{PROG}] CA and cached leaf certificates removed from {ca.dir}\n")
        reset_out.write(f"[{PROG}] existing trust entries remain; remove them with --mitm-ca-remove\n")
        if not (run_after or args.mitm_ca_install):
            return 0
    if args.mitm_ca_install:
        try:
            ca.ensure()
        except RuntimeError as exc:
            sys.stderr.write(f"[{PROG}] error: {exc}\n")
            return 2
        rc = install_ca(ca, color, stream=ca_stream)
        if not run_after:
            return rc
    if args.mitm_ca_remove:
        rc = install_ca(ca, color, remove=True, stream=ca_stream)
        if not run_after:
            return rc

    if capture_mode:
        if args.command:
            parser.error("a command can only be run with the MITM proxy (drop --capture)")
    else:
        if not (0 <= args.mitm_port <= 65535):
            parser.error("--mitm-port must be between 0 and 65535")
        if args.mitm_timeout <= 0:
            parser.error("--mitm-timeout must be > 0")

    # a few sanity checks that would otherwise fail confusingly mid-capture
    try:
        if args.duration < 0 or args.count < 0 or args.idle <= 0:
            raise ValueError
    except ValueError:
        parser.error("--duration/--count must be >= 0 and --idle > 0")
    if args.width and args.width < 40:
        parser.error("--width must be at least 40")
    if mitm_mode:
        return mitm_capture(args, color, ca)
    return capture(args, color)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
