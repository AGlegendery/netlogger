**English** | [فارسی](README.fa.md)

# netlogger

A tiny, colourful Linux CLI that shows **every fetch your apps make** — as it
happens — with the method, the URL, the owning process and how much traffic
that request used.

```
03:21:29 [GET  ] download.example.com/package1.zip - 12.6 MB  curl(2381) · 200 · 1.90s · 6.64 MB/s
03:21:29 [H2   ] registry.npmjs.org/lodash/-/lodash-4.17.21.tgz - 1.41 MB  node(npm)(9124) · 610ms · ↓1.40 MB · ↑3.10 KB · tls1.3
03:21:30 [POST ] api.github.com/repos/octocat/hello/issues - 5.33 KB  git(7781) · 201 · 220ms
03:21:31 [WS   ] stream.example.com/live/feed?channel=7 - 296 KB  firefox(3311) · 101 · 12.40s
03:21:32 [QUIC ] www.youtube.com - 48.9 MB  chrome(5510) · 22.80s · 2.15 MB/s · ↓48.2 MB · ↑704 KB · h3
03:21:33 [DNS  ] download.example.com - 160 B  curl(2381) · ↓96 B · ↑64 B · 93.184.216.34
03:21:34 [SSH  ] git.internal:22 - 1.91 MB  ssh(4412) · 9.60s · 199 KB/s · ↓1.82 MB · ↑88.2 KB
──────────────────────────────────────────────────────────────────────────────
 netlogger 1.0.0 · 1.08s · 9 fetches
 traffic   ↓ 64.8 MB   ↑ 815 KB   total 65.6 MB
 top apps  chrome 48.9 MB · curl 12.6 MB · ssh 1.91 MB · node(npm) 1.41 MB · firefox 506 KB
 methods   GET 3 · H2 1 · POST 1 · WS 1 · QUIC 1 · DNS 1 · SSH 1
──────────────────────────────────────────────────────────────────────────────
```

No third-party packages, no eBPF, no libpcap, no daemon. One file, the Python
standard library, a raw socket and `/proc`.

---

## Install

```bash
chmod +x netlogger.py
sudo ./netlogger.py                 # from this directory
./install.sh                        # or install as `netlogger` in ~/.local/bin
netlogger.py --demo                 # preview without root
```

Requirements: Linux, Python 3.8+, raw-packet permission (root or
`CAP_NET_RAW`).

## Why root?

Capturing every process' traffic needs a raw `AF_PACKET` socket, which is a
privileged operation. Two ways:

```bash
sudo ./netlogger.py                       # simplest
sudo -E ./netlogger.py                    # keeps NO_COLOR, etc.
```

`setcap` on a Python script does not work (the kernel applies file
capabilities to the interpreter, not to the script), so `sudo` is the sane
option. The program tells you this if it can't open the socket.

---

## Usage

```bash
# everything, pretty colours
sudo ./netlogger.py

# only the wireless interface, one line per fetch as it starts
sudo ./netlogger.py -i wlan0 --live

# only downloads bigger than 1 MB, only zip-ish hosts
sudo ./netlogger.py --min-size 1M --host '*.zip'

# watch what apt / a single app is doing
sudo ./netlogger.py --app apt --peer

# follow websockets and DNS too
sudo ./netlogger.py --dns --method WS,GET,POST

# machine readable
sudo ./netlogger.py -f json -o fetches.jsonl
sudo ./netlogger.py -f csv  -o fetches.csv

# keep the raw packets for Wireshark while logging
sudo ./netlogger.py --pcap dump.pcap

# stop after 20 fetches, or after 30 seconds
sudo ./netlogger.py -n 20
sudo ./netlogger.py -d 30
```

Useful flags (see `--help` for all of them):

| flag | meaning |
| --- | --- |
| `-i, --interface IFACE` | capture one interface (repeatable); default: all real ones |
| `-l, --live` | print a line when a fetch starts, and its final size when it ends |
| `--dns` | also show DNS lookups (hidden by default) |
| `--all` | also show traffic that isn't a fetch (SSH, NTP, custom protocols) |
| `--host`, `--exclude-host` | glob or substring filter on the host name |
| `--app`, `--exclude-app`, `--pid` | filter by process |
| `--method GET,POST,WS` | filter by badge |
| `--port 443` | filter by port (either side) |
| `--min-size`, `--max-size` | filter by traffic used |
| `-w, --watch PATTERN` | highlight matching lines |
| `-f, --format` | `pretty` (default), `plain`, `json`, `csv` |
| `-o, --out FILE` | write records to a file instead of stdout |
| `--log FILE` | also append plain lines to a log file |
| `--pcap FILE` | save the raw frames, openable in Wireshark |
| `--peer` | show `→ ip:port` for every fetch |
| `--full-url` | never truncate URLs |
| `--binary` | KiB/MiB/GiB instead of KB/MB/GB |
| `--color auto\|always\|never` | colour control (also honours `NO_COLOR`) |
| `--stats-interval SECS` | running totals on stderr while capturing |
| `--list-interfaces` | show what can be captured |
| `--demo` | offline colourful demo, no root needed |
| `--selftest` | parser self-checks |

---

## What the badges mean

| badge | meaning |
| --- | --- |
| `GET`, `POST`, `PUT`, `DELETE`, … | real HTTP method (only visible on plain HTTP) |
| `WS`, `WSS` | WebSocket handshake / stream |
| `HTTPS` | encrypted TLS session; host comes from the TLS SNI |
| `H2`, `H3` | HTTP/2, HTTP/3 (ALPN detected; method shown when it can be read) |
| `QUIC` | QUIC / HTTP-3 flow |
| `DNS` | name lookup (needs `--dns`) |
| `SSH`, `SMB`, `MYSQL`, … | guessed from the port, shown for big enough flows or with `--all` |
| `TCP`, `UDP` | unknown protocol |

The trailing parts are optional and disappear automatically on narrow
terminals, in this priority order: process name, HTTP status, duration,
throughput, bytes down/up, TLS version, ALPN, request count, expected
`Content-Length` (only when the transfer looks incomplete), peer address,
notes.

## How it works

1. A raw `AF_PACKET` socket on every real interface (`lo` included) gives full
   Ethernet frames.
2. The frame is parsed by hand: Ethernet/VLAN → IPv4/IPv6 (extension headers
   included) → TCP/UDP.
3. Connections are grouped in a small flow table keyed by the 4-tuple, so both
   directions and every segment land in the same record.
4. The first bytes of each direction are buffered (16 KiB) and sniffed:
   HTTP/1.1 request line + headers, WebSocket `Upgrade`, TLS ClientHello
   (SNI, ALPN, version), HTTP/2 preface + a peek at HPACK for the method,
   QUIC long header, DNS questions/answers.
5. `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` give the socket inode of each
   connection; walking `/proc/<pid>/fd` maps the inode to a process name and
   PID. Sockets are cached, so lookups are cheap.
6. When a flow closes (FIN/RST) or goes idle, the record is printed with the
   exact application payload bytes seen in each direction. DNS answers are
   remembered, so later TLS flows to the same IP can show a hostname even when
   SNI is absent.

## Limitations (honest ones)

- **HTTPS paths are encrypted.** You get the host (SNI), the process, the
  status-independent byte count and the TLS version — not `/path/file.zip`.
  Only plain HTTP reveals paths, because that is what TLS is for. Same for
  HTTP/2 and HTTP/3 request paths (HPACK/QPACK compressed).
- **Very short connections may miss the process name.** Attribution is read
  from `/proc` while the socket exists; a 5 ms localhost request can be gone
  before the frame is processed. Downloads and anything that lives longer than
  a few hundred milliseconds are attributed reliably.
- **Retransmitted bytes are counted.** The number is real wire traffic, not the
  file size. On a clean link they are the same, modulo TCP/HTTP framing.
- **Loops/bridges.** Virtual interfaces (`docker0`, `br-*`, `veth*`, `tun*`,
  `wg*`, `ifb*`) are skipped by default because they duplicate packets already
  seen on the physical link; use `--all-ifaces` if you know what you want.
- **Throughput.** Pure Python parsing handles tens of thousands of packets per
  second comfortably; a saturated multi-gigabit link will drop frames. Use
  `-i` to narrow the capture.
- Tested on Linux only (that is the point) with Python 3.8+.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 68 tests, no root needed
./netlogger.py --selftest                  # quick built-in checks
```

The tests build real Ethernet/IP/TCP/UDP frames (IPv4, IPv6, VLAN, SLL,
TLS ClientHello split across segments, DNS, WebSocket, HTTP/2 preface) and push
them through the exact same engine the live sniffer uses.

## Files

```
netlogger.py          the whole program
tests/test_netlogger.py
install.sh
README.md             English
README.fa.md          فارسی
LICENSE
Makefile
```

## Ideas that would make it even better (not implemented on purpose)

- eBPF `kprobe` on `tcp_connect` for 100 % process attribution of ultra-short
  connections.
- TLS decryption via `SSLKEYLOGFILE` (needs `cryptography`) to recover HTTPS
  paths.
- A curses/tmux dashboard with per-app live gauges.

They are omitted to keep this a single dependency-free file that always runs.
