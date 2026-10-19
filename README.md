**English** | [فارسی](README.fa.md)

# netlogger

A tiny, colourful Linux CLI that shows **every fetch your apps make** — as it
happens — with the method, the URL, the owning process and how much traffic
that request used.

```
03:21:29 [GET  ] download.example.com/package1.zip - 12.6 MB  curl(2381) · 200 · 1.90s · 6.64 MB/s
03:21:29 [GET  ] registry.npmjs.org/lodash/-/lodash-4.17.21.tgz?cache=1 - 1.41 MB  node(npm)(9124) · 200 · 610ms · tls1.3
03:21:30 [POST ] api.github.com/repos/octocat/hello/issues - 5.33 KB  git(7781) · 201 · 220ms
03:21:31 [WS   ] stream.example.com/live/feed?channel=7 - 296 KB  firefox(3311) · 101 · 12.40s
03:21:32 [QUIC ] www.youtube.com - 48.9 MB  chrome(5510) · 22.80s · 2.15 MB/s · h3
03:21:33 [DNS  ] download.example.com - 160 B  curl(2381) · 93.184.216.34
03:21:34 [SSH  ] git.internal:22 - 1.91 MB  ssh(4412) · 9.60s · 199 KB/s
03:21:35 [CONN ] pinned.example.com - 7085 B  app(6677) · pass-through (not decrypted)
──────────────────────────────────────────────────────────────────────────────
 netlogger 1.1.0 · 1.08s · 8 fetches
 traffic   ↓ 64.8 MB   ↑ 815 KB   total 65.6 MB
 top apps  chrome 48.9 MB · curl 12.6 MB · ssh 1.91 MB · node(npm) 1.41 MB · firefox 506 KB
 methods   GET 2 · POST 1 · WS 1 · QUIC 1 · DNS 1 · SSH 1 · CONN 1
──────────────────────────────────────────────────────────────────────────────
```

Packet capture uses only the Python standard library, `/proc`, and no eBPF,
libpcap or daemon. One file, one raw socket. For **full HTTPS paths** there is
a built-in MITM proxy (no mitmproxy needed) that terminates TLS locally with
its own CA — see [Full HTTPS URLs](#full-https-urls-mitm-mode).

---

## Install

```bash
chmod +x netlogger.py
sudo ./netlogger.py                 # from this directory
./install.sh                        # or install as `netlogger` in ~/.local/bin
netlogger.py --demo                 # preview without root
```

Requirements: Linux, Python 3.8+, raw-packet permission (root or
`CAP_NET_RAW`). MITM mode needs no root and uses either the `cryptography`
module or the `openssl` command to make certificates (one of them is almost
always already installed).

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
**MITM mode does not need root** (except for `--mitm-ca-install`, which asks
`sudo` to write the system trust store).

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

## Full HTTPS URLs (MITM mode)

TLS hides paths. The built-in proxy fixes that by accepting the connection,
showing a certificate for the requested host (signed by a local CA that
netlogger creates), reading the request, then connecting upstream over TLS.
It does **not** need mitmproxy and does **not** need root.

```bash
# 1. start the proxy (127.0.0.1:8080 by default)
./netlogger.py --mitm

# ... or let netlogger run one app with the proxy + CA already configured
./netlogger.py --mitm -- curl -L https://example.com/releases/app.tar.gz

# ... or point GNOME's system proxy at it (restored when netlogger exits)
./netlogger.py --mitm --mitm-system
```

For a single shell, use the variables the banner prints:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.config/netlogger/mitm/ca.pem
export NODE_EXTRA_CA_CERTS=~/.config/netlogger/mitm/ca.pem
```

`--mitm -- command ...` sets all of these for the child automatically:
`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`,
`GIT_SSL_CAINFO`, `PIP_CERT`. If you ran netlogger with `sudo`, the child is
dropped back to your desktop user (Python 3.9+), so it does not run as root.

### Trust the CA

`--mitm -- curl ...` works because curl is told to trust the CA through
`CURL_CA_BUNDLE`. For every other app, install it once:

```bash
./netlogger.py --mitm-ca-install    # system store + Firefox/Chrome NSS
./netlogger.py --mitm-ca-show       # path + SHA-256 fingerprint
./netlogger.py --mitm-ca-remove     # undo it
./netlogger.py --mitm-ca-reset      # delete the CA and leaf cache
```

`--mitm-ca-install` detects Arch/Debian/Fedora layouts, writes the anchor with
`sudo`, runs `update-ca-trust` / `update-ca-certificates`, and adds the CA to
`~/.pki/nssdb` plus every Firefox profile (native, Flatpak and Snap). Restart
browsers afterwards. Java has its own `cacerts` store and is not touched;
point Java at the CA with `-Djavax.net.ssl.trustStore=...` if needed.

The CA lives in `~/.config/netlogger/mitm/` (or `$XDG_CONFIG_HOME`). The
private key is mode `0600`; **treat it as a secret**. Remove trust with
`--mitm-ca-remove` when you are done.

### What you get

Every proxied request becomes one normal netlogger record:

```
03:47:41 [GET  ] example.com/ - 1.01 KB  curl(906450) · 200 · 652ms · ↓936 B · ↑75 B · tls1.3
```

- Full path and query string, method, status, content type, request/response
  bytes, duration, TLS version, ALPN, host and process.
- HTTPS, WebSocket (`WS`/`WSS`, including the handshake path and tunnelled
  frames), `CONNECT` tunnels and plain HTTP.
- JSON/CSV output has the complete `url`, e.g.
  `https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`.
- Process attribution comes from the client's source port in
  `/proc/net/tcp{,6}`, so it stays reliable while the connection is open.

The proxy speaks HTTP/1.1 with clients and upstream servers; browsers and
clients that prefer HTTP/2 see `http/1.1` in ALPN and fall back automatically.
HTTP/3/QUIC uses UDP and bypasses an HTTP proxy — run the normal packet mode
alongside MITM if you also want to see QUIC flows (as `QUIC`, without paths).

### Limitations and safety

- **Certificate pinning wins.** Apps that pin a certificate or public key will
  reject the MITM certificate. netlogger emits a `CONN` record with
  `TLS handshake failed — certificate pinning?` instead of hiding the attempt.
  For known pinned hosts, pass them through untouched:
  `--mitm-ignore '*.pinned.example'` (you get a `CONN` record with bytes, but
  no path).
- **Only HTTP(S) is decrypted.** Non-TLS `CONNECT` (SSH, custom TCP) is
  tunnelled and counted, with no application URL.
- **HTTP/1.1 only.** Clients that prefer HTTP/2 see `http/1.1` in ALPN and
  fall back automatically; upstream is always HTTP/1.1 too. This is deliberate:
  it keeps the proxy small and dependency-free, and almost every server still
  supports HTTP/1.1.
- **Trust is powerful.** Anyone with the CA private key can sign certificates
  your machine trusts. Keep the directory private and remove the CA when you
  are finished. Do not expose the proxy on `0.0.0.0` on an untrusted network.
- **System proxy is GNOME-only.** `--mitm-system` uses `gsettings`
  (`org.gnome.system.proxy`) and restores the saved values on exit. If netlogger
  is killed with `SIGKILL`, run `./netlogger.py --mitm-restore` (add the same
  `--mitm-ca-dir` if you used a custom one). KDE/other desktops: use the
  environment variables from the banner.
- **Short connections.** Attribution can still miss a process that disappears
  in under ~0.5 s; MITM connections usually live long enough, but a one-shot
  request may show `-`. Run as root to attribute apps owned by other users.
- **Byte counts.** MITM records count HTTP payload (headers included), not TLS
  framing. Pass-through/tunnel records count the raw tunnelled bytes.

---

## What the badges mean

| badge | meaning |
| --- | --- |
| `GET`, `POST`, `PUT`, `DELETE`, … | real HTTP method (plain HTTP, or HTTPS with `--mitm`) |
| `WS`, `WSS` | WebSocket handshake / stream |
| `HTTPS` | encrypted TLS session; host comes from the TLS SNI |
| `H2`, `H3` | HTTP/2, HTTP/3 (ALPN detected; method shown when it can be read) |
| `QUIC` | QUIC / HTTP-3 flow |
| `DNS` | name lookup (needs `--dns`) |
| `CONN` | a raw `CONNECT` tunnel or an ignored/pinned host |
| `SSH`, `SMB`, `MYSQL`, … | guessed from the port, shown for big enough flows or with `--all` |
| `TCP`, `UDP` | unknown protocol |

The trailing parts are optional and disappear automatically on narrow
terminals, in this priority order: process name, HTTP status, duration,
throughput, bytes down/up, TLS version, ALPN, request count, expected
`Content-Length` (only when the transfer looks incomplete), peer address,
notes.

## How it works

### Packet mode (default)

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

### MITM mode (`--mitm`)

1. A local CA and a per-host leaf certificate are created on demand (cached in
   `certs/`), using `cryptography` when available and the `openssl` CLI
   otherwise.
2. The proxy accepts the client's `CONNECT`, answers `200`, and terminates TLS
   with a certificate for the requested host (SNI is honoured too).
3. The HTTP request is parsed and forwarded upstream over a fresh verified TLS
   connection; `Expect: 100-continue`, chunked bodies, redirects, 1xx
   responses and WebSocket upgrades are handled. Verification can be disabled
   for local testing with `--mitm-insecure`.
4. The response is relayed byte-for-byte and a normal `Record` is pushed into
   the same formatter, filters and statistics as packet mode.
5. `--mitm-system` saves the previous GNOME proxy values to
   `proxy-state.json` before switching and restores them on exit/`SIGINT`.
   `--mitm-restore` recovers after a hard kill.

## Limitations (honest ones)

- **HTTPS paths are encrypted without `--mitm`.** You get the host (SNI), the
  process, the byte count and the TLS version — not `/path/file.zip`. Only
  plain HTTP reveals paths in packet mode. HTTP/2 and HTTP/3 paths are
  compressed (HPACK/QPACK).
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
- **MITM is HTTP/1.1.** Clients and upstream are negotiated as HTTP/1.1 (the
  path is still complete); HTTP/3/QUIC bypasses HTTP proxies. Certificate
  pinning cannot be defeated, only detected or passed through.
- Tested on Linux only (that is the point) with Python 3.8+.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 84 tests, no root needed
./netlogger.py --selftest                  # 26 built-in checks
```

The tests build real Ethernet/IP/TCP/UDP frames (IPv4, IPv6, VLAN, SLL,
TLS ClientHello split across segments, DNS, WebSocket, HTTP/2 preface) and push
them through the exact same engine the live sniffer uses. The MITM tests start
a real loopback HTTP/HTTPS origin, intercept it through the proxy, verify the
full path/TLS record, and cover `CONNECT` tunnelling, keep-alive connection
reuse, the openssl certificate backend and a `gsettings` save/restore
round-trip (with a fake `gsettings`, so your desktop settings are never
touched).

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
- HTTP/2 upstream in MITM mode and an optional mitmproxy bridge for HTTP/3.
- A curses/tmux dashboard with per-app live gauges.

They are omitted to keep this a single file that always runs; packet mode stays
dependency-free, and MITM mode needs only Python plus the `cryptography` module
or the openssl CLI.
