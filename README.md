**English** | [فارسی](README.fa.md)

# netlogger

A tiny, colourful Linux CLI that shows **every fetch your apps make** — with the
**full URL, including the HTTPS path**, the method, the owning process and how
much traffic that request used.

By default it runs a local MITM proxy with its own CA, so even encrypted requests
show their complete address:

```
12:33:04 [GET  ] download.example.com/package1.zip?mirror=eu - 12.6 MB  curl(2381) · 200 · 0.41s · 3.9 MB/s · tls1.3
12:33:05 [POST ] api.github.com/repos/octocat/hello/issues - 5.33 KB  git(7781) · 201 · 220ms
12:33:06 [GET  ] registry.npmjs.org/lodash/-/lodash-4.17.21.tgz - 1.41 MB  node(npm)(9124) · 200 · 610ms
12:33:07 [WS   ] stream.example.com/live/feed?channel=7 - 296 KB  firefox(3311) · 101 · 12.40s
12:33:08 [CONN ] pinned.example.com - 7085 B  app(6677) · pass-through (not decrypted)
──────────────────────────────────────────────────────────────────────────────
 netlogger 1.2.0 · 1.08s · 5 fetches
 traffic   ↓ 14.3 MB   ↑ 815 KB   total 15.1 MB
 top apps  curl 12.6 MB · node(npm) 1.41 MB · firefox 296 KB · github 5.33 KB
 methods   GET 3 · POST 1 · WS 1 · CONN 1
──────────────────────────────────────────────────────────────────────────────
```

There is also the original **raw packet-capture mode** (no proxy, every interface,
DNS, QUIC) with `--capture`; it needs root/`CAP_NET_RAW`. Neither mode uses eBPF,
libpcap or a daemon.

---

## Install

```bash
chmod +x netlogger.py
sudo ./netlogger.py                 # full-path proxy for everything (default)
./install.sh                        # install as `netlogger` in ~/.local/bin
netlogger.py --demo                 # preview without root
```

Requirements: Linux and Python 3.8+. The default proxy builds its CA with the
`cryptography` module or the `openssl` command (one of them is almost always
already installed). Capture mode additionally needs root or `CAP_NET_RAW`.

## Permissions

The **proxy itself needs no root**. Root (or `sudo`) is used only to trust the CA
in the system store and to change GNOME's system proxy — and both are undone when
netlogger exits. Run it with `sudo` for the full "everything just works" path:

```bash
sudo ./netlogger.py                       # trust the CA for this run, proxy everything
sudo ./netlogger.py --no-ca-install       # proxy, but never touch the trust stores
./netlogger.py -- curl https://x/y        # proxy only this command (no system changes)
```

Raw packet capture (`--capture`) needs a privileged `AF_PACKET` socket. `setcap`
on a Python script does not work (the kernel applies capabilities to the
interpreter, not the script), so `sudo` is the sane option.

---

## Usage

```bash
# default: full paths for everything; CA trusted and GNOME proxy set for the run
sudo ./netlogger.py

# proxy one command only (no system changes): CA + proxy env are set for the child
./netlogger.py -- curl -L https://example.com/releases/app.tar.gz

# proxy without touching system trust or the desktop proxy
sudo ./netlogger.py --no-ca-install --no-system-proxy

# only show fetches from one app, or bigger than 1 MB
sudo ./netlogger.py --app curl
sudo ./netlogger.py --min-size 1M

# machine readable
sudo ./netlogger.py -f json -o fetches.jsonl
sudo ./netlogger.py -f csv  -o fetches.csv

# stop after 20 fetches, or after 30 seconds
sudo ./netlogger.py -n 20
sudo ./netlogger.py -d 30

# the old raw-packet view: every interface, DNS, QUIC, no proxy
sudo ./netlogger.py --capture
sudo ./netlogger.py --capture -i wlan0 --dns --live
sudo ./netlogger.py --capture --pcap dump.pcap      # save frames for Wireshark
```

Passing capture-only flags (`-i`, `--dns`, `--pcap`, `--all`, `--snaplen`, …)
without a mode is treated as `--capture`; add `--mitm` to force the proxy.

Useful flags (see `--help` for all of them):

| flag | meaning |
| --- | --- |
| `--capture` | raw AF_PACKET sniffer instead of the proxy (needs root) |
| `--mitm` | the local TLS-terminating proxy (this is the default) |
| `--no-ca-install` | don't auto-install/remove the CA in the trust stores |
| `--no-system-proxy` | don't touch GNOME's system proxy automatically |
| `-i, --interface IFACE` | capture one interface (repeatable); capture mode |
| `-l, --live` | print a line when a fetch starts, and its final size when it ends |
| `--dns` | also show DNS lookups (capture mode) |
| `--all` | also show traffic that isn't a fetch (capture mode) |
| `--host`, `--exclude-host` | glob or substring filter on the host name |
| `--app`, `--exclude-app`, `--pid` | filter by process |
| `--method GET,POST,WS` | filter by badge |
| `--port 443` | filter by port (either side) |
| `--min-size`, `--max-size` | filter by traffic used |
| `-w, --watch PATTERN` | highlight matching lines |
| `-f, --format` | `pretty` (default), `plain`, `json`, `csv` |
| `-o, --out FILE` | write records to a file instead of stdout |
| `--log FILE` | also append plain lines to a log file |
| `--pcap FILE` | save the raw frames, openable in Wireshark (capture mode) |
| `--peer` | show `→ ip:port` for every fetch |
| `--full-url` | never truncate URLs |
| `--binary` | KiB/MiB/GiB instead of KB/MB/GB |
| `--color auto\|always\|never` | colour control (also honours `NO_COLOR`) |
| `--stats-interval SECS` | running totals on stderr while capturing |
| `--list-interfaces` | show what can be captured |
| `--demo` | offline colourful demo, no root needed |
| `--selftest` | parser self-checks |

---

## Default mode: full URLs for everything

TLS normally hides paths. netlogger accepts the connection, shows a certificate
for the requested host (signed by a CA it keeps in `~/.config/netlogger/mitm/`),
reads the request, then connects upstream over its own TLS connection. It does
**not** need mitmproxy, and the proxy itself does **not** need root.

A plain `sudo ./netlogger.py` run does three things:

1. creates the CA if needed,
2. trusts it in the system + Firefox/Chrome (NSS) stores **for the duration of the
   run**, and removes it again on exit,
3. points GNOME's system proxy at `127.0.0.1:8080` and restores your previous
   settings on exit.

Disable either with `--no-ca-install` and `--no-system-proxy`. If netlogger is
killed with `SIGKILL`, recover the proxy settings with `./netlogger.py
--mitm-restore` (add the same `--mitm-ca-dir` if you used a custom one).

Apps have to honour the proxy. Firefox/Chrome on GNOME do. For one command, or a
shell, use the environment instead:

```bash
./netlogger.py -- curl -L https://example.com/releases/app.tar.gz
# or copy the variables the banner prints:
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.config/netlogger/mitm/ca.pem
export NODE_EXTRA_CA_CERTS=~/.config/netlogger/mitm/ca.pem
```

`--mitm -- command ...` (or just `-- command ...`) sets all of these for the
child automatically: `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`,
`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`,
`GIT_SSL_CAINFO`, `PIP_CERT`. If you ran netlogger with `sudo`, the child is
dropped back to your desktop user (Python 3.9+), so it does not run as root.

### Keeping the CA trusted

The automatic trust is removed when netlogger exits. To trust the CA permanently
(for example because you run the proxy as a non-root service, or want browsers to
keep working across runs), install it once:

```bash
./netlogger.py --mitm-ca-install    # system store + Firefox/Chrome NSS
./netlogger.py --mitm-ca-show       # path + SHA-256 fingerprint
./netlogger.py --mitm-ca-remove     # undo it
./netlogger.py --mitm-ca-reset      # delete the CA and leaf cache
```

`--mitm-ca-install` detects Arch/Debian/Fedora layouts, writes the anchor with
`sudo`, runs `update-ca-trust` / `update-ca-certificates`, and adds the CA to
`~/.pki/nssdb` plus every Firefox profile (native, Flatpak and Snap). Restart
browsers afterwards. Java has its own `cacerts` store and is not touched; point
Java at the CA with `-Djavax.net.ssl.trustStore=...` if needed.

The CA lives in `~/.config/netlogger/mitm/` (or `$XDG_CONFIG_HOME`). The private
key is mode `0600`; **treat it as a secret**. Remove trust with
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
HTTP/3/QUIC uses UDP and bypasses an HTTP proxy. Apps that bypass the proxy
(QUIC, hosts in `NO_PROXY`, apps ignoring the system proxy) are not seen — run
`--capture` alongside if you also want those.

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
- **Trust is powerful.** While netlogger runs, its CA is trusted by your machine.
  Anyone with the CA private key can sign certificates your machine trusts. Keep
  the directory private; the automatic run removes the trust again on exit. Do
  not expose the proxy on `0.0.0.0` on an untrusted network.
- **System proxy is GNOME-only.** Automatic switching uses `gsettings`
  (`org.gnome.system.proxy`); on KDE or other desktops use the environment
  variables from the banner, or `--no-system-proxy` plus manual configuration.
- **Short connections.** Attribution can still miss a process that disappears
  in under ~0.5 s; MITM connections usually live long enough, but a one-shot
  request may show `-`. Run as root to attribute apps owned by other users.
- **Byte counts.** MITM records count HTTP payload (headers included), not TLS
  framing. Pass-through/tunnel records count the raw tunnelled bytes.

---

## Capture mode (`--capture`)

The original mode: a raw `AF_PACKET` socket on every real interface, no proxy.
It sees **all** traffic — including QUIC, DNS and apps that ignore proxies — but
cannot decrypt HTTPS paths:

```
03:21:29 [HTTPS] www.example.com - 12.6 MB  curl(2381) · 1.90s · tls1.3
03:21:30 [QUIC ] www.youtube.com - 48.9 MB  chrome(5510) · 22.80s · h3
03:21:31 [DNS  ] download.example.com - 160 B  curl(2381) · 93.184.216.34
03:21:32 [SSH  ] git.internal:22 - 1.91 MB  ssh(4412) · 9.60s
```

```bash
sudo ./netlogger.py --capture                  # everything on every interface
sudo ./netlogger.py --capture -i wlan0 --live
sudo ./netlogger.py --capture --dns --all
sudo ./netlogger.py --capture --host '*.zip' --min-size 1M
sudo ./netlogger.py --capture --pcap dump.pcap
```

## What the badges mean

| badge | meaning |
| --- | --- |
| `GET`, `POST`, `PUT`, `DELETE`, … | real HTTP method (proxy mode) |
| `WS`, `WSS` | WebSocket handshake / stream |
| `HTTPS` | encrypted TLS session; host comes from the TLS SNI (capture mode) |
| `H2`, `H3` | HTTP/2, HTTP/3 (ALPN detected; method shown when it can be read) |
| `QUIC` | QUIC / HTTP-3 flow |
| `DNS` | name lookup (needs `--dns`) |
| `CONN` | a raw `CONNECT` tunnel, an ignored/pinned host, or a non-TLS tunnel |
| `SSH`, `SMB`, `MYSQL`, … | guessed from the port, shown for big enough flows or with `--all` |
| `TCP`, `UDP` | unknown protocol |

The trailing parts are optional and disappear automatically on narrow terminals,
in this priority order: process name, HTTP status, duration, throughput, bytes
down/up, TLS version, ALPN, request count, expected `Content-Length` (only when
the transfer looks incomplete), peer address, notes.

## How it works

### Proxy mode (default)

1. A local CA and a per-host leaf certificate are created on demand (cached in
   `certs/`), using `cryptography` when available and the `openssl` CLI
   otherwise.
2. The proxy accepts the client's `CONNECT`, answers `200`, and terminates TLS
   with a certificate for the requested host (SNI is honoured too).
3. The HTTP request is parsed and forwarded upstream over a fresh verified TLS
   connection; `Expect: 100-continue`, chunked bodies, keep-alive, redirects, 1xx
   responses and WebSocket upgrades are handled. Verification can be disabled
   for local testing with `--mitm-insecure`.
4. The response is relayed byte-for-byte and a normal `Record` is pushed into
   the same formatter, filters and statistics as capture mode.
5. On a plain run, the CA is trusted for the duration and GNOME's proxy is
   switched; both are undone on exit. `--mitm-system` / `--mitm-restore` expose
   that behaviour explicitly for scripts.

### Capture mode (`--capture`)

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

- **Apps must use the proxy.** In the default mode netlogger sees what goes
  through its proxy: the GNOME system proxy, or the environment you set. Apps
  that ignore both (or use QUIC) are missed — use `--capture` for those.
- **HTTPS paths are encrypted in capture mode.** You get the host (SNI), the
  process, the byte count and the TLS version — not `/path/file.zip`. HTTP/2 and
  HTTP/3 paths are compressed (HPACK/QPACK) as well.
- **Very short connections may miss the process name.** Attribution is read
  from `/proc` while the socket exists; a 5 ms localhost request can be gone
  before the frame is processed.
- **Retransmitted bytes are counted.** The number is real wire traffic, not the
  file size. On a clean link they are the same, modulo TCP/HTTP framing.
- **Loops/bridges.** In capture mode, virtual interfaces (`docker0`, `br-*`,
  `veth*`, `tun*`, `wg*`, `ifb*`) are skipped by default because they duplicate
  packets already seen on the physical link; use `--all-ifaces` if you want them.
- **Throughput.** Pure Python parsing handles tens of thousands of packets per
  second comfortably; a saturated multi-gigabit link will drop frames. Use
  `-i` (capture mode) to narrow the capture.
- **HTTP/1.1 proxy.** Clients and upstream are negotiated as HTTP/1.1; HTTP/3
  bypasses HTTP proxies. Certificate pinning cannot be defeated, only detected
  or passed through.
- Tested on Linux only (that is the point) with Python 3.8+.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 88 tests, no root needed
./netlogger.py --selftest                  # 26 built-in checks
```

The tests build real Ethernet/IP/TCP/UDP frames (IPv4, IPv6, VLAN, SLL,
TLS ClientHello split across segments, DNS, WebSocket, HTTP/2 preface) and push
them through the exact same engine the live sniffer uses. The proxy tests start
a real loopback HTTP/HTTPS origin, intercept it through the proxy, verify the
full path/TLS record, and cover `CONNECT` tunnelling, keep-alive connection
reuse, the openssl certificate backend, mode selection, the automatic
trust/proxy behaviour (mocked, so your system is never touched) and a
`gsettings` save/restore round-trip (with a fake `gsettings`).

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
- HTTP/2 upstream in proxy mode and an optional mitmproxy bridge for HTTP/3.
- A curses/tmux dashboard with per-app live gauges.

They are omitted to keep this a single file that always runs; proxy mode needs
only Python plus the `cryptography` module or the openssl CLI, and capture mode
needs nothing but the standard library.
