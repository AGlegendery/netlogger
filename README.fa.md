[English](README.md) | **فارسی**

<div dir="rtl">

# netlogger

یک ابزار خط فرمان کوچک و رنگی برای لینوکس که **همهٔ واکشی‌ها (fetch) و دانلودهای برنامه‌ها** را همان لحظه نشان می‌دهد — همراه با متد، آدرس، نام برنامه و حجم ترافیکی که آن درخواست مصرف کرده است.

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

ضبط بسته‌ها فقط با کتابخانهٔ استاندارد پایتون و `/proc` انجام می‌شود؛ بدون eBPF، بدون libpcap و بدون دیمن. یک فایل، یک سوکت خام. برای دیدن **مسیر کامل HTTPS** یک پروکسی MITM داخلی هم دارد (بدون نیاز به mitmproxy) که TLS را با CA محلی خودش پایان می‌دهد — بخش [مسیر کامل HTTPS](#مسیر-کامل-https-حالت-mitm) را ببینید.

---

## نصب

```bash
chmod +x netlogger.py
sudo ./netlogger.py                 # from this directory
./install.sh                        # or install as `netlogger` in ~/.local/bin
netlogger.py --demo                 # preview without root
```

پیش‌نیازها: لینوکس، پایتون ۳.۸ به بالا، و دسترسی به بسته‌های خام (root یا `CAP_NET_RAW`). حالت MITM به root نیاز ندارد و برای ساخت گواهی یا از ماژول `cryptography` استفاده می‌کند یا از فرمان `openssl` (تقریباً همیشه یکی از این دو نصب است).

## چرا root؟

برای دیدن ترافیک همهٔ فرایندها به یک سوکت خام `AF_PACKET` نیاز است و این کار یک عملیات سطح‌بالا (privileged) محسوب می‌شود. دو راه دارید:

```bash
sudo ./netlogger.py                       # simplest
sudo -E ./netlogger.py                    # keeps NO_COLOR, etc.
```

اعمال `setcap` روی یک اسکریپت پایتون کار نمی‌کند (کرنل قابلیت‌ها را به مفسر اعمال می‌کند، نه به اسکریپت)، بنابراین `sudo` گزینهٔ منطقی است. اگر برنامه نتواند سوکت را باز کند، خودش همین توضیح را نشان می‌دهد.
**حالت MITM به root نیاز ندارد** (به‌جز `--mitm-ca-install` که با `sudo` گواهی را در مخزن اعتماد سیستم می‌نویسد).

---

## استفاده

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

گزینه‌های پرکاربرد (فهرست کامل با `--help`):

| گزینه | معنی |
| --- | --- |
| `-i, --interface IFACE` | فقط همین رابط شبکه را ضبط کن (قابل تکرار)؛ پیش‌فرض: همهٔ رابط‌های واقعی |
| `-l, --live` | هنگام شروع یک واکشی یک خط چاپ کن و در پایان حجم نهایی را |
| `--dns` | جست‌وجوهای DNS را هم نشان بده (پیش‌فرض پنهان است) |
| `--all` | ترافیک غیرواکشی (SSH، NTP، پروتکل‌های دلخواه) را هم نشان بده |
| `--host`, `--exclude-host` | فیلتر نام میزبان با glob یا زیررشته |
| `--app`, `--exclude-app`, `--pid` | فیلتر بر اساس فرایند |
| `--method GET,POST,WS` | فیلتر بر اساس برچسب |
| `--port 443` | فیلتر بر اساس پورت (هر دو سمت) |
| `--min-size`, `--max-size` | فیلتر بر اساس حجم ترافیک |
| `-w, --watch PATTERN` | خطوط منطبق را برجسته کن |
| `-f, --format` | `pretty` (پیش‌فرض)، `plain`، `json`، `csv` |
| `-o, --out FILE` | رکوردها را در فایل بنویس، نه در خروجی استاندارد |
| `--log FILE` | خطوط ساده را هم به یک فایل لاگ اضافه کن |
| `--pcap FILE` | فریم‌های خام را ذخیره کن؛ با Wireshark باز می‌شود |
| `--peer` | برای هر واکشی `→ ip:port` را نشان بده |
| `--full-url` | آدرس‌ها را هرگز کوتاه نکن |
| `--binary` | به‌جای KB/MB/GB از KiB/MiB/GiB استفاده کن |
| `--color auto\|always\|never` | کنترل رنگ (متغیر محیطی `NO_COLOR` هم رعایت می‌شود) |
| `--stats-interval SECS` | جمع‌بندی جاری را هر چند ثانیه روی stderr چاپ کن |
| `--list-interfaces` | رابط‌های قابل ضبط را نشان بده |
| `--demo` | نمایش رنگی آفلاین، بدون نیاز به root |
| `--selftest` | بررسی‌های داخلی تجزیه‌گرها |

---

## مسیر کامل HTTPS (حالت MITM)

TLS مسیرها را پنهان می‌کند. پروکسی داخلی این مشکل را حل می‌کند: اتصال را می‌پذیرد، برای میزبان درخواستی یک گواهی (امضاشده با CA محلی که netlogger می‌سازد) نشان می‌دهد، درخواست را می‌خواند و سپس خودش با TLS به سرور اصلی وصل می‌شود. **به mitmproxy نیاز ندارد و به root هم نیاز ندارد.**

```bash
# 1. start the proxy (127.0.0.1:8080 by default)
./netlogger.py --mitm

# ... or let netlogger run one app with the proxy + CA already configured
./netlogger.py --mitm -- curl -L https://example.com/releases/app.tar.gz

# ... or point GNOME's system proxy at it (restored when netlogger exits)
./netlogger.py --mitm --mitm-system
```

برای یک شل، همان خطوط `export` را که در بنر چاپ می‌شود کپی کنید:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.config/netlogger/mitm/ca.pem
export NODE_EXTRA_CA_CERTS=~/.config/netlogger/mitm/ca.pem
```

فرم `--mitm -- command ...` همهٔ این‌ها را برای فرزند تنظیم می‌کند: `HTTPS_PROXY`، `HTTP_PROXY`، `ALL_PROXY`، `NO_PROXY`، `SSL_CERT_FILE`، `CURL_CA_BUNDLE`، `REQUESTS_CA_BUNDLE`، `NODE_EXTRA_CA_CERTS`، `GIT_SSL_CAINFO` و `PIP_CERT`. اگر netlogger را با `sudo` اجرا کرده باشید، فرزند به کاربر دسکتاپ شما برمی‌گردد (پایتون ۳.۹ به بالا) تا با root اجرا نشود.

### اعتماد به CA

فرم `--mitm -- curl ...` کار می‌کند چون curl از طریق `CURL_CA_BUNDLE` به CA اعتماد می‌کند. برای بقیهٔ برنامه‌ها یک‌بار نصبش کنید:

```bash
./netlogger.py --mitm-ca-install    # system store + Firefox/Chrome NSS
./netlogger.py --mitm-ca-show       # path + SHA-256 fingerprint
./netlogger.py --mitm-ca-remove     # undo it
./netlogger.py --mitm-ca-reset      # delete the CA and leaf cache
```

`--mitm-ca-install` چیدمان Arch/Debian/Fedora را تشخیص می‌دهد، فایل لنگر (anchor) را با `sudo` می‌نویسد، `update-ca-trust` یا `update-ca-certificates` را اجرا می‌کند و CA را به `~/.pki/nssdb` و همهٔ پروفایل‌های Firefox (بومی، Flatpak و Snap) اضافه می‌کند. بعد از آن مرورگرها را دوباره باز کنید. Java مخزن `cacerts` جداگانه دارد و دست نمی‌خورد؛ در صورت نیاز با `-Djavax.net.ssl.trustStore=...` آن را به CA اشاره دهید.

CA در `~/.config/netlogger/mitm/` (یا `$XDG_CONFIG_HOME`) قرار می‌گیرد. کلید خصوصی با مجوز `0600` است؛ **با آن مثل یک راز رفتار کنید**. وقتی کارتان تمام شد با `--mitm-ca-remove` اعتماد را بردارید.

### چه چیزی می‌گیرید

هر درخواست عبوری تبدیل به یک رکورد معمولی netlogger می‌شود:

```
03:47:41 [GET  ] example.com/ - 1.01 KB  curl(906450) · 200 · 652ms · ↓936 B · ↑75 B · tls1.3
```

- مسیر و query کامل، متد، کد وضعیت، نوع محتوا، بایت درخواست/پاسخ، مدت زمان، نسخهٔ TLS، ALPN، میزبان و فرایند.
- HTTPS، WebSocket (برچسب `WS`/`WSS`، شامل مسیر handshake و فریم‌های تونل‌شده)، تونل‌های `CONNECT` و HTTP ساده.
- در خروجی JSON/CSV فیلد `url` کامل است، مثلاً `https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`.
- نسبت‌دادن فرایند از پورت مبدأ کلاینت در `/proc/net/tcp{,6}` انجام می‌شود، بنابراین تا وقتی اتصال باز است قابل اعتماد می‌ماند.

پروکسی با کلاینت و سرور اصلی HTTP/1.1 صحبت می‌کند؛ مرورگرها و کلاینت‌هایی که HTTP/2 را ترجیح می‌دهند در ALPN مقدار `http/1.1` می‌بینند و خودکار به آن برمی‌گردند. HTTP/3/QUIC از UDP استفاده می‌کند و از پروکسی HTTP عبور نمی‌کند — اگر می‌خواهید جریان‌های QUIC را هم ببینید (به‌صورت `QUIC` و بدون مسیر)، حالت عادی ضبط بسته را در کنار MITM اجرا کنید.

### محدودیت‌ها و ایمنی

- **Certificate pinning برنده است.** برنامه‌هایی که گواهی یا کلید عمومی را pin می‌کنند، گواهی MITM را رد می‌کنند. netlogger به‌جای پنهان‌کردن تلاش، یک رکورد `CONN` با یادداشت `TLS handshake failed — certificate pinning?` چاپ می‌کند. برای میزبان‌های pin‌شدهٔ شناخته‌شده، آن‌ها را بدون دست‌کاری رد کنید: `--mitm-ignore '*.pinned.example'` (رکورد `CONN` با حجم می‌گیرید، اما بدون مسیر).
- **فقط HTTP(S) رمزگشایی می‌شود.** `CONNECT` غیر-TLS (SSH، TCP دلخواه) تونل می‌شود و شمرده می‌شود، بدون URL برنامه.
- **فقط HTTP/1.1.** مرورگرها و کلاینت‌هایی که HTTP/2 را ترجیح می‌دهند در ALPN مقدار `http/1.1` می‌بینند و خودکار به آن برمی‌گردند؛ سمت سرور اصلی هم همیشه HTTP/1.1 است. این کار عمدی است تا پروکسی کوچک و بدون وابستگی بماند و تقریباً همهٔ سرورها هنوز HTTP/1.1 را پشتیبانی می‌کنند.
- **اعتماد قدرت است.** هر کسی که کلید خصوصی CA را داشته باشد می‌تواند گواهی‌هایی امضا کند که سیستم شما به آن‌ها اعتماد دارد. پوشه را خصوصی نگه دارید و در پایان CA را بردارید. پروکسی را روی `0.0.0.0` در شبکهٔ غیرقابل‌اعتماد باز نکنید.
- **پروکسی سیستم فقط GNOME.** `--mitm-system` از `gsettings` (`org.gnome.system.proxy`) استفاده می‌کند و مقادیر ذخیره‌شده را هنگام خروج برمی‌گرداند. اگر netlogger با `SIGKILL` کشته شد، `./netlogger.py --mitm-restore` را اجرا کنید (اگر `--mitm-ca-dir` سفارشی داده بودید همان را هم بدهید). KDE و دسکتاپ‌های دیگر: از متغیرهای محیطی بنر استفاده کنید.
- **اتصال‌های کوتاه.** ممکن است فرایندی که در کمتر از حدود ۰٫۵ ثانیه ناپدید می‌شود از دست برود؛ اتصال‌های MITM معمولاً به‌قدر کافی زنده می‌مانند، اما یک درخواست یک‌باره ممکن است `-` نشان دهد. برای نسبت‌دادن برنامه‌های متعلق به کاربران دیگر، با root اجرا کنید.
- **شمارش بایت‌ها.** رکوردهای MITM بایت‌های payload HTTP (شامل هدرها) را می‌شمارند، نه فریم‌بندی TLS را. رکوردهای pass-through/تونل، بایت‌های خام تونل‌شده را می‌شمارند.

---

## معنی برچسب‌ها

| برچسب | معنی |
| --- | --- |
| `GET`, `POST`, `PUT`, `DELETE`, … | متد واقعی HTTP (HTTP ساده، یا HTTPS با `--mitm`) |
| `WS`, `WSS` | دست‌دادن (handshake) یا جریان WebSocket |
| `HTTPS` | نشست رمزنگاری‌شدهٔ TLS؛ نام میزبان از SNI می‌آید |
| `H2`, `H3` | HTTP/2 و HTTP/3 (تشخیص با ALPN؛ در صورت امکان متد هم نمایش داده می‌شود) |
| `QUIC` | جریان QUIC / HTTP-3 |
| `DNS` | جست‌وجوی نام (نیازمند `--dns`) |
| `CONN` | تونل خام `CONNECT` یا میزبان ignore/pin‌شده |
| `SSH`, `SMB`, `MYSQL`, … | حدس از روی پورت؛ برای جریان‌های بزرگ یا با `--all` نمایش داده می‌شود |
| `TCP`, `UDP` | پروتکل ناشناخته |

بخش‌های انتهایی اختیاری‌اند و در ترمینال‌های باریک به‌طور خودکار حذف می‌شوند؛ ترتیب اهمیت: نام فرایند، کد وضعیت HTTP، مدت زمان، سرعت، بایت‌های دریافتی/ارسالی، نسخهٔ TLS، ALPN، تعداد درخواست، `Content-Length` مورد انتظار (فقط وقتی انتقال ناقص به نظر می‌رسد)، آدرس مقصد و یادداشت‌ها.

## چطور کار می‌کند

### حالت ضبط بسته (پیش‌فرض)

1. یک سوکت خام `AF_PACKET` روی همهٔ رابط‌های واقعی (شامل `lo`) فریم‌های کامل اترنت را می‌گیرد.
2. فریم دستی تجزیه می‌شود: اترنت/VLAN ← IPv4/IPv6 (شامل هدرهای افزونه) ← TCP/UDP.
3. اتصال‌ها در یک جدول کوچک جریان بر اساس ۴-تایی (مبدأ/مقصد) گروه‌بندی می‌شوند تا هر دو جهت و همهٔ قطعه‌ها در یک رکورد جمع شوند.
4. نخستین بایت‌های هر جهت (تا ۱۶ کیلوبایت) بافر و بررسی می‌شوند: خط درخواست و هدرهای HTTP/1.1، هدر `Upgrade` مربوط به WebSocket، پیام ClientHello در TLS (SNI، ALPN، نسخه)، مقدمهٔ HTTP/2 و یک نگاه به HPACK برای یافتن متد، هدر بلند QUIC، و پرسش/پاسخ DNS.
5. از `/proc/net/tcp{,6}` و `/proc/net/udp{,6}` inode هر سوکت به دست می‌آید؛ با پیمایش `/proc/<pid>/fd` آن inode به نام فرایند و PID نگاشت می‌شود. سوکت‌ها کش می‌شوند، پس جست‌وجو ارزان است.
6. وقتی جریانی بسته شود (FIN/RST) یا بی‌کار بماند، رکورد همراه با تعداد دقیق بایت‌های دادهٔ برنامه در هر جهت چاپ می‌شود. پاسخ‌های DNS به خاطر سپرده می‌شوند تا جریان‌های TLS بعدی به همان IP حتی بدون SNI هم نام میزبان داشته باشند.

### حالت MITM (`--mitm`)

1. یک CA محلی و برای هر میزبان یک گواهی برگ (leaf) به‌صورت درخواستی ساخته می‌شود (کش در `certs/`)، با `cryptography` در صورت وجود و در غیر این صورت با فرمان `openssl`.
2. پروکسی `CONNECT` کلاینت را می‌پذیرد، `200` پاسخ می‌دهد و با گواهی میزبان درخواستی TLS را پایان می‌دهد (SNI هم رعایت می‌شود).
3. درخواست HTTP تجزیه و روی یک اتصال TLS تازه و تأییدشده به سرور اصلی فرستاده می‌شود؛ `Expect: 100-continue`، بدنه‌های chunked، ریدایرکت‌ها، پاسخ‌های 1xx و ارتقای WebSocket پشتیبانی می‌شوند. برای آزمایش محلی می‌توانید تأیید گواهی را با `--mitm-insecure` خاموش کنید.
4. پاسخ بایت‌به‌بایت عبور داده می‌شود و یک `Record` معمولی وارد همان قالب‌بند، فیلترها و آمار حالت بسته می‌شود.
5. `--mitm-system` مقادیر قبلی پروکسی GNOME را در `proxy-state.json` ذخیره می‌کند و هنگام خروج/`SIGINT` برمی‌گرداند. `--mitm-restore` بعد از kill سخت بازیابی می‌کند.

## محدودیت‌ها (صادقانه)

- **بدون `--mitm` مسیرهای HTTPS رمزنگاری شده‌اند.** نام میزبان (SNI)، فرایند، حجم بایت‌ها و نسخهٔ TLS را می‌گیرید — اما نه `/path/file.zip` را. فقط HTTP ساده در حالت بسته مسیرها را آشکار می‌کند. مسیرهای HTTP/2 و HTTP/3 هم فشرده‌اند (HPACK/QPACK).
- **اتصال‌های بسیار کوتاه ممکن است نام فرایند را نداشته باشند.** نگاشت فرایند از `/proc` و تا زمانی که سوکت وجود دارد خوانده می‌شود؛ یک درخواست ۵ میلی‌ثانیه‌ای روی لوپ‌بک ممکن است قبل از پردازش فریم بسته شده باشد. دانلودها و هر چیزی که بیش از چند صد میلی‌ثانیه زنده بماند، با اطمینان به فرایند نسبت داده می‌شود.
- **بایت‌های ارسال‌شدهٔ مجدد هم شمرده می‌شوند.** عدد نمایش‌داده‌شده ترافیک واقعی شبکه است، نه اندازهٔ فایل. روی یک لینک سالم این دو یکی هستند، به‌جز تفاوت هدرهای TCP/HTTP.
- **پل‌ها و رابط‌های مجازی.** رابط‌های مجازی (`docker0`، `br-*`، `veth*`، `tun*`، `wg*`، `ifb*`) به‌طور پیش‌فرض رد می‌شوند، چون بسته‌هایی را تکرار می‌کنند که قبلاً روی لینک فیزیکی دیده شده‌اند؛ اگر می‌دانید چه می‌خواهید از `--all-ifaces` استفاده کنید.
- **توان عبوری.** تجزیهٔ خالص پایتون ده‌ها هزار بسته در ثانیه را راحت پردازش می‌کند؛ یک لینک چند گیگابیتی اشباع‌شده فریم از دست می‌دهد. با `-i` دامنهٔ ضبط را محدود کنید.
- **MITM فقط HTTP/1.1 است.** کلاینت و سرور اصلی با HTTP/1.1 مذاکره می‌کنند (مسیر همچنان کامل است)؛ HTTP/3/QUIC از پروکسی HTTP عبور نمی‌کند. Certificate pinning شکستنی نیست؛ فقط قابل تشخیص یا دورزدن (pass-through) است.
- فقط روی لینوکس آزمایش شده است (که هدف اصلی است) با پایتون ۳.۸ به بالا.

## تست‌ها

```bash
python3 -m unittest discover -s tests -v   # 84 tests, no root needed
./netlogger.py --selftest                  # 26 built-in checks
```

تست‌ها فریم‌های واقعی اترنت/IP/TCP/UDP می‌سازند (IPv4، IPv6، VLAN، SLL، ClientHello تقسیم‌شده میان چند قطعه، DNS، WebSocket، مقدمهٔ HTTP/2) و آن‌ها را از همان مسیری عبور می‌دهند که شنودگر زنده استفاده می‌کند. تست‌های MITM یک سرور HTTP/HTTPS واقعی روی لوپ‌بک بالا می‌آورند، آن را از پروکسی عبور می‌دهند، رکورد مسیر/TLS کامل را بررسی می‌کنند و تونل `CONNECT`، استفادهٔ مجدد از اتصال keep-alive، بک‌اند گواهی openssl و ذخیره/بازیابی `gsettings` را (با یک `gsettings` تقلبی، تا تنظیمات دسکتاپ شما دست نخورد) آزمایش می‌کنند.

## فایل‌ها

```
netlogger.py          the whole program
tests/test_netlogger.py
install.sh
README.md             English
README.fa.md          فارسی
LICENSE
Makefile
```

## ایده‌هایی که عمداً پیاده نشده‌اند

- استفاده از `kprobe` در eBPF روی `tcp_connect` برای نسبت‌دادن ۱۰۰٪ اتصال‌های فوق‌کوتاه به فرایند.
- HTTP/2 در سمت سرور اصلی در حالت MITM و یک پل اختیاری mitmproxy برای HTTP/3.
- یک داشبورد curses/tmux با نمودارهای زندهٔ هر برنامه.

این‌ها کنار گذاشته شده‌اند تا پروژه یک فایل تک‌تکه بماند که همیشه اجرا می‌شود؛ حالت بسته بدون وابستگی است و حالت MITM فقط به پایتون به‌همراه ماژول `cryptography` یا فرمان `openssl` نیاز دارد.

</div>
