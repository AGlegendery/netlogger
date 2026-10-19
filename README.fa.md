[English](README.md) | **فارسی**

<div dir="rtl">

# netlogger

یک ابزار خط فرمان کوچک و رنگی برای لینوکس که **همهٔ واکشی‌ها (fetch) و دانلودهای برنامه‌ها** را همان لحظه نشان می‌دهد — همراه با متد، آدرس، نام برنامه و حجم ترافیکی که آن درخواست مصرف کرده است.

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

بدون هیچ کتابخانهٔ شخص ثالث، بدون eBPF، بدون libpcap و بدون دیمن. فقط یک فایل، کتابخانهٔ استاندارد پایتون، یک سوکت خام (raw socket) و `/proc`.

---

## نصب

```bash
chmod +x netlogger.py
sudo ./netlogger.py                 # from this directory
./install.sh                        # or install as `netlogger` in ~/.local/bin
netlogger.py --demo                 # preview without root
```

پیش‌نیازها: لینوکس، پایتون ۳.۸ به بالا، و دسترسی به بسته‌های خام (root یا `CAP_NET_RAW`).

## چرا root؟

برای دیدن ترافیک همهٔ فرایندها به یک سوکت خام `AF_PACKET` نیاز است و این کار یک عملیات سطح‌بالا (privileged) محسوب می‌شود. دو راه دارید:

```bash
sudo ./netlogger.py                       # simplest
sudo -E ./netlogger.py                    # keeps NO_COLOR, etc.
```

اعمال `setcap` روی یک اسکریپت پایتون کار نمی‌کند (کرنل قابلیت‌ها را به مفسر اعمال می‌کند، نه به اسکریپت)، بنابراین `sudo` گزینهٔ منطقی است. اگر برنامه نتواند سوکت را باز کند، خودش همین توضیح را نشان می‌دهد.

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

## معنی برچسب‌ها

| برچسب | معنی |
| --- | --- |
| `GET`, `POST`, `PUT`, `DELETE`, … | متد واقعی HTTP (فقط در HTTP ساده دیده می‌شود) |
| `WS`, `WSS` | دست‌دادن (handshake) یا جریان WebSocket |
| `HTTPS` | نشست رمزنگاری‌شدهٔ TLS؛ نام میزبان از SNI می‌آید |
| `H2`, `H3` | HTTP/2 و HTTP/3 (تشخیص با ALPN؛ در صورت امکان متد هم نمایش داده می‌شود) |
| `QUIC` | جریان QUIC / HTTP-3 |
| `DNS` | جست‌وجوی نام (نیازمند `--dns`) |
| `SSH`, `SMB`, `MYSQL`, … | حدس از روی پورت؛ برای جریان‌های بزرگ یا با `--all` نمایش داده می‌شود |
| `TCP`, `UDP` | پروتکل ناشناخته |

بخش‌های انتهایی اختیاری‌اند و در ترمینال‌های باریک به‌طور خودکار حذف می‌شوند؛ ترتیب اهمیت: نام فرایند، کد وضعیت HTTP، مدت زمان، سرعت، بایت‌های دریافتی/ارسالی، نسخهٔ TLS، ALPN، تعداد درخواست، `Content-Length` مورد انتظار (فقط وقتی انتقال ناقص به نظر می‌رسد)، آدرس مقصد و یادداشت‌ها.

## چطور کار می‌کند

1. یک سوکت خام `AF_PACKET` روی همهٔ رابط‌های واقعی (شامل `lo`) فریم‌های کامل اترنت را می‌گیرد.
2. فریم دستی تجزیه می‌شود: اترنت/VLAN ← IPv4/IPv6 (شامل هدرهای افزونه) ← TCP/UDP.
3. اتصال‌ها در یک جدول کوچک جریان بر اساس ۴-تایی (مبدأ/مقصد) گروه‌بندی می‌شوند تا هر دو جهت و همهٔ قطعه‌ها در یک رکورد جمع شوند.
4. نخستین بایت‌های هر جهت (تا ۱۶ کیلوبایت) بافر و بررسی می‌شوند: خط درخواست و هدرهای HTTP/1.1، هدر `Upgrade` مربوط به WebSocket، پیام ClientHello در TLS (SNI، ALPN، نسخه)، مقدمهٔ HTTP/2 و یک نگاه به HPACK برای یافتن متد، هدر بلند QUIC، و پرسش/پاسخ DNS.
5. از `/proc/net/tcp{,6}` و `/proc/net/udp{,6}` inode هر سوکت به دست می‌آید؛ با پیمایش `/proc/<pid>/fd` آن inode به نام فرایند و PID نگاشت می‌شود. سوکت‌ها کش می‌شوند، پس جست‌وجو ارزان است.
6. وقتی جریانی بسته شود (FIN/RST) یا بی‌کار بماند، رکورد همراه با تعداد دقیق بایت‌های دادهٔ برنامه در هر جهت چاپ می‌شود. پاسخ‌های DNS به خاطر سپرده می‌شوند تا جریان‌های TLS بعدی به همان IP حتی بدون SNI هم نام میزبان داشته باشند.

## محدودیت‌ها (صادقانه)

- **مسیرهای HTTPS رمزنگاری شده‌اند.** نام میزبان (SNI)، فرایند، حجم بایت‌ها و نسخهٔ TLS را می‌گیرید — اما نه `/path/file.zip` را. فقط HTTP ساده مسیرها را آشکار می‌کند؛ فلسفهٔ وجود TLS همین است. دربارهٔ HTTP/2 و HTTP/3 هم مسیر درخواست (فشرده‌شده با HPACK/QPACK) قابل خواندن نیست.
- **اتصال‌های بسیار کوتاه ممکن است نام فرایند را نداشته باشند.** نگاشت فرایند از `/proc` و تا زمانی که سوکت وجود دارد خوانده می‌شود؛ یک درخواست ۵ میلی‌ثانیه‌ای روی لوپ‌بک ممکن است قبل از پردازش فریم بسته شده باشد. دانلودها و هر چیزی که بیش از چند صد میلی‌ثانیه زنده بماند، با اطمینان به فرایند نسبت داده می‌شود.
- **بایت‌های ارسال‌شدهٔ مجدد هم شمرده می‌شوند.** عدد نمایش‌داده‌شده ترافیک واقعی شبکه است، نه اندازهٔ فایل. روی یک لینک سالم این دو یکی هستند، به‌جز تفاوت هدرهای TCP/HTTP.
- **پل‌ها و رابط‌های مجازی.** رابط‌های مجازی (`docker0`، `br-*`، `veth*`، `tun*`، `wg*`، `ifb*`) به‌طور پیش‌فرض رد می‌شوند، چون بسته‌هایی را تکرار می‌کنند که قبلاً روی لینک فیزیکی دیده شده‌اند؛ اگر می‌دانید چه می‌خواهید از `--all-ifaces` استفاده کنید.
- **توان عبوری.** تجزیهٔ خالص پایتون ده‌ها هزار بسته در ثانیه را راحت پردازش می‌کند؛ یک لینک چند گیگابیتی اشباع‌شده فریم از دست می‌دهد. با `-i` دامنهٔ ضبط را محدود کنید.
- فقط روی لینوکس آزمایش شده است (که هدف اصلی است) با پایتون ۳.۸ به بالا.

## تست‌ها

```bash
python3 -m unittest discover -s tests -v   # 68 tests, no root needed
./netlogger.py --selftest                  # quick built-in checks
```

تست‌ها فریم‌های واقعی اترنت/IP/TCP/UDP می‌سازند (IPv4، IPv6، VLAN، SLL، ClientHello تقسیم‌شده میان چند قطعه، DNS، WebSocket، مقدمهٔ HTTP/2) و آن‌ها را از همان مسیری عبور می‌دهند که شنودگر زنده استفاده می‌کند.

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
- رمزگشایی TLS با `SSLKEYLOGFILE` (نیازمند `cryptography`) برای بازیابی مسیرهای HTTPS.
- یک داشبورد curses/tmux با نمودارهای زندهٔ هر برنامه.

این‌ها کنار گذاشته شده‌اند تا پروژه یک فایل تک‌تکهٔ بدون وابستگی بماند که همیشه اجرا می‌شود.

</div>
