#  WebVuln Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Ethics](https://img.shields.io/badge/Use-Ethically-red?style=flat-square)

A Python-based web application vulnerability scanner that crawls target sites and tests for common security weaknesses — SQL injection, reflected XSS, missing security headers, and exposed directories. Built for security researchers, ethical hackers, and anyone learning web app pentesting.

##  Legal Disclaimer

> **Only use this tool on web applications you own or have explicit written permission to test.**
> Running this against systems without authorization is illegal under computer fraud laws in most countries.
> The author takes zero responsibility for any misuse. Stay legal, stay ethical.

---

##  Why I Built This

Honestly? I was tired of explaining web vulnerabilities in theory without having something to actually *show* people. Built this as a learning project to understand how scanners work under the hood — turns out crawling forms and throwing payloads at them teaches you more about web security than any YouTube video ever could. If it helps someone else learn too, even better.

---

##  Features

-  **Smart Crawler** — discovers all pages and forms on the target automatically
- **SQL Injection Detection** — error-based detection across all discovered forms
-  **Reflected XSS Testing** — checks if payloads bounce back unescaped in responses
-  **Security Headers Audit** — grades your headers A through F (spoiler: most sites get a D)
-  **Directory Bruteforce** — hunts for exposed paths using a curated wordlist
-  **HTML Report** — generates a clean dark-mode report you can actually share
-  **Modular** — run all checks or pick just what you need

---

##  Installation

**Clone the repo:**
```bash
git clone https://github.com/yourusername/webvuln-scanner.git
cd webvuln-scanner
```

**Set up a virtual environment (don't skip this, trust me):**
```bash
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
```

**Install dependencies:**
```bash
pip install -r requirements.txt
```

---

##  Usage

**Run a full scan:**
```bash
python scanner.py -t https://testphp.vulnweb.com --full
```

**Pick specific tests:**
```bash
python scanner.py -t https://example.com --sqli --headers
python scanner.py -t https://example.com --xss --dirs
python scanner.py -t https://example.com --headers
```

**Verbose mode (shows everything, even misses):**
```bash
python scanner.py -t https://example.com --full -v
```

**Custom report output path:**
```bash
python scanner.py -t https://example.com --full --output my_scan.html
```

**All flags:**
```
  -t, --target       Target URL (required)
  --sqli             Test for SQL injection
  --xss              Test for reflected XSS
  --headers          Audit security headers
  --dirs             Directory bruteforce
  --full             Run all scans
  --max-pages        Max pages to crawl (default: 20)
  --timeout          Request timeout in seconds (default: 5)
  --output           Custom HTML report path
  --no-report        Skip report, terminal output only
  -v, --verbose      Verbose output
```

---

## 📸 Sample Output

```
██╗    ██╗███████╗██████╗ ██╗   ██╗██╗     ███╗   ██╗
██║    ██║██╔════╝██╔══██╗██║   ██║██║     ████╗  ██║
...
       WebVuln Scanner v1.0 | For Authorized Use Only

[*] target: https://testphp.vulnweb.com
[*] scan started at 14:23:01
[*] starting crawl on https://testphp.vulnweb.com
[+] crawl done. visited 18 pages, found 6 forms

[*] testing 6 form(s) for SQL injection...
  [!!!] SQLi hit on https://testphp.vulnweb.com/search.php
        payload: ' OR 1=1--
        evidence: you have an error in your sql syntax

[*] testing 6 form(s) for reflected XSS...
  [!!!] XSS reflected on https://testphp.vulnweb.com/guestbook.php

[*] checking security headers on https://testphp.vulnweb.com
  [-] MISSING: Strict-Transport-Security (HIGH)
  [-] MISSING: Content-Security-Policy (HIGH)
  [*] security header grade: F

============================================================
  SCAN SUMMARY
============================================================
  Target          : https://testphp.vulnweb.com
  Pages Crawled   : 18
  Forms Found     : 6
  SQLi Findings   : 1
  XSS Findings    : 1
  Header Grade    : F
  Dir Hits        : 4
  Total Vulns     : 2
============================================================
  [!!!] 2 vulnerability(s) need attention!

[+] report saved to reports/report_20260531_142318.html
[*] stay legal out here fam ✌️
```

---

## 📁 Project Structure

```
webvuln-scanner/
├── scanner.py              # main entry point
├── src/
│   ├── crawler.py          # URL and form discovery
│   ├── sqli_tester.py      # SQL injection tests
│   ├── xss_tester.py       # XSS payload tests
│   ├── header_checker.py   # security headers audit
│   ├── dir_bruteforce.py   # directory discovery
│   ├── reporter.py         # HTML report generator
│   ├── utils.py            # shared helper functions
│   └── payloads/
│       ├── sqli.txt        # SQLi payloads
│       └── xss.txt         # XSS payloads
├── wordlists/
│   └── common_dirs.txt     # directory wordlist
├── reports/                # generated reports land here
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```


##  Safe Testing Targets

Want to test without breaking anything? These are intentionally vulnerable apps made for this exact purpose:

- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web Application
- [testphp.vulnweb.com](http://testphp.vulnweb.com) - Acunetix test site (authorized)
- [WebGoat](https://github.com/WebGoat/WebGoat) - OWASP's training app
- [HackTheBox](https://www.hackthebox.com/) - Legal practice environments


##  Known Issues / Roadmap

- [ ] Blind SQLi detection is not implemented yet (it's on the list, chill)
- [ ] No support for JavaScript-heavy SPAs (would need Selenium, maybe later)
- [ ] Rate limiting isn't super sophisticated — don't hammer production servers
- [ ] Stored XSS detection is out of scope for now
- [ ] Add proxy support (Burp Suite integration would be clean)
- [ ] Multi-threading for faster crawling

## Contributing

Pull requests are welcome. For major changes, open an issue first so we can talk about it. Just make sure whatever you add doesn't make this easier to abuse — we're keeping this educational.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/cool-new-thing`)
3. Commit your changes (`git commit -m 'add cool new thing'`)
4. Push to the branch (`git push origin feature/cool-new-thing`)
5. Open a Pull Request

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

Built for learning. Use responsibly. Don't make the rest of us look bad.*
