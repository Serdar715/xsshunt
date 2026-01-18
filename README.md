<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blueviolet?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars/Serdar715/xsshunt?style=for-the-badge&color=yellow" alt="Stars">
</p>

<h1 align="center">🕵️ XSSHunt</h1>
<p align="center"><b>Advanced XSS Vulnerability Scanner with WAF Bypass</b></p>

---

## ⚡ Quick Install

```bash
go install github.com/Serdar715/xsshunt/cmd/xsshunt@latest
```

Or build from source:
```bash
git clone https://github.com/Serdar715/xsshunt.git && cd xsshunt && go build -o xsshunt ./cmd/xsshunt
```

> **Requires:** Go 1.21+ and Chrome/Chromium

---

## 🎯 Features

- **DOM & Reflected XSS Detection** - Real browser verification with minimal false positives
- **WAF Bypass** - Cloudflare, Akamai, Imperva, ModSecurity, Sucuri, F5, and more
- **Proxy Support** - Burp Suite, OWASP ZAP integration
- **Authenticated Scanning** - Cookie and header-based authentication
- **Header Fuzzing** - Test XSS in HTTP headers with `FUZZ` marker
- **Batch Scanning** - Scan multiple URLs from file
- **Rate Limiting** - Configurable delays to avoid detection

---

## 🚀 Usage

### Basic
```bash
xsshunt "https://target.com/search?q="
```

### With Proxy (Burp Suite)
```bash
xsshunt "https://target.com/search?q=" --proxy http://127.0.0.1:8080
```

### Authenticated Scan
```bash
xsshunt "https://target.com/search?q=" -c "session=abc123" --auth "Bearer token"
```

### Header Fuzzing
```bash
xsshunt "https://target.com/api" -H "X-Forwarded-For: FUZZ" -H "Referer: FUZZ"
```

### Batch Scan
```bash
xsshunt -l urls.txt -o report.html --format html
```

### Rate Limited (Stealth)
```bash
xsshunt "https://target.com/search?q=" --delay 1000 -t 2
```

### Full Example
```bash
xsshunt "https://target.com/search?q=" \
  --proxy http://127.0.0.1:8080 \
  -c "session=abc" \
  -H "X-Custom: FUZZ" \
  -w cloudflare \
  -t 10 \
  --delay 500 \
  -o report.html --format html
```

---

## 📋 Options

| Flag | Description |
|------|-------------|
| `-l, --list` | File containing URLs to scan |
| `-p, --payloads` | Custom payload file |
| `-w, --waf` | WAF type (auto, cloudflare, akamai, imperva, etc.) |
| `-t, --threads` | Concurrent threads (default: 5) |
| `--delay` | Delay between requests in ms |
| `--proxy` | Proxy URL (http://host:port) |
| `-c, --cookie` | Cookie header value |
| `--auth` | Authorization header |
| `-H, --header` | Header to fuzz (use FUZZ marker) |
| `-o, --output` | Output file |
| `--format` | Output format (json, html) |
| `-v, --visible` | Show browser window |
| `--verbose` | Verbose output |

---

## 🛡️ Supported WAFs

Cloudflare • Akamai • AWS WAF • Imperva • Wordfence • ModSecurity • Sucuri • F5 BIG-IP • Barracuda

---

## 📁 Project Structure

```
xsshunt/
├── cmd/xsshunt/main.go      # Entry point
├── internal/
│   ├── scanner/             # Core XSS detection engine
│   ├── payloads/            # WAF bypass payloads
│   ├── waf/                 # WAF detection
│   ├── report/              # HTML/JSON reports
│   └── cli/                 # CLI handling
└── README.md
```

---

## ⚠️ Disclaimer

**Authorized testing only.** Only use on systems you own or have explicit permission to test. The developers assume no liability for misuse.

---

<p align="center">
  Made by <a href="https://github.com/Serdar715">@Serdar715</a> • 
  <a href="https://github.com/Serdar715/xsshunt/issues">Report Bug</a>
</p>
