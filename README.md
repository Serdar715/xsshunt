<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blueviolet?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars/Serdar715/xsshunt?style=for-the-badge&color=yellow" alt="Stars">
</p>

<h1 align="center">🕵️ XSSHunt</h1>
<p align="center"><b>Advanced XSS Vulnerability Scanner with WAF Bypass, SSTI & Open Redirect Detection</b></p>
<p align="center"><i>Inspired by XSStrike, Dalfox, and XSSer - Built for Security Professionals</i></p>

---

## ⚡ Quick Install

### Linux/macOS (One-Line)
```bash
git clone https://github.com/Serdar715/xsshunt.git && cd xsshunt && go build -o xsshunt ./cmd/xsshunt && sudo mv xsshunt /usr/local/bin/
```

### Windows (PowerShell One-Line)
```powershell
git clone https://github.com/Serdar715/xsshunt.git; cd xsshunt; go build -o xsshunt.exe ./cmd/xsshunt
```

> **Requirements:** Go 1.21+ and Chrome/Chromium

---

## 🎯 Features

### Core XSS Detection
- **DOM-based XSS** - Real browser verification with JavaScript execution
- **Reflected XSS** - Context-aware analysis with zero false positives
- **Blind XSS** - Callback-based detection (XSSHunter integration)
- **Stored XSS** - Optimized payloads for persistent XSS

### Advanced Detection
- **Fuzzy Matching** (XSStrike-style) - Levenshtein algorithm for partial payload detection
- **SSTI Detection** (Dalfox-style) - Server Side Template Injection scanning
- **Open Redirect Detection** - Comprehensive redirect vulnerability testing
- **Security Headers Analysis** - CSP, X-Frame-Options, HSTS evaluation

### WAF Bypass
Cloudflare, Akamai, Imperva, ModSecurity, Sucuri, F5, AWS WAF, and more

### Professional Features
- Proxy Support (Burp Suite, OWASP ZAP)
- Authenticated Scanning (Cookie/Header)
- Header Fuzzing with `FUZZ` marker
- Batch Scanning from file
- HTML/JSON Reports

---

## 🚀 Usage

```bash
# Basic scan
xsshunt "https://target.com/search?q="

# With proxy (Burp Suite)
xsshunt "https://target.com/search?q=" --proxy http://127.0.0.1:8080

# Authenticated scan
xsshunt "https://target.com/search?q=" -c "session=abc123" --auth "Bearer token"

# Header fuzzing
xsshunt "https://target.com/api" -H "X-Forwarded-For: FUZZ"

# Blind XSS with callback
xsshunt "https://target.com/contact" --blind-callback "yourid.xss.ht"

# Full vulnerability scan (XSS + SSTI + Open Redirect)
xsshunt "https://target.com/page?param=" --ssti --open-redirect

# Batch scan with report
xsshunt -l urls.txt -o report.html --format html
```

---

## 📋 Options

| Flag | Description | Default |
|------|-------------|---------|
| `-l, --list` | File containing URLs to scan | - |
| `-p, --payloads` | Custom payload file | - |
| `-w, --waf` | WAF type (auto, cloudflare, akamai, etc.) | auto |
| `-t, --threads` | Concurrent threads | 5 |
| `--delay` | Delay between requests (ms) | 0 |
| `--proxy` | Proxy URL | - |
| `-c, --cookie` | Cookie header value | - |
| `--auth` | Authorization header | - |
| `-H, --header` | Header to fuzz (use FUZZ marker) | - |
| `-o, --output` | Output file for report | - |
| `--format` | Output format (json, html) | json |
| `-v, --visible` | Show browser window | false |
| `--verbose` | Verbose output | false |
| `--blind-callback` | Callback URL for blind XSS | - |
| `--ssti` | Scan for SSTI | false |
| `--open-redirect` | Scan for Open Redirect | false |
| `--fuzzy` | Enable fuzzy matching | true |
| `--stored` | Stored XSS testing mode | false |

---

## 🛡️ Supported WAFs

| WAF | Detection | Bypass |
|-----|-----------|--------|
| Cloudflare | ✅ | ✅ |
| Akamai | ✅ | ✅ |
| CloudFront | ✅ | ✅ |
| Imperva | ✅ | ✅ |
| ModSecurity | ✅ | ✅ |
| Sucuri | ✅ | ✅ |
| F5 BIG-IP | ✅ | ✅ |
| AWS WAF | ✅ | ✅ |

---

##  Comparison

| Feature | XSSHunt | XSStrike | Dalfox |
|---------|---------|----------|--------|
| DOM XSS | ✅ | ✅ | ✅ |
| Fuzzy Matching | ✅ | ✅ | ❌ |
| Blind XSS | ✅ | ⚠️ | ✅ |
| SSTI Detection | ✅ | ❌ | ✅ |
| Open Redirect | ✅ | ❌ | ✅ |
| WAF Bypass | ✅ | ✅ | ✅ |

---

## ⚠️ Disclaimer

**Authorized testing only.** Only use on systems you own or have explicit permission to test.

---

<p align="center">Made with ❤️ by <a href="https://github.com/Serdar715">@Serdar715</a></p>
