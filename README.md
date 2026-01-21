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

### Option 1: Clone & Build (Recommended)
```bash
# Clone repository
git clone https://github.com/Serdar715/xsshunt.git
cd xsshunt

# Build
go mod tidy
go build -o xsshunt ./cmd/xsshunt

# Linux/macOS: Install to PATH
sudo mv xsshunt /usr/local/bin/

# Windows: The executable will be xsshunt.exe in current directory
# You can add the directory to PATH or move it to a PATH directory
```

### Option 2: One-Line Install (Linux/macOS)
```bash
git clone https://github.com/Serdar715/xsshunt.git && cd xsshunt && go mod tidy && go build -o xsshunt ./cmd/xsshunt && sudo mv xsshunt /usr/local/bin/
```

### Option 3: One-Line Build (Windows PowerShell)
```powershell
git clone https://github.com/Serdar715/xsshunt.git; cd xsshunt; go mod tidy; go build -o xsshunt.exe ./cmd/xsshunt
```

### Option 4: Using Makefile
```bash
git clone https://github.com/Serdar715/xsshunt.git && cd xsshunt
make build         # Build for current platform
sudo make install  # Install to /usr/local/bin (Linux/macOS)
```

### Option 5: Go Install (after module is indexed)
```bash
# Note: May take 30+ minutes after new releases for Go proxy to update
GO111MODULE=on go install github.com/Serdar715/xsshunt/cmd/xsshunt@latest
```

> **Requirements:** 
> - Go 1.21+
> - Chrome/Chromium (for headless browser testing)

---

## 🎯 Features

### Core XSS Detection
- **DOM-based XSS Detection** - Real browser verification with JavaScript execution
- **Reflected XSS Detection** - Context-aware analysis with zero false positives
- **Stored XSS Testing** - Optimized payloads for persistent XSS
- **Blind XSS Support** - Callback-based detection (XSSHunter integration)

### Advanced Detection (Inspired by Top Tools)
- **Fuzzy Matching** (XSStrike-style) - Levenshtein algorithm for partial payload reflection
- **Context Analysis** - Smart payload selection based on injection context
- **SSTI Detection** (Dalfox-style) - Server Side Template Injection scanning
- **Open Redirect Detection** (Dalfox-style) - Comprehensive redirect vulnerability testing
- **Security Headers Analysis** - CSP, X-Frame-Options, HSTS evaluation

### WAF Bypass
- **Cloudflare, Akamai, Imperva** - Advanced bypass payloads
- **ModSecurity, Sucuri, F5** - Rule evasion techniques
- **Auto-detection** - Automatic WAF fingerprinting
- **Encoding Variations** - HTML entity, Unicode, Base64 bypasses

### Professional Features
- **Proxy Support** - Burp Suite, OWASP ZAP integration
- **Authenticated Scanning** - Cookie and header-based auth
- **Header Fuzzing** - XSS in HTTP headers with `FUZZ` marker
- **Batch Scanning** - Multiple URLs from file
- **Rate Limiting** - Configurable delays
- **Beautiful Reports** - HTML and JSON output

---

## 🚀 Usage

### Basic Scanning
```bash
# Basic XSS scan
xsshunt "https://target.com/search?q="

# With verbose output
xsshunt "https://target.com/search?q=" --verbose

# Visible browser mode (for debugging)
xsshunt "https://target.com/search?q=" -v
```

### Proxy & Authentication
```bash
# With Burp Suite proxy
xsshunt "https://target.com/search?q=" --proxy http://127.0.0.1:8080

# Authenticated scan with cookies
xsshunt "https://target.com/search?q=" -c "session=abc123; token=xyz"

# With Authorization header
xsshunt "https://target.com/search?q=" --auth "Bearer eyJhbGc..."

# Combined proxy + auth
xsshunt "https://target.com/search?q=" --proxy http://127.0.0.1:8080 -c "session=abc" --auth "Bearer token"
```

### Header Fuzzing
```bash
# Fuzz single header
xsshunt "https://target.com/api" -H "X-Forwarded-For: FUZZ"

# Fuzz multiple headers
xsshunt "https://target.com/api" -H "X-Forwarded-For: FUZZ" -H "User-Agent: FUZZ"

# Referer-based XSS
xsshunt "https://target.com/page" -H "Referer: FUZZ"
```

### Blind XSS (with callback)
```bash
# Using XSSHunter callback
xsshunt "https://target.com/contact" --blind-callback "yourid.xss.ht"

# Using custom callback server
xsshunt "https://target.com/form" --blind-callback "https://yourserver.com/callback"
```

### Additional Vulnerability Scanning
```bash
# Enable SSTI detection (Dalfox-style)
xsshunt "https://target.com/template?name=" --ssti

# Enable Open Redirect detection
xsshunt "https://target.com/redirect?url=" --open-redirect

# Full vulnerability scan
xsshunt "https://target.com/page?param=" --ssti --open-redirect --check-headers
```

### Batch Scanning
```bash
# Scan URLs from file
xsshunt -l urls.txt

# With report output
xsshunt -l urls.txt -o report.html --format html

# Rate limited batch scan
xsshunt -l urls.txt --delay 500 -t 3
```

### Advanced Options
```bash
# Disable fuzzy matching
xsshunt "https://target.com/search?q=" --fuzzy=false

# Adjust fuzzy threshold
xsshunt "https://target.com/search?q=" --fuzzy-threshold 0.9

# Stored XSS mode
xsshunt "https://target.com/comment" --stored

# Custom payloads
xsshunt "https://target.com/search?q=" -p custom_payloads.txt

# Specific WAF type
xsshunt "https://target.com/search?q=" -w cloudflare
```

---

## 📋 Command Line Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--list` | `-l` | File containing URLs to scan | - |
| `--payloads` | `-p` | Custom payload file | - |
| `--waf` | `-w` | WAF type (auto, cloudflare, akamai, etc.) | auto |
| `--threads` | `-t` | Concurrent threads | 5 |
| `--timeout` | - | Request timeout in seconds | 30 |
| `--delay` | - | Delay between requests (ms) | 0 |
| `--proxy` | - | Proxy URL (http://host:port) | - |
| `--cookie` | `-c` | Cookie header value | - |
| `--auth` | - | Authorization header | - |
| `--header` | `-H` | Header to fuzz (use FUZZ marker) | - |
| `--output` | `-o` | Output file for report | - |
| `--format` | - | Output format (json, html) | json |
| `--visible` | `-v` | Show browser window | false |
| `--verbose` | - | Verbose output | false |
| `--blind-callback` | - | Callback URL for blind XSS | - |
| `--ssti` | - | Scan for SSTI | false |
| `--open-redirect` | - | Scan for Open Redirect | false |
| `--check-headers` | - | Check security headers | true |
| `--fuzzy` | - | Enable fuzzy matching | true |
| `--fuzzy-threshold` | - | Fuzzy match threshold (0.0-1.0) | 0.8 |
| `--stored` | - | Stored XSS testing mode | false |
| `--dom-deep` | - | Deep DOM analysis | true |
| `--no-smart` | - | Disable smart payload generation | false |

---

## 🛡️ Supported WAF Bypasses

| WAF | Detection | Bypass |
|-----|-----------|--------|
| Cloudflare | ✅ | ✅ |
| Akamai | ✅ | ✅ |
| CloudFront (AWS) | ✅ | ✅ |
| Imperva/Incapsula | ✅ | ✅ |
| ModSecurity | ✅ | ✅ |
| Sucuri | ✅ | ✅ |
| F5 BIG-IP | ✅ | ✅ |
| Wordfence | ✅ | ✅ |
| Barracuda | ✅ | ✅ |
| AWS WAF | ✅ | ✅ |
| FortiWeb | ✅ | ✅ |

---

## 📊 Example Output

```
🕵️ XSSHunt - Advanced XSS Scanner v2.0

┌─────────────────────────────────────────────────┐
│              SCAN CONFIGURATION                 │
└─────────────────────────────────────────────────┘
  📋 Mode:        Single URL Scan
  🧵 Threads:     5
  ⏱️  Timeout:    30s
─────────────────────────────────────────────────

[*] Detecting WAF...
[✓] No WAF detected
[*] Loaded 127 payloads

[*] Starting XSS scan on: https://target.com/search?q=

[*] Testing parameter: q
  [*] Smart Analysis reduced payloads from 127 to 45

[!] XSS Found: <script>alert(1)</script>

════════════════════════════════════════ Vulnerability #1 ════════════════════════════════════════
  Type:     DOM-based XSS (Confirmed)
  Payload:  <script>alert(1)</script>
  URL:      https://target.com/search?q=<script>alert(1)</script>
  Context:  JavaScript execution verified
  Severity: Critical

┌─────────────────────────────────────────────────┐
│                 SCAN SUMMARY                    │
└─────────────────────────────────────────────────┘
  🎯 Payloads Tested:   45
  ⏱️  Duration:         12.5s
  ⚠️  Vulnerabilities:  1 FOUND
─────────────────────────────────────────────────
```

---

## 🔧 Building from Source

```bash
# Clone
git clone https://github.com/Serdar715/xsshunt.git
cd xsshunt

# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
make test

# Clean
make clean
```

---

## 🔄 Comparison with Other Tools

| Feature | XSSHunt | XSStrike | Dalfox | XSSer |
|---------|---------|----------|--------|-------|
| DOM XSS Detection | ✅ | ✅ | ✅ | ⚠️ |
| Fuzzy Matching | ✅ | ✅ | ❌ | ❌ |
| Context Analysis | ✅ | ✅ | ✅ | ⚠️ |
| Blind XSS | ✅ | ⚠️ | ✅ | ❌ |
| SSTI Detection | ✅ | ❌ | ✅ | ❌ |
| Open Redirect | ✅ | ❌ | ✅ | ❌ |
| WAF Bypass | ✅ | ✅ | ✅ | ✅ |
| Proxy Support | ✅ | ✅ | ✅ | ✅ |
| Header Fuzzing | ✅ | ⚠️ | ✅ | ✅ |
| HTML Reports | ✅ | ❌ | ✅ | ⚠️ |

---

## ⚠️ Disclaimer

**Authorized testing only.** This tool is intended for authorized security testing and educational purposes. Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/Serdar715">@Serdar715</a>
</p>
