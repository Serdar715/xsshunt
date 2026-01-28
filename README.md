<div align="center">

# 🕵️ XSSHunt
### Advanced XSS Vulnerability Scanner & Pathway Analyzer

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blueviolet?style=for-the-badge)](https://github.com/Serdar715/xsshunt)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Serdar715/xsshunt?style=for-the-badge&color=yellow)](https://github.com/Serdar715/xsshunt/stargazers)

<p align="center">
  <b>XSSHunt</b> is a next-generation automated scanner designed for security professionals to detect Cross-Site Scripting (XSS), Server-Side Template Injection (SSTI), and Open Redirect vulnerabilities with high precision.
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-configuration">Configuration</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

</div>

---

## 🚀 Features

### 🧠 Intelligent Detection
*   **Context-Aware Analysis:** Dynamic analysis of HTML context (Attribute, Script, HTML Body) to select the perfect payload.
*   **Zero False Positives:** Advanced verification engine with strict marker validation - only confirmed XSS executions are reported.
*   **Fuzzy Matching:** Levenshtein distance algorithm to detect filtered/modified reflections (inspired by XSStrike).
*   **Polyglot Payloads:** Smart generation of polyglot vectors to break multiple contexts simultaneously.

### 🛡️ WAF Evasion
*   **Automated Bypass:** payloads optimized for **Cloudflare, Akamai, Imperva, AWS WAF, F5 BIG-IP, ModSecurity**, and more.
*   **Protocol Level Obfuscation:** Uses HTTP parameter pollution and encoding techniques to evade filters.

### ⚡ Performance & Stability
*   **Headless Browser Engine:** Chrome/Chromium integration (via `go-rod`) for accurate DOM-based XSS verification.
*   **Resource Efficient:** Optimized concurrency with worker pools and memory-safe processing (goroutine leak protection).
*   **Secure:** Cryptographically safe randomization for scan markers.

### 🔍 Comprehensive Auditing
*   **Blind XSS:** Integrated callback support for detecting blind injection points.
*   **SSTI & Open Redirect:** Additional scanning modules for template injection and unvalidated redirects.
*   **Security Headers:** Checks for CSP, HSTS, and X-Frame-Options misconfigurations.

### 🆕 v2.2 Refactoring Updates (Advanced)
*   **Rod Page Pool:** Integrated highly efficient browser page pooling to drastically reduce memory/CPU usage during heavy scans.
*   **Smart Context Mutator:** Automatically fixes broken payloads based on reflection context (e.g. `"><script>` vs `';alert(1)//`).
*   **Advanced WAF Bypass:** Dynamic encoding (URL, Double URL, Unicode) and structural obfuscation (Comment injection, whitespace) engine.
*   **Structured Reporting:** JSON, Markdown, and Webhook-ready reporting module.
*   **False Positive Reduction:** 5-Layer verification system (Safe Container, Encoding Check, Sanitization Check).

---

## 📥 Installation

### Prerequisites
*   **Go** (version 1.21 or higher)
*   **Google Chrome** or **Chromium** installed on the system.

### One-Line Install

**Linux / macOS / WSL:**
```bash
go install github.com/Serdar715/xsshunt/cmd/xsshunt@latest
```

**Windows (PowerShell):**
```powershell
go install github.com/Serdar715/xsshunt/cmd/xsshunt@latest
```

### Build from Source

**Linux / macOS:**
```bash
git clone https://github.com/Serdar715/xsshunt.git && cd xsshunt && go build -o xsshunt ./cmd/xsshunt && chmod +x xsshunt && sudo mv xsshunt /usr/local/bin/ && xsshunt -h
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/Serdar715/xsshunt.git; cd xsshunt; go build -o xsshunt.exe ./cmd/xsshunt; .\xsshunt.exe -h
```

---

## 💻 Usage

### Basic Scan
Scan a single URL for XSS vulnerabilities:
```bash
xsshunt --url "https://example.com/search?q=test"
```

### Advanced Scans

**Authenticated Scan with Proxy:**
```bash
xsshunt --url "https://example.com/dashboard" \
  --cookie "session_id=xyz123" \
  --auth "Bearer token_here" \
  --proxy "http://127.0.0.1:8080"
```

**Full Audit (XSS + SSTI + Open Redirect):**
```bash
xsshunt --url "https://target.com/param?id=1" --ssti --open-redirect
```

**Header Fuzzing:**
Test specific headers for injection vulnerabilities:
```bash
xsshunt --url "https://api.target.com/v1" -H "User-Agent: FUZZ" -H "X-Forwarded-For: FUZZ"
```

**Batch Scan:**
Scan multiple URLs from a file and generate an HTML report:
```bash
xsshunt -l targets.txt -o report.html --format html --threads 10
```

---

## ⚙️ Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL to scan |
| `-l, --list` | File containing list of URLs to scan |
| `-p, --payloads` | Path to custom payload file |
| `--cookie` | Session cookies (e.g., `JSESSIONID=...`) |
| `--auth` | Authorization header value |
| `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) |
| `-t, --threads` | Number of concurrent threads (Default: 5) |
| `--timeout` | Request timeout in seconds (Default: 30) |
| `--delay` | Delay between requests in ms (Rate limiting) |
| `-w, --waf` | Specific WAF to target (Default: `auto`) |
| `--format` | Report format: `json` or `html` |
| `-v, --visible` | Run browser in visible mode (for debugging) |
| `--verbose` | Enable verbose logging |
| `--silent` | Silence all output except findings |

---



## ⚠️ Disclaimer

This tool is developed for **educational and security testing purposes only**. The usage of XSSHunt on targets without prior mutual consent is illegal. The developer allows no responsibility and liability for any misuse or damage caused by this program.

---

<div align="center">
  <sub>Made with ❤️ by <a href="https://github.com/Serdar715">Serdar715</a></sub>
</div>
