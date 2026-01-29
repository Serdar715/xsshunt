<div align="center">

# 🕵️ XSSHunt

### Advanced XSS Vulnerability Scanner

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blueviolet?style=for-the-badge)](https://github.com/Serdar715/xsshunt)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Serdar715/xsshunt?style=for-the-badge&color=yellow)](https://github.com/Serdar715/xsshunt/stargazers)

<p align="center">
  <b>XSSHunt</b> is a next-generation automated XSS scanner designed for security professionals. Detects Reflected, DOM-based, and Blind XSS with high precision and WAF bypass capabilities.
</p>

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Options](#%EF%B8%8F-options)

</div>

---

## ✨ Features

| Category | Description |
|----------|-------------|
| 🧠 **Smart Detection** | Context-aware analysis (HTML, Attribute, Script, URL) with zero false positives |
| 🛡️ **WAF Bypass** | Built-in bypasses for Cloudflare, Akamai, Imperva, AWS WAF, F5, ModSecurity |
| ⚡ **High Performance** | Concurrent scanning with goroutine pools and page pooling |
| 🔐 **Payload Encoding** | URL, Double URL, HTML Entity, Unicode encoding + obfuscation |
| � **KXSS/GXSS** | Smart parameter reflection testing with context-aware payload generation |
| 🔍 **Multi-Vuln** | Also scans for SSTI and Open Redirect vulnerabilities |
| 📊 **Reporting** | JSON and HTML report generation |

---

## 📥 Installation

**Requirements:** Go 1.21+ and Chrome/Chromium

```bash
# Install via Go
go install github.com/Serdar715/xsshunt/cmd/xsshunt@latest

# Or build from source
git clone https://github.com/Serdar715/xsshunt.git
cd xsshunt
go build -o xsshunt ./cmd/xsshunt
```

---

## 💻 Usage

### Basic Scan
```bash
xsshunt "https://example.com/search?q=test"
```

### Authenticated Scan with Proxy
```bash
xsshunt "https://example.com/dashboard" \
  --cookie "session_id=xyz123" \
  --proxy "http://127.0.0.1:8080"
```

### Custom Payloads with Encoding
```bash
# Use custom payloads
xsshunt "https://target.com/page?id=1" -p payloads.txt

# Apply encoding to custom payloads
xsshunt "https://target.com/page?id=1" -p payloads.txt --encode
```

### Full Audit
```bash
xsshunt "https://target.com/page?id=1" --ssti --open-redirect
```

### Header Fuzzing
```bash
xsshunt "https://api.target.com/v1" -H "User-Agent: FUZZ" -H "X-Forwarded-For: FUZZ"
```

### Batch Scan
```bash
xsshunt -l urls.txt -o report.html --format html -t 10
```

---

## ⚙️ Options

| Flag | Description | Default |
|------|-------------|---------|
| `[url]` | Target URL to scan | - |
| `-l, --list` | File containing URLs | - |
| `-p, --payloads` | Custom payload file | - |
| `--encode` | Apply encoding to custom payloads | `false` |
| `-c, --cookie` | Session cookies | - |
| `--auth` | Authorization header | - |
| `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) | - |
| `-t, --threads` | Concurrent threads | `5` |
| `--timeout` | Request timeout (seconds) | `30` |
| `--delay` | Request delay (ms) | `0` |
| `-w, --waf` | Target WAF type | `auto` |
| `--format` | Report format (`json`, `html`) | `json` |
| `-o, --output` | Output file path | - |
| `-v, --visible` | Visible browser mode | `false` |
| `--verbose` | Verbose logging | `false` |
| `--kxss` | KXSS mode (smart detection) | `true` |
| `--gxss` | GXSS mode (payload testing) | `true` |
| `--ssti` | Scan for SSTI | `false` |
| `--open-redirect` | Scan for Open Redirect | `false` |
| `--strict` | Strict verification (alert required) | `false` |
| `--static-only` | Static analysis only (no browser) | `false` |

---

## 🔧 Architecture

```
xsshunt/
├── cmd/xsshunt/          # CLI entry point
├── internal/
│   ├── cli/              # Command-line interface
│   ├── scanner/          # Core scanning engine
│   │   ├── scanner.go    # Main scanner
│   │   ├── kxss.go       # KXSS reflection detector
│   │   ├── gxss.go       # GXSS payload tester
│   │   ├── analysis.go   # Context analysis
│   │   └── strategy.go   # Verification strategies
│   ├── payloads/         # Payload generation
│   │   ├── generator.go  # Smart payload generator
│   │   ├── encoder.go    # Encoding engine
│   │   └── obfuscator.go # Obfuscation engine
│   ├── waf/              # WAF detection & bypass
│   └── report/           # Report generation
└── README.md
```

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security testing only**. Usage on targets without explicit permission is illegal. The developer assumes no liability for misuse.

---

<div align="center">
  <sub>Made with ❤️ by <a href="https://github.com/Serdar715">Serdar715</a></sub>
</div>
