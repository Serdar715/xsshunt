<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blueviolet?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars/At0m1/xsshunt?style=for-the-badge&color=yellow" alt="Stars">
</p>

<h1 align="center">
  <br>
  🕵️ XSSHunt
  <br>
</h1>

<h4 align="center">Advanced Cross-Site Scripting (XSS) Scanner with WAF Bypass Capabilities</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#waf-bypass">WAF Bypass</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## 📖 About

**XSSHunt** is a powerful, fast, and comprehensive XSS vulnerability scanner written in Go. It utilizes headless browser technology (Chromedp) to accurately detect both **Reflected XSS** and **DOM-based XSS** vulnerabilities. The tool includes advanced WAF bypass techniques and generates professional reports.

> 🔄 This project is a Go port of [HackUnderway/xss_scanner](https://github.com/HackUnderway/xss_scanner)

---

## ✨ Features

### 🎯 Detection Capabilities
| Feature | Description |
|---------|-------------|
| **Reflected XSS** | Detects payloads reflected in HTTP responses |
| **DOM-based XSS** | Uses real browser to detect JavaScript execution |
| **Context-Aware** | Identifies injection context (HTML, JS, attribute, URL) |
| **Smart Payloads** | Dynamically generates context-specific payloads |

### 🛡️ WAF Bypass Support
- ☁️ **Cloudflare**
- 🔵 **Akamai**
- 🌐 **AWS CloudFront**
- 🔒 **Imperva / Incapsula**
- 🛡️ **Wordfence**
- ⚙️ **ModSecurity**
- 🌿 **Sucuri**
- 🔷 **F5 BIG-IP ASM**
- 📦 **Barracuda**

### 📊 Reporting
- 📄 **JSON** - Machine-readable format for automation
- 🌐 **HTML** - Beautiful, interactive reports with modern UI
- 📋 Detailed vulnerability information with exploitation URLs

### ⚡ Performance
- 🚀 Concurrent scanning with configurable threads
- 🎭 Headless browser for accurate DOM testing
- ⏱️ Configurable timeouts
- 🔄 Automatic WAF detection

---

## 📦 Installation

### Prerequisites
- **Go 1.21+** - [Download Go](https://golang.org/dl/)
- **Chrome/Chromium** - Required for headless browser testing

### Quick Install

```bash
# Clone the repository
git clone https://github.com/At0m1/xsshunt.git
cd xsshunt

# Download dependencies
go mod tidy

# Build
make build

# Or build directly
go build -o xsshunt ./cmd/xsshunt

# Install system-wide (optional)
sudo make install
```

### Install Chrome/Chromium

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y chromium-browser

# Arch Linux
sudo pacman -S chromium

# Fedora
sudo dnf install chromium

# macOS
brew install --cask chromium
```

### One-liner Install

```bash
go install github.com/At0m1/xsshunt/cmd/xsshunt@latest
```

---

## 🚀 Usage

### Basic Scan

```bash
# Simple scan with auto WAF detection
xsshunt "https://target.com/search?q="

# Scan with verbose output
xsshunt "https://target.com/search?q=" --verbose
```

### WAF-Specific Scan

```bash
# Target behind Cloudflare
xsshunt "https://target.com/search?q=" -w cloudflare

# Target behind Akamai
xsshunt "https://target.com/search?q=" -w akamai

# Auto-detect WAF
xsshunt "https://target.com/search?q=" -w auto
```

### Advanced Options

```bash
# Custom payload file
xsshunt "https://target.com/search?q=" -p custom_payloads.txt

# Visible browser mode (for debugging)
xsshunt "https://target.com/search?q=" -v

# Multi-threaded scan
xsshunt "https://target.com/search?q=" -t 10

# Generate HTML report
xsshunt "https://target.com/search?q=" -o report.html --format html

# Generate JSON report
xsshunt "https://target.com/search?q=" -o report.json --format json
```

### All Options

```
Usage:
  xsshunt [target_url] [flags]

Flags:
  -p, --payloads string   Custom payload file path
  -v, --visible           Run browser in visible mode
  -w, --waf string        WAF type: auto, cloudflare, akamai, cloudfront,
                          imperva, wordfence, modsecurity, sucuri, f5 (default "auto")
      --no-smart          Disable smart payload generation
      --format string     Output format: json, html (default "json")
  -o, --output string     Output file for report
  -t, --threads int       Number of concurrent threads (default 5)
      --timeout int       Request timeout in seconds (default 30)
      --verbose           Enable verbose output
  -h, --help              Show help message
```

---

## 🛡️ WAF Bypass

XSSHunt includes specialized payloads designed to bypass common Web Application Firewalls:

### Bypass Techniques Used

| WAF | Techniques |
|-----|------------|
| **Cloudflare** | HTML entity encoding, Unicode escapes, eval obfuscation |
| **Akamai** | Case variation, null bytes, alternative event handlers |
| **CloudFront** | String.fromCharCode, template literals, regex tricks |
| **Imperva** | Comment injection, constructor chains, form actions |
| **ModSecurity** | Hex encoding, Unicode, base64 eval |

### Example Bypass Payloads

```html
<!-- Cloudflare Bypass -->
<svg/onload=&#97&#108&#101&#114&#116(1)>
<svg onload=eval(atob('YWxlcnQoMSk='))>

<!-- Akamai Bypass -->
<body/onload=alert(1)>
<input/onfocus=alert(1) autofocus>

<!-- Generic Bypass -->
<script>onerror=alert;throw 1</script>
```

---

## 🧪 Testing

### Safe Testing Targets

```bash
# Acunetix Test Site (Intentionally Vulnerable)
xsshunt "https://testphp.vulnweb.com/artists.php?artist="

# PortSwigger XSS Labs
xsshunt "https://portswigger-labs.net/xss/xss.php?x="

# OWASP WebGoat (Local)
xsshunt "http://localhost:8080/WebGoat/start.mvc?param="
```

---

## 📁 Project Structure

```
xsshunt/
├── cmd/
│   └── xsshunt/
│       └── main.go              # Entry point
├── internal/
│   ├── banner/
│   │   └── banner.go            # ASCII art banner
│   ├── cli/
│   │   └── cli.go               # CLI argument handling
│   ├── config/
│   │   └── config.go            # Configuration structures
│   ├── payloads/
│   │   └── generator.go         # Payload generation & WAF bypass
│   ├── report/
│   │   └── report.go            # Report generation (JSON/HTML)
│   ├── scanner/
│   │   └── scanner.go           # Core scanning engine
│   └── waf/
│       └── detector.go          # WAF detection module
├── Makefile                     # Build automation
├── go.mod
├── go.sum
└── README.md
```

---

## 🔧 Build Options

```bash
# Build for current platform
make build

# Build for Linux (amd64 & arm64)
make build-linux

# Build for Windows
make build-windows

# Build for macOS
make build-darwin

# Build for all platforms
make build-all

# Clean build artifacts
make clean
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**. 

✅ **Allowed Use:**
- Your own systems and applications
- Systems you have explicit written permission to test
- Bug bounty programs where you are authorized
- Educational and research purposes in controlled environments

❌ **Prohibited Use:**
- Unauthorized testing of third-party systems
- Any use that violates applicable laws
- Malicious activities

**The developers assume no liability for misuse of this tool.**

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- Original Python project: [HackUnderway/xss_scanner](https://github.com/HackUnderway/xss_scanner)
- [chromedp](https://github.com/chromedp/chromedp) - Headless Chrome
- [cobra](https://github.com/spf13/cobra) - CLI Framework
- [color](https://github.com/fatih/color) - Terminal Colors

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/At0m1">@At0m1</a>
</p>
