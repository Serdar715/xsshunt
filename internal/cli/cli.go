package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Serdar715/xsshunt/internal/banner"
	"github.com/Serdar715/xsshunt/internal/config"
	"github.com/Serdar715/xsshunt/internal/report"
	"github.com/Serdar715/xsshunt/internal/scanner"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Target options
	urlListFile string

	// Payload options
	payloadFile string
	noSmart     bool

	// Browser options
	visibleMode bool
	timeout     int

	// WAF options
	wafType string

	// Output options
	outputFormat string
	outputFile   string
	verbose      bool

	// Performance options
	threads int
	delay   int

	// Proxy options
	proxyURL string

	// Authentication options
	cookies     string
	authHeader  string
	headersFile string
	cookieFile  string

	// Header Fuzzing options
	fuzzHeaders []string

	// Blind XSS options
	blindCallback string

	// Additional vulnerability scanning (Dalfox-inspired)
	scanSSTI         bool
	scanOpenRedirect bool
	checkSecHeaders  bool

	// Advanced options
	fuzzyMatching  bool
	fuzzyThreshold float64
	storedXSS      bool
	domDeepScan    bool
)

func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "xsshunt [target_url]",
		Short: "🕵️ Advanced XSS Scanner Tool v2.0",
		Long: banner.GetBanner() + `
XSSHunt - Advanced Cross-Site Scripting Scanner

An advanced XSS scanning tool for web security audits with WAF bypass 
capabilities and comprehensive reporting.

Features:
  • DOM-based XSS detection
  • Reflected XSS detection  
  • WAF bypass techniques (Cloudflare, Akamai, Cloudfront, Imperva, etc.)
  • Smart payload generation
  • Header fuzzing with FUZZ marker
  • Proxy support (Burp Suite, OWASP ZAP)
  • Cookie/Header authentication
  • Batch URL scanning
  • Rate limiting
  • Comprehensive reporting (HTML, JSON)
`,
		Example: `  # Basic GET scan
  xsshunt "https://example.com/search?q="

  # Specify WAF type
  xsshunt "https://example.com/search?q=" -w cloudflare

  # Visible browser mode
  xsshunt "https://example.com/search?q=" -v

  # Scan through proxy (Burp Suite)
  xsshunt "https://example.com/search?q=" --proxy http://127.0.0.1:8080

  # Authenticated scan with cookies
  xsshunt "https://example.com/search?q=" -c "session=abc123; token=xyz"

  # Authenticated scan with Authorization header
  xsshunt "https://example.com/search?q=" --auth "Bearer eyJhbGc..."

  # Header fuzzing - inject payloads into custom header
  xsshunt "https://example.com/api" -H "X-Custom-Header: FUZZ"
  xsshunt "https://example.com/api" -H "X-Forwarded-For: FUZZ" -H "User-Agent: FUZZ"

  # Batch scan from URL list
  xsshunt -l urls.txt -o report.html --format html

  # Rate limited scan (500ms delay between requests)
  xsshunt "https://example.com/search?q=" --delay 500

  # Full featured scan
  xsshunt "https://example.com/search?q=" \
    --proxy http://127.0.0.1:8080 \
    -c "session=abc123" \
    --auth "Bearer token" \
    -H "X-Custom: FUZZ" \
    -t 10 \
    --delay 500 \
    -o report.html --format html`,
		Args: cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Check if we have a target URL, URL list file, or header fuzzing mode
			hasFuzzHeaders := len(fuzzHeaders) > 0 && containsFuzzMarker(fuzzHeaders)

			if len(args) == 0 && urlListFile == "" {
				return fmt.Errorf("either a target URL or a URL list file (-l) must be provided")
			}

			// Validate target URL if provided (skip param check for header fuzzing mode)
			if len(args) > 0 && !hasFuzzHeaders {
				targetURL := args[0]
				if !strings.Contains(targetURL, "?") || !strings.Contains(targetURL, "=") {
					return fmt.Errorf("target URL must contain injection parameters (e.g., ?param=) or use header fuzzing (-H)")
				}
			}

			// Validate URL list file if provided
			if urlListFile != "" {
				if _, err := os.Stat(urlListFile); os.IsNotExist(err) {
					return fmt.Errorf("URL list file not found: %s", urlListFile)
				}
			}

			// Validate WAF type
			validWAFs := []string{"auto", "cloudflare", "akamai", "cloudfront", "imperva", "incapsula", "wordfence", "modsecurity", "sucuri", "f5", "barracuda"}
			if wafType != "" {
				found := false
				for _, w := range validWAFs {
					if strings.EqualFold(wafType, w) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("invalid WAF type: %s. Valid types: %s", wafType, strings.Join(validWAFs, ", "))
				}
			}

			// Validate proxy URL format
			if proxyURL != "" {
				if !strings.HasPrefix(proxyURL, "http://") && !strings.HasPrefix(proxyURL, "https://") && !strings.HasPrefix(proxyURL, "socks5://") {
					return fmt.Errorf("invalid proxy URL format. Use http://, https://, or socks5:// prefix")
				}
			}

			// Validate headers file if provided
			if headersFile != "" {
				if _, err := os.Stat(headersFile); os.IsNotExist(err) {
					return fmt.Errorf("headers file not found: %s", headersFile)
				}
			}

			// Validate cookie file if provided
			if cookieFile != "" {
				if _, err := os.Stat(cookieFile); os.IsNotExist(err) {
					return fmt.Errorf("cookie file not found: %s", cookieFile)
				}
			}

			// Validate fuzz headers format
			for _, h := range fuzzHeaders {
				if !strings.Contains(h, ":") {
					return fmt.Errorf("invalid header format: %s (expected 'Header-Name: value')", h)
				}
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Print banner
			fmt.Println(banner.GetBanner())

			// Collect target URLs
			var targetURLs []string

			// Add single target if provided
			if len(args) > 0 {
				targetURLs = append(targetURLs, args[0])
			}

			// Load URLs from file if provided
			if urlListFile != "" {
				urls, err := loadURLsFromFile(urlListFile)
				if err != nil {
					return fmt.Errorf("failed to load URL list: %w", err)
				}
				targetURLs = append(targetURLs, urls...)
				color.Cyan("[*] Loaded %d URLs from %s", len(urls), urlListFile)
			}

			// Parse custom headers
			customHeaders := make(map[string]string)

			// Add Authorization header if provided
			if authHeader != "" {
				customHeaders["Authorization"] = authHeader
			}

			// Load headers from file if provided
			if headersFile != "" {
				headers, err := loadHeadersFromFile(headersFile)
				if err != nil {
					return fmt.Errorf("failed to load headers file: %w", err)
				}
				for k, v := range headers {
					customHeaders[k] = v
				}
			}

			// Load cookies from file if provided
			if cookieFile != "" {
				cookieValue, err := loadCookiesFromFile(cookieFile)
				if err != nil {
					return fmt.Errorf("failed to load cookie file: %w", err)
				}
				if cookies != "" {
					cookies = cookies + "; " + cookieValue
				} else {
					cookies = cookieValue
				}
			}

			// Check if header fuzzing mode is enabled
			hasFuzzHeaders := len(fuzzHeaders) > 0 && containsFuzzMarker(fuzzHeaders)

			// Create scanner config
			cfg := &config.ScanConfig{
				TargetURL:        targetURLs[0],
				TargetURLs:       targetURLs,
				URLListFile:      urlListFile,
				PayloadFile:      payloadFile,
				VisibleMode:      visibleMode,
				WAFType:          wafType,
				SmartPayload:     !noSmart,
				OutputFormat:     outputFormat,
				OutputFile:       outputFile,
				Threads:          threads,
				Timeout:          timeout,
				Verbose:          verbose,
				ProxyURL:         proxyURL,
				ProxyEnabled:     proxyURL != "",
				Cookies:          cookies,
				Headers:          customHeaders,
				AuthHeader:       authHeader,
				Delay:            delay,
				FuzzHeaders:      fuzzHeaders,
				FuzzMode:         hasFuzzHeaders,
				BlindXSSCallback: blindCallback,
				BlindXSSEnabled:  blindCallback != "",
				ScanSSTI:         scanSSTI,
				ScanOpenRedirect: scanOpenRedirect,
				CheckSecHeaders:  checkSecHeaders,
				FuzzyMatching:    fuzzyMatching,
				FuzzyThreshold:   fuzzyThreshold,
				StoredXSS:        storedXSS,
				DOMDeepScan:      domDeepScan,
			}

			// Print configuration summary
			printConfigSummary(cfg, len(targetURLs))

			// Process each URL
			var allResults []*config.ScanResult

			for i, targetURL := range targetURLs {
				if len(targetURLs) > 1 {
					color.Cyan("\n[*] Scanning URL %d/%d: %s", i+1, len(targetURLs), truncateURL(targetURL, 60))
				} else {
					color.Cyan("\n[*] Starting XSS scan on: %s\n", targetURL)
				}

				// Update config with current URL
				cfg.TargetURL = targetURL

				// Initialize scanner
				xssScanner, err := scanner.New(cfg)
				if err != nil {
					color.Red("[!] Failed to initialize scanner for %s: %v", truncateURL(targetURL, 40), err)
					continue
				}

				// Run scan
				results, err := xssScanner.Scan()
				xssScanner.Close()

				if err != nil {
					color.Red("[!] Scan failed for %s: %v", truncateURL(targetURL, 40), err)
					continue
				}

				allResults = append(allResults, results)

				// Print results for this URL
				if len(results.Vulnerabilities) > 0 {
					color.Red("\n[!] Found %d XSS vulnerabilities!", len(results.Vulnerabilities))
					printVulnerabilities(results.Vulnerabilities)
				} else {
					color.Green("\n[✓] No XSS vulnerabilities found.")
				}
			}

			// Merge results if batch mode
			finalResults := mergeResults(allResults, targetURLs)

			// Print summary
			printSummary(finalResults, len(targetURLs))

			// Save report if output file specified
			if outputFile != "" {
				reporter := report.New(outputFormat)
				if err := reporter.Generate(finalResults, outputFile); err != nil {
					return fmt.Errorf("failed to generate report: %w", err)
				}
				color.Green("\n[✓] Report saved to: %s\n", outputFile)
			}

			return nil
		},
	}

	// Target flags
	rootCmd.Flags().StringVarP(&urlListFile, "list", "l", "", "File containing URLs to scan (one per line)")

	// Payload flags
	rootCmd.Flags().StringVarP(&payloadFile, "payloads", "p", "", "Custom payload file to use")
	rootCmd.Flags().BoolVar(&noSmart, "no-smart", false, "Disable smart payload generation")

	// Browser flags
	rootCmd.Flags().BoolVarP(&visibleMode, "visible", "v", false, "Run browser in visible mode")
	rootCmd.Flags().IntVar(&timeout, "timeout", 30, "Request timeout in seconds")

	// WAF flags
	rootCmd.Flags().StringVarP(&wafType, "waf", "w", "auto", "WAF type (auto, cloudflare, akamai, cloudfront, imperva, incapsula, wordfence, modsecurity, sucuri, f5, barracuda)")

	// Output flags
	rootCmd.Flags().StringVar(&outputFormat, "format", "json", "Output format (json, html)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for report")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	// Performance flags
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 5, "Number of concurrent threads")
	rootCmd.Flags().IntVar(&delay, "delay", 0, "Delay between requests in milliseconds (rate limiting)")

	// Proxy flags
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)")

	// Authentication flags
	rootCmd.Flags().StringVarP(&cookies, "cookie", "c", "", "Cookie header value (e.g., \"session=abc123; token=xyz\")")
	rootCmd.Flags().StringVar(&authHeader, "auth", "", "Authorization header value (e.g., \"Bearer eyJhbGc...\")")
	rootCmd.Flags().StringVar(&headersFile, "headers-file", "", "File containing custom headers (key: value format)")
	rootCmd.Flags().StringVar(&cookieFile, "cookie-file", "", "File containing cookies (name=value format, one per line)")

	// Header Fuzzing flags
	rootCmd.Flags().StringArrayVarP(&fuzzHeaders, "header", "H", []string{}, "Header to fuzz with FUZZ marker (e.g., \"X-Custom: FUZZ\"). Can be used multiple times.")

	// Blind XSS flags
	rootCmd.Flags().StringVar(&blindCallback, "blind-callback", "", "Callback URL for blind XSS detection (e.g., yourserver.xsshunter.com)")

	// Additional vulnerability scanning flags (Dalfox-inspired)
	rootCmd.Flags().BoolVar(&scanSSTI, "ssti", false, "Also scan for Server Side Template Injection (SSTI)")
	rootCmd.Flags().BoolVar(&scanOpenRedirect, "open-redirect", false, "Also scan for Open Redirect vulnerabilities")
	rootCmd.Flags().BoolVar(&checkSecHeaders, "check-headers", true, "Check security headers (CSP, X-Frame-Options, etc.)")

	// Advanced options flags
	rootCmd.Flags().BoolVar(&fuzzyMatching, "fuzzy", true, "Enable fuzzy matching for payload detection (XSStrike-style)")
	rootCmd.Flags().Float64Var(&fuzzyThreshold, "fuzzy-threshold", 0.8, "Threshold for fuzzy matching (0.0-1.0)")
	rootCmd.Flags().BoolVar(&storedXSS, "stored", false, "Enable stored XSS testing mode")
	rootCmd.Flags().BoolVar(&domDeepScan, "dom-deep", true, "Enable deep DOM analysis")

	return rootCmd.Execute()
}

// containsFuzzMarker checks if any header contains the FUZZ marker
func containsFuzzMarker(headers []string) bool {
	for _, h := range headers {
		if strings.Contains(h, "FUZZ") {
			return true
		}
	}
	return false
}

// loadURLsFromFile loads URLs from a file (one per line)
func loadURLsFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid URLs found in file")
	}

	return urls, nil
}

// loadHeadersFromFile loads headers from a file (key: value format)
func loadHeadersFromFile(filepath string) (map[string]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	headers := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				headers[key] = value
			}
		}
	}

	return headers, scanner.Err()
}

// loadCookiesFromFile loads cookies from a file (name=value format)
func loadCookiesFromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var cookies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			// Support both "name=value" and "name: value" formats
			if strings.Contains(line, "=") || strings.Contains(line, ":") {
				// Normalize to name=value format
				line = strings.Replace(line, ": ", "=", 1)
				cookies = append(cookies, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return strings.Join(cookies, "; "), nil
}

// printConfigSummary prints the scan configuration
func printConfigSummary(cfg *config.ScanConfig, urlCount int) {
	color.Yellow("\n┌─────────────────────────────────────────────────┐")
	color.Yellow("│              SCAN CONFIGURATION                 │")
	color.Yellow("└─────────────────────────────────────────────────┘")

	if urlCount > 1 {
		color.White("  📋 Mode:        Batch Scan (%d URLs)", urlCount)
	} else if cfg.FuzzMode {
		color.White("  📋 Mode:        Header Fuzzing")
	} else {
		color.White("  📋 Mode:        Single URL Scan")
	}

	color.White("  🧵 Threads:     %d", cfg.Threads)
	color.White("  ⏱️  Timeout:     %ds", cfg.Timeout)

	if cfg.Delay > 0 {
		color.White("  ⏳ Delay:       %dms (rate limiting)", cfg.Delay)
	}

	if cfg.ProxyEnabled {
		color.White("  🔀 Proxy:       %s", cfg.ProxyURL)
	}

	if cfg.Cookies != "" {
		color.White("  🍪 Cookies:     %s", truncateURL(cfg.Cookies, 30))
	}

	if cfg.AuthHeader != "" {
		color.White("  🔑 Auth:        %s", truncateURL(cfg.AuthHeader, 30))
	}

	if len(cfg.Headers) > 0 {
		color.White("  📝 Headers:     %d custom header(s)", len(cfg.Headers))
	}

	if cfg.FuzzMode {
		color.White("  🎯 Fuzz Headers:")
		for _, h := range cfg.FuzzHeaders {
			if strings.Contains(h, "FUZZ") {
				color.Cyan("      - %s", h)
			}
		}
	}

	color.Yellow("─────────────────────────────────────────────────")
}

// printVulnerabilities prints vulnerability details
func printVulnerabilities(vulns []config.Vulnerability) {
	for i, vuln := range vulns {
		fmt.Printf("\n%s Vulnerability #%d %s\n",
			color.RedString("════════════════════════════════════════"),
			i+1,
			color.RedString("════════════════════════════════════════"))
		fmt.Printf("  Type:     %s\n", color.YellowString(vuln.Type))
		fmt.Printf("  Payload:  %s\n", color.CyanString(vuln.Payload))
		fmt.Printf("  URL:      %s\n", vuln.URL)
		fmt.Printf("  Context:  %s\n", vuln.Context)
		fmt.Printf("  Severity: %s\n", getSeverityColor(vuln.Severity))
	}
}

// printSummary prints the final scan summary
func printSummary(results *config.ScanResult, urlCount int) {
	color.Yellow("\n┌─────────────────────────────────────────────────┐")
	color.Yellow("│                 SCAN SUMMARY                    │")
	color.Yellow("└─────────────────────────────────────────────────┘")

	if urlCount > 1 {
		color.White("  📊 URLs Scanned:      %d", urlCount)
	}

	color.White("  🎯 Payloads Tested:   %d", results.TestedPayloads)
	color.White("  ⏱️  Duration:          %s", results.ScanDuration)

	if results.WAFDetected != "" {
		color.Yellow("  🛡️  WAF Detected:      %s", results.WAFDetected)
	}

	if len(results.Vulnerabilities) > 0 {
		color.Red("  ⚠️  Vulnerabilities:   %d FOUND", len(results.Vulnerabilities))
	} else {
		color.Green("  ✅ Vulnerabilities:   0 (Clean)")
	}

	if results.ErrorCount > 0 {
		color.Yellow("  ❌ Errors:            %d", results.ErrorCount)
	}

	color.Yellow("─────────────────────────────────────────────────")
}

// mergeResults merges multiple scan results into one
func mergeResults(results []*config.ScanResult, targetURLs []string) *config.ScanResult {
	if len(results) == 0 {
		return &config.ScanResult{}
	}

	if len(results) == 1 {
		return results[0]
	}

	merged := &config.ScanResult{
		TargetURL:       targetURLs[0],
		TargetURLs:      targetURLs,
		ScanStartTime:   results[0].ScanStartTime,
		ScanEndTime:     results[len(results)-1].ScanEndTime,
		Vulnerabilities: make([]config.Vulnerability, 0),
		Errors:          make([]string, 0),
		TotalURLs:       len(targetURLs),
		ScannedURLs:     len(results),
	}

	for _, result := range results {
		merged.TotalPayloads += result.TotalPayloads
		merged.TestedPayloads += result.TestedPayloads
		merged.ErrorCount += result.ErrorCount
		merged.Vulnerabilities = append(merged.Vulnerabilities, result.Vulnerabilities...)
		merged.Errors = append(merged.Errors, result.Errors...)

		if result.WAFDetected != "" && merged.WAFDetected == "" {
			merged.WAFDetected = result.WAFDetected
		}
	}

	merged.ScanDuration = merged.ScanEndTime.Sub(merged.ScanStartTime).String()

	return merged
}

func getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint(severity)
	case "high":
		return color.RedString(severity)
	case "medium":
		return color.YellowString(severity)
	case "low":
		return color.CyanString(severity)
	default:
		return severity
	}
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen] + "..."
}

func init() {
	// Disable color if not a terminal
	if os.Getenv("NO_COLOR") != "" {
		color.NoColor = true
	}
}
