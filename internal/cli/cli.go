package cli

import (
	"fmt"
	"os"
	"strings"

	"xsshunt/internal/banner"
	"xsshunt/internal/config"
	"xsshunt/internal/report"
	"xsshunt/internal/scanner"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	payloadFile  string
	visibleMode  bool
	wafType      string
	noSmart      bool
	outputFormat string
	outputFile   string
	threads      int
	timeout      int
	verbose      bool
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
  • Context-aware payloads
  • Comprehensive reporting (HTML, JSON, PDF)
`,
		Example: `  # Basic GET scan
  xsshunt "https://example.com/search?q="

  # Specify WAF type
  xsshunt "https://example.com/search?q=" -w cloudflare

  # Visible browser mode
  xsshunt "https://example.com/search?q=" -v

  # Custom payload file
  xsshunt "https://example.com/search?q=" -p payloads/custom.txt

  # Generate HTML report
  xsshunt "https://example.com/search?q=" -o report.html --format html`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]

			// Validate URL contains injection point
			if !strings.Contains(targetURL, "?") || !strings.Contains(targetURL, "=") {
				return fmt.Errorf("target URL must contain injection parameters (e.g., ?param=)")
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

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]

			// Print banner
			fmt.Println(banner.GetBanner())

			// Create scanner config
			cfg := &config.ScanConfig{
				TargetURL:    targetURL,
				PayloadFile:  payloadFile,
				VisibleMode:  visibleMode,
				WAFType:      wafType,
				SmartPayload: !noSmart,
				OutputFormat: outputFormat,
				OutputFile:   outputFile,
				Threads:      threads,
				Timeout:      timeout,
				Verbose:      verbose,
			}

			// Initialize scanner
			xssScanner, err := scanner.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize scanner: %w", err)
			}
			defer xssScanner.Close()

			// Run scan
			color.Cyan("\n[*] Starting XSS scan on: %s\n", targetURL)

			results, err := xssScanner.Scan()
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Generate report
			if len(results.Vulnerabilities) > 0 {
				color.Red("\n[!] Found %d XSS vulnerabilities!\n", len(results.Vulnerabilities))

				for i, vuln := range results.Vulnerabilities {
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
			} else {
				color.Green("\n[✓] No XSS vulnerabilities found.\n")
			}

			// Save report if output file specified
			if outputFile != "" {
				reporter := report.New(outputFormat)
				if err := reporter.Generate(results, outputFile); err != nil {
					return fmt.Errorf("failed to generate report: %w", err)
				}
				color.Green("\n[✓] Report saved to: %s\n", outputFile)
			}

			return nil
		},
	}

	// Flags
	rootCmd.Flags().StringVarP(&payloadFile, "payloads", "p", "", "Custom payload file to use")
	rootCmd.Flags().BoolVarP(&visibleMode, "visible", "v", false, "Run browser in visible mode")
	rootCmd.Flags().StringVarP(&wafType, "waf", "w", "auto", "WAF type (auto, cloudflare, akamai, cloudfront, imperva, incapsula, wordfence, modsecurity, sucuri, f5, barracuda)")
	rootCmd.Flags().BoolVar(&noSmart, "no-smart", false, "Disable smart payload generation")
	rootCmd.Flags().StringVar(&outputFormat, "format", "json", "Output format (json, html, pdf)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for report")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 5, "Number of concurrent threads")
	rootCmd.Flags().IntVar(&timeout, "timeout", 30, "Request timeout in seconds")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	return rootCmd.Execute()
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

func init() {
	// Disable color if not a terminal
	if os.Getenv("NO_COLOR") != "" {
		color.NoColor = true
	}
}
