// Package scanner - Vulnerability reporting abstraction
package scanner

import (
	"fmt"
	"sync"

	"github.com/Serdar715/xsshunt/internal/config"
	"github.com/fatih/color"
)

// VulnReporter defines the interface for vulnerability reporting.
// This abstraction allows for different output formats and destinations.
type VulnReporter interface {
	// Report outputs a vulnerability finding
	Report(vuln *config.Vulnerability, count int)
	// ReportSummary outputs a summary of all findings
	ReportSummary(total, verified, unverified int)
	// SetVerbose enables or disables verbose output
	SetVerbose(verbose bool)
}

// ConsoleReporter implements VulnReporter for terminal output.
// Thread-safe for concurrent reporting.
type ConsoleReporter struct {
	mu      sync.Mutex
	verbose bool
}

// NewConsoleReporter creates a new console-based reporter.
func NewConsoleReporter(verbose bool) *ConsoleReporter {
	return &ConsoleReporter{
		verbose: verbose,
	}
}

// SetVerbose enables or disables verbose output.
func (r *ConsoleReporter) SetVerbose(verbose bool) {
	r.mu.Lock()
	r.verbose = verbose
	r.mu.Unlock()
}

// Report outputs a vulnerability to the console.
// Thread-safe - multiple goroutines can call this safely.
func (r *ConsoleReporter) Report(vuln *config.Vulnerability, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Header
	color.Red("\n  ╔══════════════════════════════════════════════════════════╗")
	color.Red("  ║  🔴 XSS VULNERABILITY FOUND! (#%d)                        ║", count)
	color.Red("  ╚══════════════════════════════════════════════════════════╝")

	// Details
	color.Yellow("  Type:      %s", vuln.Type)
	color.White("  Severity:  %s", r.colorSeverity(vuln.Severity))
	color.White("  Parameter: %s", vuln.Parameter)
	color.White("  Context:   %s", vuln.Context)

	// Verification status
	if vuln.Verified {
		color.Green("  Verified:  ✅ YES (Method: %s)", vuln.Method)
	} else {
		color.Yellow("  Verified:  ⚠️ NO (Reflection Only) - Check Manually")
	}

	// WAF bypass indicator
	if vuln.WAFBypassed {
		color.Magenta("  WAF:       🛡️ Bypassed!")
	}

	fmt.Println()
	color.Cyan("  Payload: %s", r.truncatePayload(vuln.Payload))
	color.Cyan("  PoC URL: %s", vuln.URL)

	// Verbose: show evidence
	if r.verbose && vuln.Evidence != "" {
		color.White("  Evidence: %s", vuln.Evidence)
	}

	fmt.Println()
}

// ReportSummary outputs a summary of all findings.
func (r *ConsoleReporter) ReportSummary(total, verified, unverified int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Println()
	color.Cyan("═══════════════════════════════════════════════════════════")
	color.Cyan("                    SCAN SUMMARY")
	color.Cyan("═══════════════════════════════════════════════════════════")

	if total == 0 {
		color.Green("  ✓ No vulnerabilities found")
	} else {
		color.Red("  Total Vulnerabilities: %d", total)
		if verified > 0 {
			color.Red("    ✓ Verified (Critical): %d", verified)
		}
		if unverified > 0 {
			color.Yellow("    ⚠ Unverified (Medium): %d", unverified)
		}
	}

	color.Cyan("═══════════════════════════════════════════════════════════")
	fmt.Println()
}

// colorSeverity returns a colored severity string.
func (r *ConsoleReporter) colorSeverity(severity string) string {
	switch severity {
	case SeverityCritical:
		return color.RedString(severity)
	case SeverityHigh:
		return color.RedString(severity)
	case SeverityMedium:
		return color.YellowString(severity)
	case SeverityLow:
		return color.WhiteString(severity)
	default:
		return severity
	}
}

// truncatePayload truncates long payloads for display.
func (r *ConsoleReporter) truncatePayload(payload string) string {
	const maxPayloadDisplay = 100
	if len(payload) <= maxPayloadDisplay {
		return payload
	}
	return payload[:maxPayloadDisplay] + "..."
}

// JSONReporter implements VulnReporter for JSON output (future extension).
type JSONReporter struct {
	mu      sync.Mutex
	vulns   []config.Vulnerability
	verbose bool
}

// NewJSONReporter creates a new JSON-based reporter.
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{
		vulns: make([]config.Vulnerability, 0),
	}
}

// SetVerbose enables or disables verbose output.
func (r *JSONReporter) SetVerbose(verbose bool) {
	r.mu.Lock()
	r.verbose = verbose
	r.mu.Unlock()
}

// Report collects a vulnerability for JSON output.
func (r *JSONReporter) Report(vuln *config.Vulnerability, count int) {
	r.mu.Lock()
	r.vulns = append(r.vulns, *vuln)
	r.mu.Unlock()
}

// ReportSummary outputs nothing for JSON (summary is in the final output).
func (r *JSONReporter) ReportSummary(total, verified, unverified int) {
	// JSON reporter doesn't print summary - it's included in the final JSON
}

// GetVulnerabilities returns collected vulnerabilities.
func (r *JSONReporter) GetVulnerabilities() []config.Vulnerability {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	result := make([]config.Vulnerability, len(r.vulns))
	copy(result, r.vulns)
	return result
}

// SilentReporter implements VulnReporter that produces no output.
// Useful for batch processing or testing.
type SilentReporter struct {
	vulns []config.Vulnerability
	mu    sync.Mutex
}

// NewSilentReporter creates a new silent reporter.
func NewSilentReporter() *SilentReporter {
	return &SilentReporter{
		vulns: make([]config.Vulnerability, 0),
	}
}

// SetVerbose does nothing for silent reporter.
func (r *SilentReporter) SetVerbose(verbose bool) {}

// Report silently collects the vulnerability.
func (r *SilentReporter) Report(vuln *config.Vulnerability, count int) {
	r.mu.Lock()
	r.vulns = append(r.vulns, *vuln)
	r.mu.Unlock()
}

// ReportSummary does nothing for silent reporter.
func (r *SilentReporter) ReportSummary(total, verified, unverified int) {}

// Count returns the number of collected vulnerabilities.
func (r *SilentReporter) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.vulns)
}
