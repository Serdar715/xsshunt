package config

import (
	"time"
)

// ScanConfig holds all configuration for an XSS scan
type ScanConfig struct {
	// Target configuration
	TargetURL   string   // Single target URL
	TargetURLs  []string // Multiple target URLs (batch mode)
	URLListFile string   // File containing URLs to scan

	// Payload configuration
	PayloadFile  string
	SmartPayload bool

	// Browser configuration
	VisibleMode bool
	Timeout     int // Request timeout in seconds

	// Browser wait times (configurable)
	BrowserWaitTime int // Time to wait for page stability in ms (default 1500)
	NavigationDelay int // Time to wait for navigation in ms (default 500)

	// WAF configuration
	WAFType string

	// Output configuration
	OutputFormat string
	OutputFile   string
	Verbose      bool
	Silent       bool

	// Performance configuration
	Threads int

	// Proxy configuration
	ProxyURL     string // HTTP/HTTPS proxy URL (e.g., http://127.0.0.1:8080)
	ProxyEnabled bool

	// Authentication configuration
	Cookies     string            // Cookie header value (e.g., "session=abc123; token=xyz")
	Headers     map[string]string // Custom headers (including Authorization)
	AuthHeader  string            // Authorization header value
	CookieFile  string            // File containing cookies (Netscape format)
	HeadersFile string            // File containing custom headers (key: value format)

	// Header Fuzzing configuration
	FuzzHeaders []string // Headers to fuzz with FUZZ marker (e.g., "X-Custom: FUZZ")
	FuzzMode    bool     // Whether header fuzzing mode is enabled

	// Rate limiting
	Delay int // Delay between requests in milliseconds

	// Blind XSS configuration
	BlindXSSCallback string // Callback URL for blind XSS detection (e.g., yourserver.xsshunter.com)
	BlindXSSEnabled  bool   // Whether blind XSS testing is enabled

	// Additional vulnerability scanning (Dalfox-inspired)
	ScanSSTI         bool // Scan for Server Side Template Injection
	ScanOpenRedirect bool // Scan for Open Redirect vulnerabilities
	CheckSecHeaders  bool // Check security headers

	// Advanced options
	FuzzyMatching   bool    // Enable fuzzy matching for payload detection
	FuzzyThreshold  float64 // Threshold for fuzzy matching (0.0-1.0)
	StoredXSS       bool    // Enable stored XSS testing mode
	DOMDeepScan     bool    // Enable deep DOM analysis
	FollowRedirects bool    // Follow HTTP redirects during scanning
	MaxRedirects    int     // Maximum number of redirects to follow

	// Dalfox-Style Verification Options
	SmartMode          bool // Check reflection before browser (Hybrid)
	StrictVerification bool // Vulnerable only if execution (alert) is confirmed
	StaticOnly         bool // Perform only static analysis (no browser)
	OnlyVerified       bool // Report only confirmed vulnerabilities

	// Encoding Options
	EncodeCustomPayloads bool // Apply encoding/obfuscation to custom payloads (-p)
}

// Vulnerability represents a detected XSS vulnerability
type Vulnerability struct {
	Type        string            `json:"type"`         // reflected, dom, stored
	Payload     string            `json:"payload"`      // The payload that worked
	URL         string            `json:"url"`          // Full URL with payload
	Parameter   string            `json:"parameter"`    // Vulnerable parameter
	Context     string            `json:"context"`      // Injection context
	Severity    string            `json:"severity"`     // critical, high, medium, low
	WAFBypassed bool              `json:"waf_bypassed"` // Whether WAF was bypassed
	Evidence    string            `json:"evidence"`     // DOM evidence
	Headers     map[string]string `json:"headers,omitempty"`

	// Verification details
	Verified bool   `json:"verified"`         // True if confirmed by browser
	Method   string `json:"method,omitempty"` // "Browser Execution", "Static Reflection"
}

// ScanResult contains the complete scan results
type ScanResult struct {
	TargetURL       string          `json:"target_url"`
	TargetURLs      []string        `json:"target_urls,omitempty"` // For batch mode
	ScanStartTime   time.Time       `json:"scan_start_time"`
	ScanEndTime     time.Time       `json:"scan_end_time"`
	TotalPayloads   int             `json:"total_payloads"`
	TestedPayloads  int             `json:"tested_payloads"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	WAFDetected     string          `json:"waf_detected,omitempty"`
	WAFBypassed     bool            `json:"waf_bypassed"`
	ScanDuration    string          `json:"scan_duration"`
	ErrorCount      int             `json:"error_count"`
	Errors          []string        `json:"errors,omitempty"`
	ProxyUsed       string          `json:"proxy_used,omitempty"`
	Authenticated   bool            `json:"authenticated"`
	TotalURLs       int             `json:"total_urls,omitempty"` // For batch mode
	ScannedURLs     int             `json:"scanned_urls,omitempty"`
}

// WAFSignature represents a WAF detection signature
type WAFSignature struct {
	Name         string
	Headers      map[string]string
	Cookies      []string
	BodyPatterns []string
	StatusCodes  []int
}

// PayloadContext represents the injection context
type PayloadContext struct {
	Type      string // html, attribute, javascript, url
	Tag       string // script, img, div, etc.
	Attribute string // src, href, onclick, etc.
	Quote     string // single, double, none
}

// DefaultConfig returns a default scan configuration
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		WAFType:            "auto",
		SmartPayload:       true,
		OutputFormat:       "json",
		Threads:            5,
		Timeout:            30,
		BrowserWaitTime:    1500,
		NavigationDelay:    500,
		Verbose:            false,
		ProxyEnabled:       false,
		Headers:            make(map[string]string),
		Delay:              0,
		FuzzyMatching:      true,
		FuzzyThreshold:     0.8,
		ScanSSTI:           false,
		ScanOpenRedirect:   false,
		CheckSecHeaders:    true,
		DOMDeepScan:        true,
		FollowRedirects:    false,
		MaxRedirects:       3,
		SmartMode:          true,
		StrictVerification: false, // Default to Hybrid: Report reflection even if unverified (Medium Confidence)
		StaticOnly:         false,
		OnlyVerified:       false,
	}
}
