package config

import (
	"time"
)

// ScanConfig holds all configuration for an XSS scan
type ScanConfig struct {
	TargetURL    string
	PayloadFile  string
	VisibleMode  bool
	WAFType      string
	SmartPayload bool
	OutputFormat string
	OutputFile   string
	Threads      int
	Timeout      int
	Verbose      bool
}

// Vulnerability represents a detected XSS vulnerability
type Vulnerability struct {
	Type        string            `json:"type"`      // reflected, dom, stored
	Payload     string            `json:"payload"`   // The payload that worked
	URL         string            `json:"url"`       // Full URL with payload
	Parameter   string            `json:"parameter"` // Vulnerable parameter
	Context     string            `json:"context"`   // Injection context
	Severity    string            `json:"severity"`  // critical, high, medium, low
	WAFBypassed bool              `json:"waf_bypassed"`
	Evidence    string            `json:"evidence"` // DOM evidence
	Headers     map[string]string `json:"headers,omitempty"`
}

// ScanResult contains the complete scan results
type ScanResult struct {
	TargetURL       string          `json:"target_url"`
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
		WAFType:      "auto",
		SmartPayload: true,
		OutputFormat: "json",
		Threads:      5,
		Timeout:      30,
		Verbose:      false,
	}
}
