// Package scanner - Interface definitions for XSS scanning components
package scanner

import (
	"context"
	"net/http"
)

// HTTPClient defines the interface for HTTP operations
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ReflectionDetector detects if and how a probe is reflected in response
type ReflectionDetector interface {
	// Detect checks if probe is reflected in body
	// Returns: isReflected, format (raw/url-encoded/html-encoded)
	Detect(body, probe string) (bool, string)

	// DetectWithVariants checks multiple encoding variants
	DetectWithVariants(body, probe string, variants []string) (bool, string)
}

// FilterTester tests which special characters are filtered
type FilterTester interface {
	// TestFiltering tests special chars and returns filtered ones
	TestFiltering(ctx context.Context, targetURL, paramName string) []string
}

// ContextDetector determines the reflection context
type ContextDetector interface {
	// DetectContext analyzes surrounding content to determine context
	DetectContext(body, probe string) string
}

// PayloadGenerator generates context-aware payloads
type PayloadGenerator interface {
	// Generate returns payloads suitable for the given context
	Generate(contextType string, filteredChars []string) []string

	// GetAll returns all available payloads
	GetAll() []string
}

// VulnerabilityChecker determines if reflection is exploitable
type VulnerabilityChecker interface {
	// IsPotentiallyVulnerable checks if the reflection could lead to XSS
	IsPotentiallyVulnerable(body, probe, contextType string) bool
}

// Scanner is the common interface for all XSS scanners
type XSSScanner interface {
	// ScanURL scans a single URL for XSS vulnerabilities
	ScanURL(ctx context.Context, targetURL string) ([]ScanResult, error)

	// Close releases scanner resources
	Close() error
}

// ScanResult is the common result type for all scanners
type ScanResult interface {
	// IsVulnerable returns true if the result indicates a vulnerability
	IsVulnerable() bool

	// GetURL returns the tested URL
	GetURL() string

	// GetParameter returns the tested parameter
	GetParameter() string

	// GetPayload returns the payload that caused the vulnerability
	GetPayload() string

	// GetContext returns the reflection context
	GetContext() string
}
