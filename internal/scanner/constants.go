package scanner

import "time"

const (
	// Default configuration values
	DefaultBrowserWaitTime = 1500 * time.Millisecond
	DefaultNavigationDelay = 500 * time.Millisecond
	DefaultTimeout         = 30 * time.Second
	DefaultThreads         = 5

	// HTTP and Response limits
	MaxResponseBodySize    = 1 << 20 // 1 MB - maximum response body to read
	PageCleanupTimeout     = 2 * time.Second
	ContextLookbackChars   = 500 // Characters to look back for context detection

	// Retry configuration
	MaxBrowserRetries  = 3
	BrowserRetryDelay  = 500 * time.Millisecond
	MaxHTTPRetries     = 2
	HTTPRetryDelay     = 200 * time.Millisecond

	// Connection pool settings
	MaxIdleConns        = 1000
	MaxIdleConnsPerHost = 500
	MaxConnsPerHost     = 500
	IdleConnTimeout     = 90 * time.Second
	DialTimeout         = 10 * time.Second
	KeepAliveInterval   = 30 * time.Second
	TLSHandshakeTimeout = 10 * time.Second
	ResponseHeaderTimeout = 20 * time.Second

	// Page pool multiplier (Threads * this = pool size)
	PagePoolMultiplier = 2

	// Detection thresholds
	EvidenceContextRadius   = 50
	ContextDetectionRadius  = 100
	SmartModeScoreThreshold = 0.1
	ReflectedScoreThreshold = 0.95

	// Random generation
	RandomStringLength = 8
	CanaryPrefix       = "xsh"
	CanaryLength       = 5

	// Probe characters for filtering detection
	ProbeChars = "\"'<>"

	// Context types
	ContextUnknown   = "unknown"
	ContextHTML      = "html"
	ContextAttribute = "attribute"
	ContextScript    = "script"
	ContextComment   = "comment"
	ContextEvent     = "event"
	ContextCSS       = "css"
	ContextUrl       = "url"

	// Vulnerability types
	VulnTypeConfirmed = "Confirmed XSS (Execution Verified)"
	VulnTypeReflected = "Reflected XSS (Unverified)"
	VulnTypeStored    = "Stored XSS"
	VulnTypeDOM       = "DOM XSS"

	// Verification methods
	MethodBrowser = "Browser Execution"
	MethodStatic  = "Static Reflection Analysis"

	// Severity levels
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
)
