// Package scanner - Reflection detection implementation
package scanner

import (
	"html"
	"net/url"
	"strings"
)

// DefaultReflectionDetector implements ReflectionDetector interface
type DefaultReflectionDetector struct{}

// NewReflectionDetector creates a new DefaultReflectionDetector
func NewReflectionDetector() *DefaultReflectionDetector {
	return &DefaultReflectionDetector{}
}

// Detect checks if probe is reflected in body
func (d *DefaultReflectionDetector) Detect(body, probe string) (bool, string) {
	if probe == "" {
		return false, ""
	}

	// Check raw reflection
	if strings.Contains(body, probe) {
		return true, "raw"
	}

	// Check URL decoded
	decodedProbe, err := url.QueryUnescape(probe)
	if err == nil && decodedProbe != probe && strings.Contains(body, decodedProbe) {
		return true, "decoded"
	}

	// Check URL encoded
	encodedProbe := url.QueryEscape(probe)
	if strings.Contains(body, encodedProbe) {
		return true, "url-encoded"
	}

	// Check HTML encoded
	htmlEncodedProbe := html.EscapeString(probe)
	if strings.Contains(body, htmlEncodedProbe) {
		return true, "html-encoded"
	}

	// Check double URL encoding
	doubleEncodedProbe := url.QueryEscape(encodedProbe)
	if strings.Contains(body, doubleEncodedProbe) {
		return true, "double-encoded"
	}

	return false, ""
}

// DetectWithVariants checks multiple encoding variants
func (d *DefaultReflectionDetector) DetectWithVariants(body, probe string, variants []string) (bool, string) {
	// First check standard encodings
	if found, format := d.Detect(body, probe); found {
		return true, format
	}

	// Then check custom variants
	for _, variant := range variants {
		if strings.Contains(body, variant) {
			return true, "variant"
		}
	}

	return false, ""
}

// CharacterEncodings maps special characters to their encoded forms
var CharacterEncodings = map[string][]string{
	"<":  {"<", "&lt;", "%3C", "%3c"},
	">":  {">", "&gt;", "%3E", "%3e"},
	"'":  {"'", "&#39;", "&#x27;", "%27"},
	"\"": {"\"", "&quot;", "%22"},
	"&":  {"&", "&amp;", "%26"},
	";":  {";", "%3B", "%3b"},
	"(":  {"(", "%28"},
	")":  {")", "%29"},
	"{":  {"{", "%7B", "%7b"},
	"}":  {"}", "%7D", "%7d"},
	"`":  {"`", "%60"},
}

// DetectPartialReflection checks if special characters are reflected in any encoded form
func DetectPartialReflection(body, payload string) (bool, string) {
	for char, encodings := range CharacterEncodings {
		if !strings.Contains(payload, char) {
			continue
		}

		for _, encoding := range encodings {
			if strings.Contains(body, encoding) {
				if encoding == char {
					return true, "raw-partial"
				}
				return true, "encoded-partial"
			}
		}
	}

	return false, ""
}
