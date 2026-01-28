package payloads

import (
	"fmt"
	"net/url"
	"strings"
)

// Encoder handles various payload encoding techniques
type Encoder struct{}

// NewEncoder creates a new payload encoder
func NewEncoder() *Encoder {
	return &Encoder{}
}

// URLEncode performs standard URL encoding
func (e *Encoder) URLEncode(payload string) string {
	return url.QueryEscape(payload)
}

// DoubleURLEncode performs double URL encoding
func (e *Encoder) DoubleURLEncode(payload string) string {
	return url.QueryEscape(url.QueryEscape(payload))
}

// HTMLEntityEncode encodes characters to HTML entities (decimal)
// e.g. < -> &#60;
func (e *Encoder) HTMLEntityEncode(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		// Encode typical dangerous characters
		if strings.ContainsRune("<>\"'()", r) {
			sb.WriteString(fmt.Sprintf("&#%d;", r))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// HTMLEntityHexEncode encodes characters to HTML entities (hex)
// e.g. < -> &#x3c;
func (e *Encoder) HTMLEntityHexEncode(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		if strings.ContainsRune("<>\"'()", r) {
			sb.WriteString(fmt.Sprintf("&#x%x;", r))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// UnicodeEncode encodes characters to unicode escapes
// e.g. < -> \u003c (JavaScript context)
func (e *Encoder) UnicodeEncode(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		if r > 127 || strings.ContainsRune("<>\"'()", r) {
			sb.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// MixedEncode applies a random mix of encodings (useful for fuzzing)
// For now, it just demonstrates mixing, can be enhanced with random
func (e *Encoder) MixedEncode(payload string) []string {
	return []string{
		e.URLEncode(payload),
		e.DoubleURLEncode(payload),
		e.HTMLEntityEncode(payload),
		e.HTMLEntityHexEncode(payload),
		e.UnicodeEncode(payload),
	}
}
