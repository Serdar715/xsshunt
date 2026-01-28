package payloads

import (
	"strings"
	"testing"
)

func TestEncoder(t *testing.T) {
	enc := NewEncoder()
	payload := "<script>alert(1)</script>"

	// Test URL Encode
	expectedURL := "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
	if got := enc.URLEncode(payload); got != expectedURL {
		t.Errorf("URLEncode: got %v, want %v", got, expectedURL)
	}

	// Test HTML Entity Encode (Decimal)
	// Check specifically for brackets
	encoded := enc.HTMLEntityEncode(payload)
	if !strings.Contains(encoded, "&#60;") || !strings.Contains(encoded, "&#62;") {
		t.Errorf("HTMLEntityEncode: failed to encode brackets in %v", payload)
	}
}

func TestObfuscator(t *testing.T) {
	obf := NewObfuscator()
	payload := "<script>alert(1)</script>"

	// Test InjectWhitespace
	// Note: It's random-ish but deterministic in logic for simple case
	variant1 := obf.InjectWhitespace(payload)
	if variant1 != "<script >alert(1)</script>" && variant1 != payload {
		// Our logic changes <script to <script
		if !strings.Contains(variant1, "<script ") {
			t.Errorf("InjectWhitespace: expected whitespace injection, got %v", variant1)
		}
	}

	// Test InjectComments
	// <script> -> <scr<!--x-->ipt>
	variantComment := obf.InjectComments(payload)
	if !strings.Contains(variantComment, "<!--x-->") {
		t.Errorf("InjectComments: comment not injected, got %v", variantComment)
	}
}

func TestGeneratorDynamic(t *testing.T) {
	// Test if generator actually produces variants when smart mode is on
	gen := NewGenerator(true)

	// We pass a dummy WAF type to trigger WAF logic
	payloads := gen.GetPayloads("cloudflare")

	foundObfuscated := false
	for _, p := range payloads {
		if strings.Contains(p, "<!--x-->") {
			foundObfuscated = true
			break
		}
	}

	if !foundObfuscated {
		t.Error("Generator failed to produce obfuscated payloads in WAF mode")
	}
}
