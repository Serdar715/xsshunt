package scanner

import (
	"math"
	"strings"
)

// FuzzyMatcher provides fuzzy string matching capabilities
// Inspired by XSStrike's approach to reduce false negatives
type FuzzyMatcher struct {
	threshold float64 // Similarity threshold (0.0 - 1.0)
}

// NewFuzzyMatcher creates a new fuzzy matcher with default threshold
func NewFuzzyMatcher() *FuzzyMatcher {
	return &FuzzyMatcher{
		threshold: 0.8, // 80% similarity threshold
	}
}

// SetThreshold sets the similarity threshold
func (fm *FuzzyMatcher) SetThreshold(t float64) {
	if t > 0 && t <= 1.0 {
		fm.threshold = t
	}
}

// LevenshteinDistance calculates the edit distance between two strings
// This is useful for detecting payloads that are slightly modified in responses
func LevenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Create matrix
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	// Calculate distances
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// SimilarityRatio calculates the similarity ratio between two strings (0.0 - 1.0)
func SimilarityRatio(s1, s2 string) float64 {
	if len(s1) == 0 && len(s2) == 0 {
		return 1.0
	}
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	distance := LevenshteinDistance(s1, s2)
	return 1.0 - float64(distance)/maxLen
}

// IsFuzzyMatch checks if two strings are similar enough
func (fm *FuzzyMatcher) IsFuzzyMatch(original, reflected string) bool {
	ratio := SimilarityRatio(original, reflected)
	return ratio >= fm.threshold
}

// FindFuzzyReflection searches for a fuzzy match of the payload in the body
// Returns the matched string and its position, or empty string and -1 if not found
func (fm *FuzzyMatcher) FindFuzzyReflection(body, payload string) (string, int) {
	lowerBody := strings.ToLower(body)
	lowerPayload := strings.ToLower(payload)

	// First, try exact match
	if idx := strings.Index(lowerBody, lowerPayload); idx != -1 {
		return body[idx : idx+len(payload)], idx
	}

	// Try case-insensitive match
	if idx := strings.Index(lowerBody, lowerPayload); idx != -1 {
		return body[idx : idx+len(payload)], idx
	}

	// Try fuzzy matching with sliding window
	payloadLen := len(payload)
	if payloadLen == 0 || len(body) < payloadLen {
		return "", -1
	}

	windowSize := payloadLen + int(float64(payloadLen)*0.3) // Allow 30% longer window
	if windowSize > len(body) {
		windowSize = len(body)
	}

	bestMatch := ""
	bestIdx := -1
	bestRatio := 0.0

	for i := 0; i <= len(body)-payloadLen; i++ {
		endIdx := i + windowSize
		if endIdx > len(body) {
			endIdx = len(body)
		}

		window := body[i:endIdx]
		checkLen := len(window)
		if payloadLen < checkLen {
			checkLen = payloadLen
		}
		ratio := SimilarityRatio(lowerPayload, strings.ToLower(window[:checkLen]))

		if ratio > bestRatio && ratio >= fm.threshold {
			bestRatio = ratio
			matchLen := len(window)
			if payloadLen < matchLen {
				matchLen = payloadLen
			}
			bestMatch = window[:matchLen]
			bestIdx = i
		}
	}

	return bestMatch, bestIdx
}

// DetectEncodedPayload checks if the payload appears in various encoded forms
func (fm *FuzzyMatcher) DetectEncodedPayload(body, payload string) (bool, string) {
	encodedVariants := generateEncodedVariants(payload)

	for encoding, encoded := range encodedVariants {
		if strings.Contains(body, encoded) {
			return true, encoding
		}
		if strings.Contains(strings.ToLower(body), strings.ToLower(encoded)) {
			return true, encoding + " (case-insensitive)"
		}
	}

	return false, ""
}

// generateEncodedVariants generates various encoded versions of a payload
func generateEncodedVariants(payload string) map[string]string {
	variants := make(map[string]string)

	// HTML entity encoding
	variants["html_entities"] = htmlEntityEncode(payload)
	variants["html_entities_numeric"] = htmlNumericEncode(payload)
	variants["html_entities_hex"] = htmlHexEncode(payload)

	// URL encoding
	variants["url_encoded"] = urlEncode(payload)
	variants["double_url_encoded"] = urlEncode(urlEncode(payload))

	// Unicode escapes
	variants["unicode"] = unicodeEncode(payload)
	variants["utf16"] = utf16Encode(payload)

	return variants
}

// htmlEntityEncode encodes special characters as HTML entities
func htmlEntityEncode(s string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
	)
	return replacer.Replace(s)
}

// htmlNumericEncode encodes characters as HTML numeric entities
func htmlNumericEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r == '<' || r == '>' || r == '"' || r == '\'' || r == '&' {
			result.WriteString("&#")
			result.WriteString(string(rune('0' + int(r)/100%10)))
			result.WriteString(string(rune('0' + int(r)/10%10)))
			result.WriteString(string(rune('0' + int(r)%10)))
			result.WriteString(";")
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// htmlHexEncode encodes characters as HTML hex entities
func htmlHexEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r == '<' || r == '>' || r == '"' || r == '\'' || r == '&' {
			result.WriteString("&#x")
			result.WriteString(strings.ToLower(string([]byte{byte(r)})))
			result.WriteString(";")
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// urlEncode performs URL encoding
func urlEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else {
			result.WriteString("%")
			result.WriteString(strings.ToUpper(string([]byte{byte(r >> 4), byte(r & 0xf)})))
		}
	}
	return result.String()
}

// unicodeEncode encodes string with JavaScript unicode escapes
func unicodeEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 && ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			result.WriteRune(r)
		} else {
			result.WriteString("\\u")
			result.WriteString(strings.ToLower(strings.Repeat("0", 4-len(strings.TrimLeft(string(rune(r)), "0")))))
		}
	}
	return result.String()
}

// utf16Encode encodes string as UTF-16 escape sequences
func utf16Encode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 && ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			result.WriteRune(r)
		} else {
			result.WriteString("\\x")
			hex := strings.ToLower(string([]byte{byte(r)}))
			if len(hex) < 2 {
				hex = "0" + hex
			}
			result.WriteString(hex)
		}
	}
	return result.String()
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
