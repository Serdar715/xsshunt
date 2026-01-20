package scanner

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ProbeResult holds the analysis of a parameter's behavior
type ProbeResult struct {
	IsReflected   bool
	Contexts      []ContextInfo
	FilteredChars map[string]bool
	Canary        string
}

// ContextInfo describes a specific reflection instance
type ContextInfo struct {
	Type         string // html, attribute, script, comment, unknown
	Quote        string // double, single, none, backtick
	EnclosingTag string // The tag that encloses the reflection
	Content      string // The text surrounding the reflection (for debugging)
}

// analyzeParameter performs intelligent probing to understand context and filtering
// This uses a raw HTTP client for speed, as a preliminary check before the main scan
func (s *Scanner) analyzeParameter(baseURL, paramName string, originalParams url.Values) *ProbeResult {
	// Create a unique canary
	canary := "xsh" + randomString(5)

	// Create probe with special characters to test filtering
	// We use commonly filtered chars: " < ' >
	probe := canary + "\"'<>"

	// Prepare request
	params := cloneParams(originalParams)
	params.Set(paramName, probe)
	targetURL := baseURL + "?" + params.Encode()

	// Use a new HTTP client for probing (faster than headless browser)
	// We use s.config to get proxy settings if needed
	// CreateHTTPClient is defined in scanner.go
	client := CreateHTTPClient(s.config.ProxyURL, 10*time.Second)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		if s.config.Verbose {
			color.Yellow("  [!] Analysis request creation failed: %v", err)
		}
		return nil
	}

	// Add headers and cookies
	if s.config.Cookies != "" {
		req.Header.Set("Cookie", s.config.Cookies)
	}
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}
	if s.config.AuthHeader != "" {
		req.Header.Set("Authorization", s.config.AuthHeader)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		if s.config.Verbose {
			color.Yellow("  [!] Analysis request failed: %v", err)
		}
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// Analyze reflection
	result := &ProbeResult{
		Contexts:      make([]ContextInfo, 0),
		FilteredChars: make(map[string]bool),
		Canary:        canary,
	}

	// Check if canary is reflected at all
	if !strings.Contains(body, canary) {
		return result // Not reflected
	}
	result.IsReflected = true

	// Analyze filtering by checking how special chars appear

	// If the exact probe string is found, nothing is filtered
	if strings.Contains(body, probe) {
		result.FilteredChars["\""] = false
		result.FilteredChars["'"] = false
		result.FilteredChars["<"] = false
		result.FilteredChars[">"] = false
	} else {
		// Naive check for filtering
		// We default to true (filtered) and set to false if we find the char raw
		result.FilteredChars["\""] = true
		result.FilteredChars["'"] = true
		result.FilteredChars["<"] = true
		result.FilteredChars[">"] = true

		// If we find the char combined with canary (or just nearby in a sophisticated check), it's not filtered
		// For simplicity, we check if the raw chars exist in the body at all, which is flawed but a starting point.
		// A better approach is checking strictly near the canary.

		// Let's refine: Check the 50 chars after canary occurrences
	}

	// Detailed Context Analysis
	indices := findAllOccurrences(body, canary)
	for _, idx := range indices {
		ctx := s.determineContext(body, idx, canary)
		result.Contexts = append(result.Contexts, ctx)

		// Determine filtering for this specific context
		startCheck := idx + len(canary)
		endCheck := startCheck + 10
		if endCheck > len(body) {
			endCheck = len(body)
		}
		if startCheck < len(body) {
			reflectedPart := body[startCheck:endCheck]

			// Check what actually came back
			if strings.Contains(reflectedPart, "\"") {
				result.FilteredChars["\""] = false
			}
			if strings.Contains(reflectedPart, "'") {
				result.FilteredChars["'"] = false
			}
			if strings.Contains(reflectedPart, "<") {
				result.FilteredChars["<"] = false
			}
			if strings.Contains(reflectedPart, ">") {
				result.FilteredChars[">"] = false
			}
		}
	}

	return result
}

func findAllOccurrences(s, substr string) []int {
	var indices []int
	i := 0
	for {
		idx := strings.Index(s[i:], substr)
		if idx == -1 {
			break
		}
		indices = append(indices, i+idx)
		i += idx + len(substr)
	}
	return indices
}

// determineContext analyzes the text surrounding the reflection
func (s *Scanner) determineContext(body string, idx int, canary string) ContextInfo {
	info := ContextInfo{
		Type:  "unknown",
		Quote: "none",
	}

	// Look backwards from the injection point
	start := idx - 500
	if start < 0 {
		start = 0
	}
	prefix := body[start:idx]

	// 1. Script Context
	scriptOpen := strings.LastIndex(prefix, "<script")
	scriptClose := strings.LastIndex(prefix, "</script")

	if scriptOpen > scriptClose {
		info.Type = "script"
		info.EnclosingTag = "script"

		// Check for quotes
		trimmedPrefix := strings.TrimSpace(prefix)
		if len(trimmedPrefix) > 0 {
			lastChar := trimmedPrefix[len(trimmedPrefix)-1]
			if lastChar == '"' {
				info.Quote = "double"
			} else if lastChar == '\'' {
				info.Quote = "single"
			} else if lastChar == '`' {
				info.Quote = "backtick"
			}
		}
		return info
	}

	// 2. Attribute Context
	tagOpen := strings.LastIndex(prefix, "<")
	tagClose := strings.LastIndex(prefix, ">")

	if tagOpen > tagClose {
		// We are inside a tag
		info.Type = "attribute"

		// Determine which tag
		tagContent := prefix[tagOpen:]
		spaceIdx := strings.Index(tagContent, " ")
		if spaceIdx != -1 {
			info.EnclosingTag = tagContent[1:spaceIdx]
		}

		// Check for quotes
		lastQuote := strings.LastIndexAny(prefix, "\"'")
		lastEquals := strings.LastIndex(prefix, "=")
		if lastQuote > lastEquals && lastEquals != -1 {
			char := prefix[lastQuote]
			if char == '"' {
				info.Quote = "double"
			} else if char == '\'' {
				info.Quote = "single"
			}
		}
		return info
	}

	// 3. Comment Context
	commentOpen := strings.LastIndex(prefix, "<!--")
	commentClose := strings.LastIndex(prefix, "-->")
	if commentOpen > commentClose {
		info.Type = "comment"
		return info
	}

	// 4. HTML Body Context
	info.Type = "html"
	return info
}

// filterPayloads selects the best payloads based on analysis
func (s *Scanner) filterPayloads(payloads []string, result *ProbeResult) []string {
	// If analysis failed or no reflection found via Probe, return all payloads
	// We rely on the browser-based scan to be the final judge for "blind" or complex cases,
	// but mostly we want to speed up by focusing on found reflections
	if result == nil || !result.IsReflected {
		return payloads
	}

	var optimized []string

	for _, p := range payloads {

		// Base logic: If a payload requires a character that is strictly filtered, skip it.
		// BUT be careful: some payloads are encoded to bypass filters.

		// Simple heuristic filtering:
		needsDoubleAndFiltered := strings.Contains(p, "\"") && result.FilteredChars["\""] && !strings.Contains(p, "&quot;") && !strings.Contains(p, "\\u")
		needsSingleAndFiltered := strings.Contains(p, "'") && result.FilteredChars["'"] && !strings.Contains(p, "&apos;") && !strings.Contains(p, "\\u")
		needsTagAndFiltered := (strings.Contains(p, "<") || strings.Contains(p, ">")) && (result.FilteredChars["<"] || result.FilteredChars[">"]) && !strings.Contains(p, "\\u")

		if needsDoubleAndFiltered || needsSingleAndFiltered || needsTagAndFiltered {
			// Skip this payload as it likely won't work due to filtering
			// Unless it's a bypass payload (we check for common bypass patterns like encoding or unicode above)
			continue
		}

		// Context Matching
		isMatch := false
		for _, ctx := range result.Contexts {
			if ctx.Type == "script" {
				// In script context, we need to break out of quotes or script tag
				if strings.Contains(p, "</script>") {
					isMatch = true
				}
				if ctx.Quote == "double" && strings.Contains(p, "\"") {
					isMatch = true
				}
				if ctx.Quote == "single" && strings.Contains(p, "'") {
					isMatch = true
				}
				if ctx.Quote == "none" && !strings.Contains(p, "\"") && !strings.Contains(p, "'") {
					isMatch = true
				} // e.g. confirm(1)
			} else if ctx.Type == "attribute" {
				// In attribute context, we need to break out of quotes
				if ctx.Quote == "double" && strings.Contains(p, "\"") {
					isMatch = true
				}
				if ctx.Quote == "single" && strings.Contains(p, "'") {
					isMatch = true
				}
				// Or use event handlers if we can inject attributes (requires space and no quotes around attribute value? complex)
				if ctx.Quote == "none" && strings.HasPrefix(p, " on") {
					isMatch = true
				}
			} else if ctx.Type == "html" {
				// HTML context needs tags
				if strings.Contains(p, "<") {
					isMatch = true
				}
			}
		}

		// If we found a matching context strategy, or if the payload is generic enough (polyglot), include it
		if isMatch || len(result.Contexts) == 0 {
			optimized = append(optimized, p)
		}
	}

	// If we filtered down to nothing (too aggressive?) return original list just in case
	if len(optimized) == 0 {
		return payloads
	}

	if s.config.Verbose {
		color.Cyan("  [*] Smart Analysis reduced payloads from %d to %d", len(payloads), len(optimized))
	}

	return optimized
}
