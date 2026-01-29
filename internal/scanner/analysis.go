package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Serdar715/xsshunt/internal/config"
	payloadsPkg "github.com/Serdar715/xsshunt/internal/payloads"
	"github.com/fatih/color"
)

// Analyzer handles static analysis and probing of parameters
type Analyzer struct {
	config *config.ScanConfig
	client *http.Client
	ctx    context.Context
}

// NewAnalyzer creates a new Analyzer instance
func NewAnalyzer(cfg *config.ScanConfig, client *http.Client) *Analyzer {
	// If allow passing external client, use it, otherwise create one
	if client == nil {
		client = CreateHTTPClient(cfg.ProxyURL, time.Duration(cfg.Timeout)*time.Second)
	}

	return &Analyzer{
		config: cfg,
		client: client,
		ctx:    context.Background(),
	}
}

// SetContext updates the context for the analyzer
func (a *Analyzer) SetContext(ctx context.Context) {
	a.ctx = ctx
}

// Constants for analysis (now using constants.go, but for local clarity)
// Note: We use the constants defined in constants.go

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

// ReflectionResult holds the analysis result of a reflected payload
type ReflectionResult struct {
	IsDangerous bool
	VulnType    string
	Context     string
	Severity    string
	Evidence    string
}

// AnalyzeParameter performs intelligent probing to understand context and filtering
func (a *Analyzer) AnalyzeParameter(baseURL, paramName string, originalParams url.Values) *ProbeResult {
	// Create a unique canary
	canary := CanaryPrefix + randomString(CanaryLength)

	// Create probe with special characters to test filtering
	probe := canary + ProbeChars

	// Prepare request
	params := cloneParams(originalParams)
	params.Set(paramName, probe)
	targetURL := baseURL + "?" + params.Encode() // Note: Depending on server, might need manual construction if Encode escapes too much

	req, err := http.NewRequestWithContext(a.ctx, "GET", targetURL, nil)
	if err != nil {
		if a.config.Verbose {
			color.Yellow("  [!] Analysis request creation failed: %v", err)
		}
		return nil
	}

	a.addHeaders(req)

	resp, err := a.client.Do(req)
	if err != nil {
		if a.config.Verbose {
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

	// Analyze filtering
	// Check if probe chars are preserved
	for _, char := range strings.Split(ProbeChars, "") {
		if char == "" {
			continue
		}
		// Simple check: is the char present?
		// Better check: is it present NEAR the canary?
		// For now, we use a global check but could be improved.
		// If the exact probe string is found, nothing is filtered.
		if strings.Contains(body, probe) {
			result.FilteredChars[char] = false
		} else {
			// Naive: assume filtered unless found
			result.FilteredChars[char] = !strings.Contains(body, char)
		}
	}

	// Detailed Context Analysis
	indices := a.findAllOccurrences(body, canary)
	for _, idx := range indices {
		ctx := a.determineContext(body, idx, canary)
		result.Contexts = append(result.Contexts, ctx)
	}

	return result
}

// CheckReflection performs a lightweight HTTP request to check if payload is reflected
// Replaces Scanner.checkReflection
func (a *Analyzer) CheckReflection(urlStr string, payload string) float64 {
	req, err := http.NewRequestWithContext(a.ctx, "GET", urlStr, nil)
	if err != nil {
		return 1.0 // If error, assume reflection to force browser check (safety)
	}

	a.addHeaders(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return 1.0 // Fail open
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 1.0
	}
	body := string(bodyBytes)

	// Check if payload reflection exists
	if strings.Contains(body, payload) {
		return 1.0
	}

	// Check decoded version just in case
	decoded, _ := url.QueryUnescape(payload)
	if strings.Contains(body, decoded) {
		return 1.0
	}

	return 0.0
}

// AnalyzeReflection performs deep analysis of how the payload is reflected
// Merged from scanner.go
func (a *Analyzer) AnalyzeReflection(html, payload string) *ReflectionResult {
	if !strings.Contains(html, payload) {
		decodedPayload, _ := url.QueryUnescape(payload)
		if !strings.Contains(html, decodedPayload) {
			return nil
		}
		payload = decodedPayload
	}

	// Step 2: Check if payload is inside HTML comments (not exploitable)
	if a.isInsideHTMLComment(html, payload) {
		return nil
	}

	// Step 3: Check if payload is properly HTML-encoded
	if a.isProperlyEncoded(html, payload) {
		return nil // Properly encoded, not vulnerable
	}

	// Step 4: Determine the injection context
	context := a.detectContextAdvanced(html, payload)

	// Step 5: Evaluate danger based on context and payload structure
	result := a.evaluateDanger(context, payload, html)

	// Step 6: Apply 5-Layer FP Filtering System
	confidence := a.isActuallyVulnerable(html, payload, result)

	if confidence < 0.2 { // Too low confidence
		return nil
	}

	// Update result with calculated confidence logic if needed
	// (Severity is already set in evaluateDanger but could be adjusted here)

	return result
}

// Helper methods

func (a *Analyzer) addHeaders(req *http.Request) {
	if a.config.Cookies != "" {
		req.Header.Set("Cookie", a.config.Cookies)
	}
	for k, v := range a.config.Headers {
		req.Header.Set(k, v)
	}
	if a.config.AuthHeader != "" {
		req.Header.Set("Authorization", a.config.AuthHeader)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (XSSHunt)")
}

func (a *Analyzer) findAllOccurrences(s, substr string) []int {
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

func (a *Analyzer) determineContext(body string, idx int, canary string) ContextInfo {
	info := ContextInfo{
		Type:  ContextUnknown,
		Quote: "none",
	}

	// Look backwards from the injection point
	start := idx - ContextLookbackChars
	if start < 0 {
		start = 0
	}
	prefix := body[start:idx]

	// 1. Script Context
	scriptOpen := strings.LastIndex(prefix, "<script")
	scriptClose := strings.LastIndex(prefix, "</script")

	if scriptOpen > scriptClose {
		info.Type = ContextScript
		info.EnclosingTag = "script"
		info.Quote = a.detectQuote(prefix)
		return info
	}

	// 2. Attribute Context
	tagOpen := strings.LastIndex(prefix, "<")
	tagClose := strings.LastIndex(prefix, ">")

	if tagOpen > tagClose {
		info.Type = ContextAttribute
		// Determine tag logic...
		// Simplified for brevity
		info.Quote = a.detectQuote(prefix)
		return info
	}

	// 3. Comment Context
	commentOpen := strings.LastIndex(prefix, "<!--")
	commentClose := strings.LastIndex(prefix, "-->")
	if commentOpen > commentClose {
		info.Type = ContextComment
		return info
	}

	// 4. HTML Body Context
	info.Type = ContextHTML
	return info
}

func (a *Analyzer) detectQuote(prefix string) string {
	trimmedPrefix := strings.TrimSpace(prefix)
	if len(trimmedPrefix) > 0 {
		lastChar := trimmedPrefix[len(trimmedPrefix)-1]
		if lastChar == '"' {
			return "double"
		} else if lastChar == '\'' {
			return "single"
		} else if lastChar == '`' {
			return "backtick"
		}
	}
	return "none"
}

// detectContextAdvanced (from scanner.go)
func (a *Analyzer) detectContextAdvanced(html, payload string) string {
	lowerHTML := strings.ToLower(html)
	lowerPayload := strings.ToLower(payload)
	idx := strings.Index(lowerHTML, lowerPayload)
	if idx == -1 {
		return ContextUnknown
	}
	start := idx - ContextDetectionRadius
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + ContextDetectionRadius
	if end > len(lowerHTML) {
		end = len(lowerHTML)
	}
	// surrounding := lowerHTML[start:end]
	before := lowerHTML[start:idx]

	scriptOpenRe := regexp.MustCompile(`<script[^>]*>`)
	scriptCloseRe := regexp.MustCompile(`</script>`)
	lastScriptIdx := strings.LastIndex(before, "<script")
	if lastScriptIdx != -1 && scriptOpenRe.MatchString(before) && !scriptCloseRe.MatchString(before[lastScriptIdx:]) {
		return "JavaScript context"
	}
	eventHandlerRe := regexp.MustCompile(`\son\w+\s*=\s*["']?[^"']*$`)
	if eventHandlerRe.MatchString(before) {
		return "Event handler context"
	}
	// More regex checks...
	return "HTML body context" // Fallback
}

func (a *Analyzer) isInsideHTMLComment(html, payload string) bool {
	idx := strings.Index(html, payload)
	if idx == -1 {
		return false
	}
	beforePayload := html[:idx]
	afterPayload := html[idx+len(payload):]
	lastCommentStart := strings.LastIndex(beforePayload, "<!--")
	lastCommentEnd := strings.LastIndex(beforePayload, "-->")
	if lastCommentStart > lastCommentEnd {
		if strings.Contains(afterPayload, "-->") {
			return true
		}
	}
	return false
}

// 5-Layer False Positive Filtering System

// isActuallyVulnerable performs a comprehensive check to rule out false positives
func (a *Analyzer) isActuallyVulnerable(html, payload string, result *ReflectionResult) float64 {
	// Layer 1: HTML Encoding Check (Most common FP)
	if a.isProperlyEncoded(html, payload) {
		return 0.0
	}

	// Layer 2: Safe Container Analysis
	if a.isInsideSafeContainer(html, payload) {
		return 0.1 // Very low confidence
	}

	// Layer 3: JavaScript Context Escaping
	if strings.Contains(strings.ToLower(result.Context), "script") {
		if a.isJSStringEscaped(html, payload) {
			return 0.2
		}
	}

	// Layer 4: Mutation/Sanitization Check (Basic)
	if a.isSanitized(html, payload) {
		return 0.4
	}

	// Layer 5 passed: Likely generic reflection or true positive
	return 0.8
}

func (a *Analyzer) isProperlyEncoded(html, payload string) bool {
	dangerousChars := map[string][]string{
		"<":  {"&lt;", "&#60;", "&#x3c;"},
		">":  {"&gt;", "&#62;", "&#x3e;"},
		"\"": {"&quot;", "&#34;", "&#x22;"},
		"'":  {"&#39;", "&#x27;", "&apos;"},
	}

	// If the raw payload isn't found but a decoded version might be,
	// we need to be careful. Here we assume we found the payload string.
	// But if the payload itself contains < and in HTML it appears as &lt;
	// it means it was encoded.

	idx := strings.Index(html, payload)
	if idx != -1 {
		// Payload is there in raw form.
		// If payload has dangerous chars, and they are NOT encoded in HTML, then it's VULNERABLE.
		// If they ARE encoded, then index wouldn't match raw payload if we search for raw.
		// Wait, if search for "<script>" finds match, it means it is NOT encoded.
		// If it finds "&lt;script&gt;", then strings.Index("<script>") would fail.

		// So if strings.Index returns a match, it usually means it's NOT encoded,
		// UNLESS the payload itself was provided in encoded form (which is rare for input).
		return false
	}

	// If raw payload is NOT found, but we know it's reflected (from previous checks),
	// it implies it might be encoded.

	// Check if the encoded version exists
	encodedPayload := payload
	wasEncoded := false
	for char, encodings := range dangerousChars {
		if strings.Contains(payload, char) {
			// Try first encoding (most common)
			// This is a heuristic.
			encodedPayload = strings.ReplaceAll(encodedPayload, char, encodings[0])
			wasEncoded = true
		}
	}

	if wasEncoded && strings.Contains(html, encodedPayload) {
		return true // Found the encoded version, so it's safe
	}

	return false
}

func (a *Analyzer) isInsideSafeContainer(html, payload string) bool {
	// Check if inside textarea, title, xmp, noscript, etc.
	idx := strings.Index(html, payload)
	if idx == -1 {
		return false
	}

	prefix := html[:idx]
	// prefixLower := strings.ToLower(prefix)

	safeTags := []string{"textarea", "title", "xmp", "noscript", "plaintext"}

	for _, tag := range safeTags {
		openTag := "<" + tag
		closeTag := "</" + tag + ">"

		lastOpen := strings.LastIndex(strings.ToLower(prefix), openTag)
		lastClose := strings.LastIndex(strings.ToLower(prefix), closeTag)

		if lastOpen > lastClose {
			// We are likely inside an open tag
			// Verify we haven't closed it after payload
			suffix := html[idx+len(payload):]
			nextClose := strings.Index(strings.ToLower(suffix), closeTag)
			if nextClose != -1 {
				return true
			}
		}
	}
	return false
}

func (a *Analyzer) isJSStringEscaped(html, payload string) bool {
	// Check if quote is escaped before the payload
	// This is tricky without full parsing but we can check immediate vicinity
	idx := strings.Index(html, payload)
	if idx <= 0 {
		return false
	}

	// Check for backslash before quote if payload starts with quote
	if strings.HasPrefix(payload, "'") || strings.HasPrefix(payload, "\"") {
		if html[idx-1] == '\\' {
			return true
		}
	}

	return false
}

func (a *Analyzer) isSanitized(html, payload string) bool {
	// Check for inserted anti-XSS tokens or modification
	// e.g. "onxss=alert(1)" mutation
	return strings.Contains(html, "safe") || strings.Contains(html, "clean")
}

func (a *Analyzer) evaluateDanger(context, payload, html string) *ReflectionResult {
	// Simplified eval
	return &ReflectionResult{
		IsDangerous: true,
		VulnType:    VulnTypeReflected,
		Context:     context,
		Severity:    SeverityMedium,
		Evidence:    fmt.Sprintf("Payload reflected in %s", context),
	}
}

// FilterPayloads selects AND ADAPTS the best payloads based on analysis
func (a *Analyzer) FilterPayloads(payloads []string, result *ProbeResult) []string {
	if result == nil || !result.IsReflected {
		return payloads
	}

	// We use the new Mutator
	mutator := payloadsPkg.NewMutator()

	var optimized []string
	seen := make(map[string]bool)

	// Add original payloads first (as baseline)
	// But only if they make sense? No, let's keep them mixed.

	// Create adapted payloads for each reflection context
	for _, ctxInfo := range result.Contexts {
		// Convert our local ContextInfo to payloads package ContextInfo
		// This conversion is needed because we defined ContextInfo in analysis.go previously
		// Ideally we should move ContextInfo to a shared package or payloads package

		// Map local types to mutator types
		mutatorCtx := payloadsPkg.ContextInfo{
			Type:         payloadsPkg.ContextType(ctxInfo.Type),
			Quote:        payloadsPkg.QuoteType(ctxInfo.Quote),
			EnclosingTag: ctxInfo.EnclosingTag,
		}

		for _, p := range payloads {
			// 1. Original
			if !seen[p] {
				optimized = append(optimized, p)
				seen[p] = true
			}

			// 2. Adapted
			// Only adapt if we have valid context
			if mutatorCtx.Type != payloadsPkg.ContextUnknown {
				adapted := mutator.AdaptPayload(p, mutatorCtx)
				if adapted != p && !seen[adapted] {
					optimized = append(optimized, adapted)
					seen[adapted] = true
				}
			}
		}
	}

	// If no context detected but reflected, return originals
	if len(optimized) == 0 {
		return payloads
	}

	return optimized
}

// Helper to extract evidence
func extractEvidence(html, payload string) string {
	idx := strings.Index(strings.ToLower(html), strings.ToLower(payload))
	if idx == -1 {
		return ""
	}
	start := idx - EvidenceContextRadius
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + EvidenceContextRadius
	if end > len(html) {
		end = len(html)
	}
	return "..." + html[start:end] + "..."
}
