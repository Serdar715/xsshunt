package scanner

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/xsshunt/internal/config"
	"github.com/Serdar715/xsshunt/internal/payloads"
	"github.com/Serdar715/xsshunt/internal/waf"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
)

const (
	DefaultBrowserWaitTime = 1500 * time.Millisecond
	EvidenceContextRadius  = 50
	ContextDetectionRadius = 100
	RandomStringLength     = 8
)

// Scanner is the main XSS scanner with proxy and auth support
type Scanner struct {
	config      *config.ScanConfig
	ctx         context.Context
	cancel      context.CancelFunc
	allocCancel context.CancelFunc // Dedicated cancel for the allocator
	payloadGen  *payloads.Generator
	wafDetector *waf.Detector
	results     *config.ScanResult
	mu          sync.Mutex
	seenVulns   map[string]bool // Track unique vulnerabilities to avoid duplicates
	lastRequest time.Time       // For rate limiting
}

// New creates a new XSS scanner instance with proxy and auth support
func New(cfg *config.ScanConfig) (*Scanner, error) {
	// Suppress chromedp internal logging
	log.SetOutput(io.Discard)

	// Build browser options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", !cfg.VisibleMode),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-plugins", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-logging", true),
		chromedp.Flag("log-level", "3"),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	// Add proxy configuration if enabled
	if cfg.ProxyEnabled && cfg.ProxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(cfg.ProxyURL))
		color.Yellow("[*] Using proxy: %s", cfg.ProxyURL)
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Create context with error logging disabled
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(format string, args ...interface{}) {}))

	// Set timeout
	ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Minute)

	// Create WAF detector with proxy support
	wafDet := waf.NewDetectorWithProxy(cfg.ProxyURL, cfg.Cookies, cfg.Headers)

	scanner := &Scanner{
		config:      cfg,
		ctx:         ctx,
		cancel:      cancel,
		allocCancel: allocCancel,
		payloadGen:  payloads.NewGenerator(cfg.SmartPayload),
		wafDetector: wafDet,
		results: &config.ScanResult{
			TargetURL:       cfg.TargetURL,
			ScanStartTime:   time.Now(),
			Vulnerabilities: make([]config.Vulnerability, 0),
			Errors:          make([]string, 0),
			ProxyUsed:       cfg.ProxyURL,
			Authenticated:   cfg.Cookies != "" || cfg.AuthHeader != "",
		},
		seenVulns:   make(map[string]bool),
		lastRequest: time.Now(),
	}

	return scanner, nil
}

// Close cleans up scanner resources
func (s *Scanner) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.allocCancel != nil {
		s.allocCancel()
	}
}

// Scan performs the XSS scan
func (s *Scanner) Scan() (*config.ScanResult, error) {
	defer func() {
		s.results.ScanEndTime = time.Now()
		s.results.ScanDuration = s.results.ScanEndTime.Sub(s.results.ScanStartTime).String()
	}()

	// Parse target URL
	parsedURL, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Detect WAF
	if s.config.WAFType == "auto" {
		color.Yellow("[*] Detecting WAF...")
		detectedWAF, err := s.wafDetector.Detect(s.config.TargetURL)
		if err != nil {
			color.Yellow("[!] WAF detection failed: %v", err)
		} else if detectedWAF != "" {
			s.results.WAFDetected = detectedWAF
			color.Yellow("[!] WAF Detected: %s", detectedWAF)
		} else {
			color.Green("[✓] No WAF detected")
		}
	} else {
		s.results.WAFDetected = s.config.WAFType
	}

	// Get payloads
	var payloadList []string
	if s.config.PayloadFile != "" {
		payloadList, err = s.payloadGen.LoadFromFile(s.config.PayloadFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load payloads: %w", err)
		}
	} else {
		payloadList = s.payloadGen.GetPayloads(s.results.WAFDetected)
	}

	s.results.TotalPayloads = len(payloadList)
	color.Cyan("[*] Loaded %d payloads", len(payloadList))

	// Check if header fuzzing mode is enabled
	if s.config.FuzzMode && len(s.config.FuzzHeaders) > 0 {
		color.Cyan("\n[*] Header Fuzzing Mode enabled")
		return s.scanHeaderFuzzing(payloadList)
	}

	// Extract parameters from URL
	params := parsedURL.Query()
	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)

	// Test each parameter
	for paramName := range params {
		color.Cyan("\n[*] Testing parameter: %s", paramName)

		// Intelligent Analysis: Probe parameter for context and filtering
		probeResult := s.analyzeParameter(baseURL, paramName, params)
		optimizedPayloads := s.filterPayloads(payloadList, probeResult)

		if len(optimizedPayloads) == 0 {
			if s.config.Verbose {
				color.Yellow("  [!] No suitable payloads found after analysis (strict filtering detected)")
			}
			continue
		}

		// Use worker pool for concurrent testing
		jobChan := make(chan string, len(optimizedPayloads))
		var wg sync.WaitGroup

		// Start workers
		for i := 0; i < s.config.Threads; i++ {
			wg.Add(1)
			go s.worker(&wg, jobChan, baseURL, paramName, params)
		}

		// Send jobs
		for _, payload := range optimizedPayloads {
			jobChan <- payload
		}
		close(jobChan)

		// Wait for completion
		wg.Wait()
	}

	return s.results, nil
}

// scanHeaderFuzzing performs header-based XSS testing
func (s *Scanner) scanHeaderFuzzing(payloadList []string) (*config.ScanResult, error) {
	// Find headers with FUZZ marker
	var fuzzableHeaders []string
	for _, header := range s.config.FuzzHeaders {
		if strings.Contains(header, "FUZZ") {
			fuzzableHeaders = append(fuzzableHeaders, header)
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				color.Cyan("[*] Will fuzz header: %s", strings.TrimSpace(parts[0]))
			}
		}
	}

	if len(fuzzableHeaders) == 0 {
		return s.results, fmt.Errorf("no headers with FUZZ marker found")
	}

	// Use worker pool for concurrent testing
	type job struct {
		header  string
		payload string
	}

	jobChan := make(chan job, len(payloadList)*len(fuzzableHeaders))
	var wg sync.WaitGroup

	// Start workers - use closure to capture job channel type
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobChan {
				s.processHeaderFuzzJob(j.header, j.payload)
			}
		}()
	}

	// Send jobs for each header and payload combination
	for _, header := range fuzzableHeaders {
		for _, payload := range payloadList {
			jobChan <- job{header: header, payload: payload}
		}
	}
	close(jobChan)

	// Wait for completion
	wg.Wait()

	return s.results, nil
}

// processHeaderFuzzJob processes a single header fuzzing job
func (s *Scanner) processHeaderFuzzJob(header, payload string) {
	// Apply rate limiting
	s.applyRateLimit()

	s.mu.Lock()
	s.results.TestedPayloads++
	currentCount := s.results.TestedPayloads
	s.mu.Unlock()

	// Parse header
	parts := strings.SplitN(header, ":", 2)
	if len(parts) != 2 {
		return
	}
	headerName := strings.TrimSpace(parts[0])
	headerValue := strings.TrimSpace(parts[1])

	// Replace FUZZ with payload
	fuzzedValue := strings.ReplaceAll(headerValue, "FUZZ", payload)

	if s.config.Verbose {
		color.White("  [%d/%d] Testing header %s: %s",
			currentCount, s.results.TotalPayloads*len(s.config.FuzzHeaders),
			headerName, truncate(fuzzedValue, 40))
	}

	// Test the header-based XSS
	vuln, err := s.testHeaderPayload(headerName, fuzzedValue, payload)
	if err != nil {
		s.mu.Lock()
		s.results.ErrorCount++
		if s.config.Verbose {
			s.results.Errors = append(s.results.Errors, err.Error())
		}
		s.mu.Unlock()
		return
	}

	if vuln != nil {
		vulnKey := s.generateVulnKey(vuln)
		s.mu.Lock()
		if !s.seenVulns[vulnKey] {
			s.seenVulns[vulnKey] = true
			s.results.Vulnerabilities = append(s.results.Vulnerabilities, *vuln)
			s.mu.Unlock()
			color.Red("  [!] Header XSS Found in %s: %s", headerName, truncate(payload, 50))
		} else {
			s.mu.Unlock()
		}
	}
}

// testHeaderPayload tests a payload injected into a header
func (s *Scanner) testHeaderPayload(headerName, headerValue, originalPayload string) (*config.Vulnerability, error) {
	var htmlContent string
	var dialogShown bool
	var dialogMessage string
	var xssExecuted bool

	// Create new context for this test
	ctx, cancel := chromedp.NewContext(s.ctx)
	defer cancel()

	// Create a unique marker for this test
	marker := fmt.Sprintf("XSSHUNT_%d_%s", time.Now().UnixNano(), randomString(8))

	// Set up the fuzzed header
	fuzzedHeaders := make(map[string]interface{})
	for k, v := range s.config.Headers {
		fuzzedHeaders[k] = v
	}
	fuzzedHeaders[headerName] = headerValue

	// Set up dialog handler
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			dialogShown = true
			dialogMessage = e.Message
			xssExecuted = true
			go chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				return page.HandleJavaScriptDialog(true).Do(ctx)
			}))
		}
	})

	// Enable network and set headers
	err := chromedp.Run(ctx,
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(fuzzedHeaders)),
	)
	if err != nil {
		return nil, err
	}

	// Set cookies if configured
	if s.config.Cookies != "" {
		parsedURL, _ := url.Parse(s.config.TargetURL)
		cookies := parseCookieString(s.config.Cookies, parsedURL.Host)
		if len(cookies) > 0 {
			_ = chromedp.Run(ctx, network.SetCookies(cookies))
		}
	}

	// Navigate and check for XSS
	err = chromedp.Run(ctx,
		chromedp.Navigate(s.config.TargetURL),
		chromedp.Sleep(DefaultBrowserWaitTime),
		chromedp.OuterHTML("html", &htmlContent),
	)
	if err != nil {
		return nil, err
	}

	// Check if marker was set
	var markerExists bool
	testPayload := s.injectMarker(originalPayload, marker)
	if strings.Contains(headerValue, "alert") {
		checkScript := fmt.Sprintf("window['%s'] === true", marker)
		_ = chromedp.Run(ctx, chromedp.Evaluate(checkScript, &markerExists))
		if markerExists {
			xssExecuted = true
		}
	}

	// Check for confirmed XSS execution
	if dialogShown || xssExecuted {
		evidence := "JavaScript executed via header injection"
		if dialogMessage != "" {
			evidence = fmt.Sprintf("Dialog triggered: %s", dialogMessage)
		}
		return &config.Vulnerability{
			Type:        "Header-based XSS (Confirmed)",
			Payload:     originalPayload,
			URL:         s.config.TargetURL,
			Parameter:   headerName,
			Context:     fmt.Sprintf("Header: %s", headerName),
			Severity:    "Critical",
			WAFBypassed: s.results.WAFDetected != "",
			Evidence:    evidence,
		}, nil
	}

	// Check if payload is reflected in response
	if strings.Contains(htmlContent, originalPayload) || strings.Contains(htmlContent, testPayload) {
		reflectionResult := s.analyzeReflection(htmlContent, originalPayload)
		if reflectionResult != nil && reflectionResult.IsDangerous {
			return &config.Vulnerability{
				Type:        "Header-based XSS (Reflected)",
				Payload:     originalPayload,
				URL:         s.config.TargetURL,
				Parameter:   headerName,
				Context:     fmt.Sprintf("Header: %s - %s", headerName, reflectionResult.Context),
				Severity:    reflectionResult.Severity,
				WAFBypassed: s.results.WAFDetected != "",
				Evidence:    reflectionResult.Evidence,
			}, nil
		}
	}

	return nil, nil
}

// worker processes payloads from the job channel
func (s *Scanner) worker(wg *sync.WaitGroup, jobs <-chan string, baseURL, paramName string, params url.Values) {
	defer wg.Done()

	for payload := range jobs {
		// Apply rate limiting
		s.applyRateLimit()

		s.mu.Lock()
		s.results.TestedPayloads++
		currentCount := s.results.TestedPayloads
		s.mu.Unlock()

		if s.config.Verbose {
			color.White("  [%d/%d] Testing: %s", currentCount, s.results.TotalPayloads, truncate(payload, 50))
		}

		// Create test URL
		testParams := cloneParams(params)
		testParams.Set(paramName, payload)
		testURL := baseURL + "?" + testParams.Encode()

		// Test for XSS
		vuln, err := s.testPayload(testURL, payload, paramName)
		if err != nil {
			s.mu.Lock()
			s.results.ErrorCount++
			if s.config.Verbose {
				s.results.Errors = append(s.results.Errors, err.Error())
			}
			s.mu.Unlock()
			continue
		}

		if vuln != nil {
			// Create unique key for this vulnerability to avoid duplicates
			vulnKey := s.generateVulnKey(vuln)
			s.mu.Lock()
			if !s.seenVulns[vulnKey] {
				s.seenVulns[vulnKey] = true
				s.results.Vulnerabilities = append(s.results.Vulnerabilities, *vuln)
				s.mu.Unlock()
				color.Red("  [!] XSS Found: %s", truncate(payload, 60))
			} else {
				s.mu.Unlock()
			}
		}
	}
}

// applyRateLimit enforces delay between requests
func (s *Scanner) applyRateLimit() {
	if s.config.Delay <= 0 {
		return
	}

	s.mu.Lock()
	elapsed := time.Since(s.lastRequest)
	delay := time.Duration(s.config.Delay) * time.Millisecond

	if elapsed < delay {
		sleepTime := delay - elapsed
		s.mu.Unlock()
		time.Sleep(sleepTime)
		s.mu.Lock()
	}

	s.lastRequest = time.Now()
	s.mu.Unlock()
}

// generateVulnKey creates a unique key for a vulnerability
func (s *Scanner) generateVulnKey(vuln *config.Vulnerability) string {
	data := fmt.Sprintf("%s:%s:%s", vuln.Type, vuln.Parameter, vuln.Context)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// testPayload tests a single payload for XSS vulnerability
func (s *Scanner) testPayload(testURL, payload, param string) (*config.Vulnerability, error) {
	var htmlContent string
	var dialogShown bool
	var dialogMessage string
	var xssExecuted bool

	// Create new context for this test
	ctx, cancel := chromedp.NewContext(s.ctx)
	defer cancel()

	// Create a unique marker for this test
	marker := fmt.Sprintf("XSSHUNT_%d_%s", time.Now().UnixNano(), randomString(8))

	// Set up cookies and headers if configured
	if s.config.Cookies != "" || len(s.config.Headers) > 0 {
		if err := s.setupAuthentication(ctx); err != nil {
			return nil, fmt.Errorf("auth setup failed: %w", err)
		}
	}

	// Set up dialog handler to detect alert/confirm/prompt
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			dialogShown = true
			dialogMessage = e.Message
			xssExecuted = true
			// Automatically dismiss the dialog
			go chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				return page.HandleJavaScriptDialog(true).Do(ctx)
			}))
		}
	})

	// Modify payloads to set a marker when executed (for verification)
	testPayload := s.injectMarker(payload, marker)

	// Build test URL with modified payload
	parsedURL, _ := url.Parse(testURL)
	testParams := parsedURL.Query()
	for key := range testParams {
		if testParams.Get(key) == payload || strings.Contains(testParams.Get(key), payload) {
			testParams.Set(key, testPayload)
		}
	}
	modifiedURL := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, testParams.Encode())

	// Navigate and check for XSS
	err := chromedp.Run(ctx,
		chromedp.Navigate(modifiedURL),
		chromedp.Sleep(DefaultBrowserWaitTime), // Wait for JS execution
		chromedp.OuterHTML("html", &htmlContent),
	)
	if err != nil {
		return nil, err
	}

	// Check if our marker was set (confirms JavaScript execution)
	var markerExists bool
	checkScript := fmt.Sprintf("window['%s'] === true", marker)
	_ = chromedp.Run(ctx, chromedp.Evaluate(checkScript, &markerExists))

	if markerExists {
		xssExecuted = true
	}

	// PRIORITY 1: Confirmed JavaScript execution (DOM-based XSS)
	if dialogShown || xssExecuted {
		evidence := "JavaScript code executed successfully in browser"
		if dialogMessage != "" {
			evidence = fmt.Sprintf("Dialog triggered with message: %s", dialogMessage)
		}
		return &config.Vulnerability{
			Type:        "DOM-based XSS (Confirmed)",
			Payload:     payload,
			URL:         testURL,
			Parameter:   param,
			Context:     "JavaScript execution verified",
			Severity:    "Critical",
			WAFBypassed: s.results.WAFDetected != "",
			Evidence:    evidence,
		}, nil
	}

	// PRIORITY 2: Check for reflected XSS with strict validation
	reflectionResult := s.analyzeReflection(htmlContent, payload)
	if reflectionResult != nil && reflectionResult.IsDangerous {
		return &config.Vulnerability{
			Type:        reflectionResult.VulnType,
			Payload:     payload,
			URL:         testURL,
			Parameter:   param,
			Context:     reflectionResult.Context,
			Severity:    reflectionResult.Severity,
			WAFBypassed: s.results.WAFDetected != "",
			Evidence:    reflectionResult.Evidence,
		}, nil
	}

	return nil, nil
}

// setupAuthentication sets up cookies and headers for authenticated scanning
func (s *Scanner) setupAuthentication(ctx context.Context) error {
	// Parse target URL for domain
	parsedURL, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return err
	}

	// Set cookies if provided
	if s.config.Cookies != "" {
		cookies := parseCookieString(s.config.Cookies, parsedURL.Host)
		if len(cookies) > 0 {
			err := chromedp.Run(ctx, network.SetCookies(cookies))
			if err != nil {
				return fmt.Errorf("failed to set cookies: %w", err)
			}
		}
	}

	// Set extra headers if provided
	if len(s.config.Headers) > 0 || s.config.AuthHeader != "" {
		headers := make(map[string]interface{})
		for k, v := range s.config.Headers {
			headers[k] = v
		}
		if s.config.AuthHeader != "" {
			headers["Authorization"] = s.config.AuthHeader
		}

		err := chromedp.Run(ctx, network.SetExtraHTTPHeaders(network.Headers(headers)))
		if err != nil {
			return fmt.Errorf("failed to set headers: %w", err)
		}
	}

	return nil
}

// parseCookieString parses a cookie string into network.CookieParam slice
func parseCookieString(cookieStr, domain string) []*network.CookieParam {
	var cookies []*network.CookieParam

	pairs := strings.Split(cookieStr, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		cookies = append(cookies, &network.CookieParam{
			Name:   name,
			Value:  value,
			Domain: domain,
			Path:   "/",
		})
	}

	return cookies
}

// ReflectionResult holds the analysis result of a reflected payload
type ReflectionResult struct {
	IsDangerous bool
	VulnType    string
	Context     string
	Severity    string
	Evidence    string
}

// analyzeReflection performs deep analysis of how the payload is reflected
func (s *Scanner) analyzeReflection(html, payload string) *ReflectionResult {
	// Step 1: Check for exact unencoded reflection
	if !strings.Contains(html, payload) {
		// Try URL decoded version
		decodedPayload, _ := url.QueryUnescape(payload)
		if !strings.Contains(html, decodedPayload) {
			return nil // Payload not reflected at all
		}
		payload = decodedPayload
	}

	// Step 2: Check if payload is inside HTML comments (not exploitable)
	if s.isInsideHTMLComment(html, payload) {
		return nil
	}

	// Step 3: Check if payload is properly HTML-encoded
	if s.isProperlyEncoded(html, payload) {
		return nil // Properly encoded, not vulnerable
	}

	// Step 4: Determine the injection context
	context := s.detectContextAdvanced(html, payload)

	// Step 5: Evaluate danger based on context and payload structure
	return s.evaluateDanger(context, payload, html)
}

// isInsideHTMLComment checks if the payload is inside an HTML comment
func (s *Scanner) isInsideHTMLComment(html, payload string) bool {
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

// isProperlyEncoded checks if dangerous characters are properly encoded
func (s *Scanner) isProperlyEncoded(html, payload string) bool {
	dangerousChars := map[string][]string{
		"<":  {"&lt;", "&#60;", "&#x3c;"},
		">":  {"&gt;", "&#62;", "&#x3e;"},
		"\"": {"&quot;", "&#34;", "&#x22;"},
		"'":  {"&#39;", "&#x27;", "&apos;"},
	}

	idx := strings.Index(html, payload)
	if idx != -1 {
		return false // If exact payload is found, it's not encoded
	}

	for char, encodings := range dangerousChars {
		if strings.Contains(payload, char) {
			for _, encoding := range encodings {
				encodedPayload := strings.ReplaceAll(payload, char, encoding)
				if strings.Contains(html, encodedPayload) {
					return true
				}
			}
		}
	}

	return false
}

// detectContextAdvanced performs advanced context detection
func (s *Scanner) detectContextAdvanced(html, payload string) string {
	lowerHTML := strings.ToLower(html)
	lowerPayload := strings.ToLower(payload)

	idx := strings.Index(lowerHTML, lowerPayload)
	if idx == -1 {
		return "Unknown"
	}

	start := idx - ContextDetectionRadius
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + ContextDetectionRadius
	if end > len(lowerHTML) {
		end = len(lowerHTML)
	}
	surrounding := lowerHTML[start:end]
	before := lowerHTML[start:idx]

	// Check for script tag context
	scriptOpenRe := regexp.MustCompile(`<script[^>]*>`)
	scriptCloseRe := regexp.MustCompile(`</script>`)

	lastScriptIdx := strings.LastIndex(before, "<script")
	if lastScriptIdx != -1 && scriptOpenRe.MatchString(before) && !scriptCloseRe.MatchString(before[lastScriptIdx:]) {
		return "JavaScript context"
	}

	// Check for event handler context
	eventHandlerRe := regexp.MustCompile(`\son\w+\s*=\s*["']?[^"']*$`)
	if eventHandlerRe.MatchString(before) {
		return "Event handler context"
	}

	// Check for URL attribute context
	urlAttrRe := regexp.MustCompile(`(href|src|action|data|formaction)\s*=\s*["']?[^"']*$`)
	if urlAttrRe.MatchString(before) {
		if strings.Contains(lowerPayload, "javascript:") {
			return "JavaScript URL context"
		}
		return "URL attribute context"
	}

	// Check for style context
	styleRe := regexp.MustCompile(`(<style[^>]*>|style\s*=\s*["'])[^<]*$`)
	if styleRe.MatchString(before) {
		return "CSS context"
	}

	// Check for HTML attribute context
	attrRe := regexp.MustCompile(`<\w+[^>]*\s+\w+\s*=\s*["']?[^"'>]*$`)
	if attrRe.MatchString(before) {
		return "HTML attribute context"
	}

	// Check for template literal context
	if strings.Contains(surrounding, "${") && strings.Contains(surrounding, "`") {
		return "Template literal context"
	}

	return "HTML body context"
}

// evaluateDanger determines if the reflection is actually dangerous
func (s *Scanner) evaluateDanger(context, payload, html string) *ReflectionResult {
	lowerPayload := strings.ToLower(payload)

	switch context {
	case "JavaScript context":
		if s.canExecuteInJSContext(payload, html) {
			return &ReflectionResult{
				IsDangerous: true,
				VulnType:    "Reflected XSS (High Confidence)",
				Context:     context,
				Severity:    "Critical",
				Evidence:    extractEvidence(html, payload),
			}
		}

	case "Event handler context":
		if s.containsExecutableCode(payload) {
			return &ReflectionResult{
				IsDangerous: true,
				VulnType:    "Reflected XSS (Event Handler)",
				Context:     context,
				Severity:    "High",
				Evidence:    extractEvidence(html, payload),
			}
		}

	case "JavaScript URL context":
		if strings.Contains(lowerPayload, "javascript:") {
			return &ReflectionResult{
				IsDangerous: true,
				VulnType:    "Reflected XSS (JavaScript URL)",
				Context:     context,
				Severity:    "High",
				Evidence:    extractEvidence(html, payload),
			}
		}

	case "HTML body context":
		if s.canInjectHTMLTags(payload, html) {
			return &ReflectionResult{
				IsDangerous: true,
				VulnType:    "Reflected XSS (Tag Injection)",
				Context:     context,
				Severity:    "High",
				Evidence:    extractEvidence(html, payload),
			}
		}

	case "HTML attribute context":
		if s.canBreakOutOfAttribute(payload, html) {
			return &ReflectionResult{
				IsDangerous: true,
				VulnType:    "Reflected XSS (Attribute Breakout)",
				Context:     context,
				Severity:    "Medium",
				Evidence:    extractEvidence(html, payload),
			}
		}

	case "URL attribute context":
		if strings.Contains(lowerPayload, "javascript:") || strings.Contains(lowerPayload, "data:") {
			return &ReflectionResult{
				IsDangerous: true,
				VulnType:    "Reflected XSS (URL Injection)",
				Context:     context,
				Severity:    "High",
				Evidence:    extractEvidence(html, payload),
			}
		}
	}

	return nil
}

// canExecuteInJSContext checks if payload can execute in JavaScript context
func (s *Scanner) canExecuteInJSContext(payload, html string) bool {
	execPatterns := []string{
		"alert(", "confirm(", "prompt(",
		"eval(", "Function(", "setTimeout(",
		"setInterval(", "document.", "window.",
		".innerHTML", ".outerHTML", "location",
	}

	lowerPayload := strings.ToLower(payload)
	for _, pattern := range execPatterns {
		if strings.Contains(lowerPayload, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// containsExecutableCode checks if payload contains executable JavaScript
func (s *Scanner) containsExecutableCode(payload string) bool {
	lowerPayload := strings.ToLower(payload)

	funcCallRe := regexp.MustCompile(`[a-z_$][a-z0-9_$]*\s*\(`)
	if funcCallRe.MatchString(lowerPayload) {
		return true
	}

	dangerousPatterns := []string{
		"alert", "confirm", "prompt", "eval", "function",
		"settimeout", "setinterval", "document", "window",
		"location", "cookie", "innerhtml", "outerhtml",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPayload, pattern) {
			return true
		}
	}

	return false
}

// canInjectHTMLTags checks if we can inject HTML tags
func (s *Scanner) canInjectHTMLTags(payload, html string) bool {
	tagPatterns := []string{
		`<script`, `<img`, `<svg`, `<body`, `<iframe`,
		`<input`, `<form`, `<a\s`, `<div`, `<marquee`,
		`<object`, `<embed`, `<video`, `<audio`, `<details`,
	}

	lowerPayload := strings.ToLower(payload)

	for _, pattern := range tagPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(lowerPayload) {
			if strings.Contains(strings.ToLower(html), strings.ToLower(strings.ReplaceAll(payload, " ", ""))) {
				return true
			}
		}
	}

	return false
}

// canBreakOutOfAttribute checks if we can break out of an HTML attribute
func (s *Scanner) canBreakOutOfAttribute(payload, html string) bool {
	idx := strings.Index(html, payload)
	if idx == -1 {
		return false
	}

	// Limit search window to find the attribute definition
	startSearch := idx - 100
	if startSearch < 0 {
		startSearch = 0
	}
	before := html[startSearch:idx]

	// Find the last equals sign which likely denotes the attribute assignment
	lastEquals := strings.LastIndex(before, "=")
	if lastEquals == -1 {
		// Fallback to strict check if we can't find the structure
		return strings.ContainsAny(payload, `"'><`)
	}

	// Check what follows the equals sign (ignoring whitespace)
	// We want to find the opening quote of the attribute
	afterEquals := strings.TrimLeft(before[lastEquals+1:], " \t\n\r")

	if len(afterEquals) == 0 {
		// Case: name=PAYLOAD (Unquoted)
		// Dangerous chars: space, >, slash, tag start
		return strings.ContainsAny(payload, " />\t\n")
	}

	quoteChar := afterEquals[0]
	if quoteChar == '"' {
		// Case: name="PAYLOAD (Double quoted)
		// Only " breaks out. ' is safe.
		return strings.Contains(payload, "\"")
	} else if quoteChar == '\'' {
		// Case: name='PAYLOAD (Single quoted)
		// Only ' breaks out. " is safe.
		return strings.Contains(payload, "'")
	} else {
		// Case: name=valPAYLOAD (Unquoted or part of value)
		// Treated as unquoted: space, >, etc. break out
		return strings.ContainsAny(payload, " />\t\n")
	}
}

// injectMarker adds a unique marker to the payload for verification
func (s *Scanner) injectMarker(payload, marker string) string {
	replacements := map[string]string{
		"alert(1)":       fmt.Sprintf("(window['%s']=true)", marker),
		"alert('XSS')":   fmt.Sprintf("(window['%s']=true)", marker),
		"alert(\"XSS\")": fmt.Sprintf("(window['%s']=true)", marker),
		"confirm(1)":     fmt.Sprintf("(window['%s']=true)", marker),
		"prompt(1)":      fmt.Sprintf("(window['%s']=true)", marker),
		"confirm()":      fmt.Sprintf("(window['%s']=true)", marker),
		"confirm``":      fmt.Sprintf("(window['%s']=true)", marker),
	}

	result := payload
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	return result
}

// Helper functions

func cloneParams(params url.Values) url.Values {
	clone := make(url.Values)
	for k, v := range params {
		clone[k] = append([]string{}, v...)
	}
	return clone
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

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

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			// Fallback in extremely rare case of crypto/rand failure, or handle error better
			// For this context, we'll just skip (or could panic/log)
			return "fallback_id"
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

// CreateHTTPClient creates an HTTP client with proxy support
func CreateHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURLParsed)
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
