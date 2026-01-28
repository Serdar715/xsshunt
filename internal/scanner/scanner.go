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
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/xsshunt/internal/config"
	"github.com/Serdar715/xsshunt/internal/payloads"
	"github.com/Serdar715/xsshunt/internal/reporter"
	"github.com/Serdar715/xsshunt/internal/waf"

	"github.com/fatih/color"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// Constants are imported from constants.go (same package)

// Scanner is the main XSS scanner with proxy and auth support
// Scanner is the main XSS scanner with proxy and auth support
type Scanner struct {
	config      *config.ScanConfig
	ctx         context.Context // Main context for cancellation
	cancel      context.CancelFunc
	payloadGen  *payloads.Generator
	wafDetector *waf.Detector
	results     *config.ScanResult
	mu          sync.Mutex
	seenVulns   map[string]bool // Track unique vulnerabilities to avoid duplicates
	lastRequest time.Time       // For rate limiting

	// New fields for Rod and Hybrid scanning
	browser  *rod.Browser
	pagePool rod.Pool[rod.Page]
	analyzer *Analyzer // Delegated analysis logic

	// Strategy for XSS verification (Approach C)
	strategy VerificationStrategy
}

// New creates a new XSS scanner instance with Rod and hybrid support
func New(cfg *config.ScanConfig) (*Scanner, error) {
	// Suppress internal logging
	log.SetOutput(io.Discard)

	// Context for cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize HTTP Client for hybrid/smart scanning
	httpClient := CreateHTTPClient(cfg.ProxyURL, time.Duration(cfg.Timeout)*time.Second)

	// Initialize Analyzer
	analyzer := NewAnalyzer(cfg, httpClient)
	analyzer.SetContext(ctx)

	// Initialize Rod Browser
	// We use a custom launcher to configure headless mode and other flags
	browserLauncher := launcher.New().
		Headless(!cfg.VisibleMode).
		Set("disable-gpu", "true").
		Set("no-sandbox", "true").
		Set("disable-dev-shm-usage", "true").
		Set("disable-web-security", "true").
		Set("ignore-certificate-errors", "true").
		Set("disable-extensions", "true").
		Set("disable-popup-blocking", "true"). // Important for XSS popups
		Set("disable-translate", "true").
		Set("disable-sync", "true")

	if cfg.ProxyEnabled && cfg.ProxyURL != "" {
		browserLauncher = browserLauncher.Proxy(cfg.ProxyURL)
		color.Yellow("[*] Using proxy: %s", cfg.ProxyURL)
	}

	controlURL, err := browserLauncher.Launch()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}

	browser := rod.New().ControlURL(controlURL).MustConnect()

	// Initialize Page Pool (limit to Threads count * 2 to avoid memory explosion)
	// This reuses pages instead of creating/destroying them constantly
	pagePool := rod.NewPagePool(cfg.Threads * 2)

	// Create WAF detector
	wafDet := waf.NewDetectorWithProxy(cfg.ProxyURL, cfg.Cookies, cfg.Headers)

	scanner := &Scanner{
		config:      cfg,
		ctx:         ctx,
		cancel:      cancel,
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
		browser:     browser,
		pagePool:    pagePool,
		analyzer:    analyzer,
		// Approach C: Default strategy with timeouts from config
		strategy: NewAlertStrategy(
			time.Duration(cfg.NavigationDelay)*time.Millisecond,
			time.Duration(cfg.BrowserWaitTime)*time.Millisecond,
		),
	}

	return scanner, nil
}

// Close cleans up scanner resources
func (s *Scanner) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.browser != nil {
		s.browser.MustClose()
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
	if !s.config.Silent {
		color.Cyan("[*] Loaded %d payloads", len(payloadList))
	}

	// Check if header fuzzing mode is enabled
	if s.config.FuzzMode && len(s.config.FuzzHeaders) > 0 {
		if !s.config.Silent {
			color.Cyan("\n[*] Header Fuzzing Mode enabled")
		}
		return s.scanHeaderFuzzing(payloadList)
	}

	// Extract parameters from URL
	params := parsedURL.Query()
	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)

	// Test each parameter
	for paramName := range params {
		if !s.config.Silent {
			color.Cyan("\n[*] Testing parameter: %s", paramName)
		}

		// Intelligent Analysis (Delegated to Analyzer)
		probeResult := s.analyzer.AnalyzeParameter(baseURL, paramName, params)

		// Payload selection (Delegated to Analyzer)
		optimizedPayloads := s.analyzer.FilterPayloads(payloadList, probeResult)

		if len(optimizedPayloads) == 0 {
			if s.config.Verbose {
				color.Yellow("  [!] No suitable payloads found after analysis (strict filtering detected)")
			}
			continue
		}

		// Worker Pool
		jobChan := make(chan string, len(optimizedPayloads))
		var wg sync.WaitGroup

		for i := 0; i < s.config.Threads; i++ {
			wg.Add(1)
			go s.worker(&wg, jobChan, baseURL, paramName, params)
		}

		for _, payload := range optimizedPayloads {
			jobChan <- payload
		}
		close(jobChan)
		wg.Wait()
	}

	// Report Results
	rep := reporter.New(s.config)
	if err := rep.SaveResults(s.results); err != nil {
		color.Red("[!] Failed to save report: %v", err)
	}

	return s.results, nil
}

// worker processes payloads from the job channel
func (s *Scanner) worker(wg *sync.WaitGroup, jobs <-chan string, baseURL, paramName string, params url.Values) {
	defer wg.Done()

	for payload := range jobs {
		s.applyRateLimit()

		s.mu.Lock()
		s.results.TestedPayloads++
		currentCount := s.results.TestedPayloads
		s.mu.Unlock()

		if s.config.Verbose {
			color.White("  [%d/%d] Testing: %s", currentCount, s.results.TotalPayloads, truncate(payload, 50))
		}

		testParams := cloneParams(params)
		testParams.Set(paramName, payload)
		testURL := baseURL + "?" + testParams.Encode()

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
			vulnKey := s.generateVulnKey(vuln)
			s.mu.Lock()
			if !s.seenVulns[vulnKey] {
				s.seenVulns[vulnKey] = true
				s.results.Vulnerabilities = append(s.results.Vulnerabilities, *vuln)
				vulnCount := len(s.results.Vulnerabilities)
				s.mu.Unlock()

				// Real-time vulnerability reporting
				color.Red("\n  ╔══════════════════════════════════════════════════════════╗")
				color.Red("  ║  🔴 XSS VULNERABILITY FOUND! (#%d)                        ║", vulnCount)
				color.Red("  ╚══════════════════════════════════════════════════════════╝")
				color.Yellow("  Type:      %s", vuln.Type)
				color.White("  Severity:  %s", vuln.Severity)
				color.White("  Parameter: %s", vuln.Parameter)
				color.White("  Context:   %s", vuln.Context)

				if vuln.Verified {
					color.Green("  Verified:  ✅ YES (Method: %s)", vuln.Method)
				} else {
					color.Yellow("  Verified:  ⚠️ NO (Reflection Only) - Check Manually")
				}

				fmt.Println()
				color.Cyan("  Payload: %s", vuln.Payload)
				color.Cyan("  PoC URL: %s", vuln.URL)
				fmt.Println()
			} else {
				s.mu.Unlock()
			}
		}
	}
}

// CheckReflection moved to analyzer.go

// testPayload tests a single payload for XSS vulnerability using Strategy Pattern
func (scanner *Scanner) testPayload(testURL, payload, param string) (*config.Vulnerability, error) {
	// 1. Smart Mode Optimization
	if shouldSkip, err := scanner.checkSmartMode(testURL, payload); err != nil {
		return nil, err
	} else if shouldSkip {
		return nil, nil
	}

	// 2. Prepare Payload & Marker
	marker := fmt.Sprintf("XSSHUNT_%s", randomString(8))
	finalURL, verifiablePayload := scanner.prepareContext(testURL, payload, param, marker)

	var verifyResult VerificationResult

	// 3. Browser Verification (if not StaticOnly)
	if !scanner.config.StaticOnly {
		page, disconnect, err := scanner.setupBrowserPage(finalURL)
		if err == nil {
			defer disconnect()

			// 4. Verification Check (Delegated to Strategy)
			verifyResult, err = scanner.strategy.Verify(scanner.ctx, page, finalURL, marker)
			if err != nil && scanner.config.Verbose {
				// Log verify error but continue to analysis
			}
		} else if scanner.config.Verbose {
			// Log browser setup error
		}
	}

	// 5. Decision Logic
	// Use the structured result from the strategy
	return scanner.analyzeResult(verifyResult.Confirmed, verifyResult.Message, finalURL, verifiablePayload, param, marker)
}

// Helper: Smart Mode Check
func (s *Scanner) checkSmartMode(testURL, payload string) (bool, error) {
	if !s.config.SmartMode {
		return false, nil
	}

	// Skip if URL has fragment (client-side routing risk)
	if strings.Contains(testURL, "#") {
		return false, nil
	}

	// Check HTTP reflection
	score := s.analyzer.CheckReflection(testURL, payload)
	return score < SmartModeScoreThreshold, nil
}

// prepareContext injects the marker using the strategy and builds the final URL
func (scanner *Scanner) prepareContext(testURL, payload, paramName, marker string) (string, string) {
	// Delegate Marker Injection to Strategy
	verifiablePayload := scanner.strategy.InjectMarker(payload, marker)

	if scanner.config.Verbose {
		color.Yellow("    [DEBUG] Original Payload: %s", payload)
		color.Yellow("    [DEBUG] Injected Payload: %s", verifiablePayload)
	}

	parsedURL, _ := url.Parse(testURL)
	params := parsedURL.Query()

	// Directly set the target parameter
	// This avoids encoding mismatch issues that happened with value matching
	params.Set(paramName, verifiablePayload)

	finalURL := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, params.Encode())
	return finalURL, verifiablePayload
}

// Helper: Setup Browser Page
func (s *Scanner) setupBrowserPage(urlStr string) (*rod.Page, func(), error) {
	// Use Page Pool to reuse pages (Drastic RAM reduction)
	// rod.NewPagePool returns Pool[rod.Page], so we work with *rod.Page pointers
	page, err := s.pagePool.Get(func() (*rod.Page, error) {
		p, err := s.browser.Page(proto.TargetCreateTarget{URL: ""})
		if err != nil {
			return nil, err
		}
		return p, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to acquire page from pool: %w", err)
	}

	// Cleanup helper (Return to pool instead of closing)
	disconnect := func() {
		// Stop any pending navigation/scripts
		// We use a separate context to ensure cleanup happens
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			// Try to navigate to blank to stop heavy scripts before putting back
			// This prevents a "dirty" page from consuming CPU in the pool
			if page != nil {
				p := page.Context(ctx)
				_ = p.StopLoading()
				s.pagePool.Put(page)
			}
		}()
	}

	s.setupRodAuthentication(page, urlStr)

	// Set Page Timeout
	timeout := time.Duration(s.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Bind context to page
	pageCtx, cancel := context.WithTimeout(s.ctx, timeout)

	// Chain cleanup to include context cancel
	finalDisconnect := func() {
		cancel()
		disconnect()
	}

	return page.Context(pageCtx), finalDisconnect, nil
}

// Helper: Analyze Result
func (s *Scanner) analyzeResult(executed bool, msg, urlStr, payload, param, marker string) (*config.Vulnerability, error) {
	// 1. Browser Execution (High Confidence)
	if executed {
		isValid := true
		if s.config.StrictVerification && !strings.Contains(msg, marker) && msg != "DOM execution verified via window object" {
			isValid = false
		}

		if isValid {
			return &config.Vulnerability{
				Type:        "Confirmed XSS (Execution Verified)",
				Payload:     payload,
				URL:         urlStr,
				Parameter:   param,
				Context:     "Alert/Execution Confirmed",
				Severity:    "Critical",
				WAFBypassed: s.results.WAFDetected != "",
				Evidence:    fmt.Sprintf("Execution verified: %s", msg),
				Verified:    true,
				Method:      "Browser Execution",
			}, nil
		}
	}

	// 2. Static Reflection Check (Hybrid Mode / Medium Confidence)
	// If execution failed (or was skipped) but StrictVerification is OFF,
	// we check if the payload is reflected in the response body.
	if !s.config.StrictVerification {
		// Use checkReflection to see if payload exists in body
		// Note: checkReflection performs an HTTP request to the URL
		score := s.analyzer.CheckReflection(urlStr, payload)

		if score > ReflectedScoreThreshold { // High reflection match
			return &config.Vulnerability{
				Type:        VulnTypeReflected,
				Payload:     payload,
				URL:         urlStr,
				Parameter:   param,
				Context:     "Source Code Reflection",
				Severity:    SeverityMedium, // Lower severity because not verified by browser
				WAFBypassed: s.results.WAFDetected != "",
				Evidence:    "Payload reflected in response body (Static Analysis)",
				Verified:    false,
				Method:      MethodStatic,
			}, nil
		}
	}

	return nil, nil
}

// scanHeaderFuzzing performs header-based XSS testing
// Note: Refactored to use Rod
func (s *Scanner) scanHeaderFuzzing(payloadList []string) (*config.ScanResult, error) {
	// Simple placeholder for header fuzzing.
	// In a full implementation, this should also use Rod.
	return s.results, nil
}

// Helper: Setup Rod Authentication
func (s *Scanner) setupRodAuthentication(page *rod.Page, urlStr string) {
	parsedURL, _ := url.Parse(urlStr)

	// Cookies
	if s.config.Cookies != "" {
		cookies := parseCookieString(s.config.Cookies, parsedURL.Host)
		var rodCookies []*proto.NetworkCookieParam
		for _, c := range cookies {
			rodCookies = append(rodCookies, &proto.NetworkCookieParam{
				Name:   c.Name,
				Value:  c.Value,
				Domain: c.Domain,
				Path:   c.Path,
			})
		}
		_ = page.SetCookies(rodCookies)
	}

	// Headers
	if len(s.config.Headers) > 0 || s.config.AuthHeader != "" {
		headers := make([]string, 0)
		for k, v := range s.config.Headers {
			headers = append(headers, k, v)
		}
		if s.config.AuthHeader != "" {
			headers = append(headers, "Authorization", s.config.AuthHeader)
		}
		_, _ = page.SetExtraHeaders(headers)
	}
}

func (s *Scanner) addHeadersToRequest(req *http.Request) {
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}
	if s.config.AuthHeader != "" {
		req.Header.Set("Authorization", s.config.AuthHeader)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (XSSHunt)")
}

func (s *Scanner) addCookiesToRequest(req *http.Request, urlStr string) {
	if s.config.Cookies != "" {
		req.Header.Set("Cookie", s.config.Cookies)
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

func (s *Scanner) generateVulnKey(vuln *config.Vulnerability) string {
	data := fmt.Sprintf("%s:%s:%s", vuln.Type, vuln.Parameter, vuln.Context)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Utility: Create HTTP Client (Optimized Transport)
func CreateHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500, // Increased for concurrent scanning
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
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

// Cookie Parser
type ParsedCookie struct {
	Name, Value, Domain, Path string
}

func parseCookieString(cookieStr, domain string) []ParsedCookie {
	var cookies []ParsedCookie
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
		cookies = append(cookies, ParsedCookie{
			Name:   strings.TrimSpace(parts[0]),
			Value:  strings.TrimSpace(parts[1]),
			Domain: domain,
			Path:   "/",
		})
	}
	return cookies
}

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

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "fallback_id"
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}
