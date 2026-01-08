package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"xsshunt/internal/config"
	"xsshunt/internal/payloads"
	"xsshunt/internal/waf"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
)

// Scanner is the main XSS scanner
type Scanner struct {
	config      *config.ScanConfig
	ctx         context.Context
	cancel      context.CancelFunc
	payloadGen  *payloads.Generator
	wafDetector *waf.Detector
	results     *config.ScanResult
	mu          sync.Mutex
}

// New creates a new XSS scanner instance
func New(cfg *config.ScanConfig) (*Scanner, error) {
	// Create browser context
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", !cfg.VisibleMode),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	allocCtx, _ := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)

	// Set timeout
	ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Minute)

	return &Scanner{
		config:      cfg,
		ctx:         ctx,
		cancel:      cancel,
		payloadGen:  payloads.NewGenerator(cfg.SmartPayload),
		wafDetector: waf.NewDetector(),
		results: &config.ScanResult{
			TargetURL:       cfg.TargetURL,
			ScanStartTime:   time.Now(),
			Vulnerabilities: make([]config.Vulnerability, 0),
			Errors:          make([]string, 0),
		},
	}, nil
}

// Close cleans up scanner resources
func (s *Scanner) Close() {
	if s.cancel != nil {
		s.cancel()
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

	// Extract parameters from URL
	params := parsedURL.Query()
	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)

	// Test each parameter
	for paramName := range params {
		color.Cyan("\n[*] Testing parameter: %s", paramName)

		// Use worker pool for concurrent testing
		jobChan := make(chan string, len(payloadList))
		var wg sync.WaitGroup

		// Start workers
		for i := 0; i < s.config.Threads; i++ {
			wg.Add(1)
			go s.worker(&wg, jobChan, baseURL, paramName, params)
		}

		// Send jobs
		for _, payload := range payloadList {
			jobChan <- payload
		}
		close(jobChan)

		// Wait for completion
		wg.Wait()
	}

	return s.results, nil
}

// worker processes payloads from the job channel
func (s *Scanner) worker(wg *sync.WaitGroup, jobs <-chan string, baseURL, paramName string, params url.Values) {
	defer wg.Done()

	for payload := range jobs {
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
			s.mu.Lock()
			s.results.Vulnerabilities = append(s.results.Vulnerabilities, *vuln)
			s.mu.Unlock()
			color.Red("  [!] XSS Found: %s", truncate(payload, 60))
		}
	}
}

// testPayload tests a single payload for XSS vulnerability
func (s *Scanner) testPayload(testURL, payload, param string) (*config.Vulnerability, error) {
	var htmlContent string
	var dialogShown bool

	// Create new context for this test
	ctx, cancel := chromedp.NewContext(s.ctx)
	defer cancel()

	// Set up dialog handler to detect alert/confirm/prompt
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev.(type) {
		case *page.EventJavascriptDialogOpening:
			dialogShown = true
			// Automatically dismiss the dialog
			go chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				return page.HandleJavaScriptDialog(true).Do(ctx)
			}))
		}
	})

	// Navigate and check for XSS
	err := chromedp.Run(ctx,
		chromedp.Navigate(testURL),
		chromedp.Sleep(800*time.Millisecond),
		chromedp.OuterHTML("html", &htmlContent),
	)
	if err != nil {
		return nil, err
	}

	// Check for reflected XSS
	if s.checkReflectedXSS(htmlContent, payload) {
		context := s.detectContext(htmlContent, payload)
		return &config.Vulnerability{
			Type:        "Reflected XSS",
			Payload:     payload,
			URL:         testURL,
			Parameter:   param,
			Context:     context,
			Severity:    s.calculateSeverity(context),
			WAFBypassed: s.results.WAFDetected != "",
			Evidence:    extractEvidence(htmlContent, payload),
		}, nil
	}

	// Check for DOM-based XSS
	if dialogShown || s.checkDOMXSS(ctx, payload) {
		return &config.Vulnerability{
			Type:        "DOM-based XSS",
			Payload:     payload,
			URL:         testURL,
			Parameter:   param,
			Context:     "JavaScript execution",
			Severity:    "Critical",
			WAFBypassed: s.results.WAFDetected != "",
			Evidence:    "JavaScript alert/confirm/prompt triggered",
		}, nil
	}

	return nil, nil
}

// checkReflectedXSS checks if payload is reflected in response
func (s *Scanner) checkReflectedXSS(html, payload string) bool {
	// Check for exact match
	if strings.Contains(html, payload) {
		return true
	}

	// Check for decoded versions
	decodedPayload, _ := url.QueryUnescape(payload)
	if strings.Contains(html, decodedPayload) {
		return true
	}

	// Check for partial matches (dangerous patterns)
	dangerous := []string{"<script", "javascript:", "onerror=", "onload=", "onclick="}
	for _, d := range dangerous {
		if strings.Contains(strings.ToLower(payload), d) && strings.Contains(strings.ToLower(html), d) {
			return true
		}
	}

	return false
}

// checkDOMXSS checks for DOM-based XSS
func (s *Scanner) checkDOMXSS(ctx context.Context, payload string) bool {
	var result bool

	// Check if dangerous sinks are affected
	script := `
		(function() {
			try {
				// Check common DOM XSS patterns
				if (document.documentElement.innerHTML.includes('` + escapeJS(payload) + `')) {
					return true;
				}
				return false;
			} catch(e) {
				return false;
			}
		})()
	`

	err := chromedp.Run(ctx, chromedp.Evaluate(script, &result))
	if err != nil {
		return false
	}

	return result
}

// detectContext determines the injection context
func (s *Scanner) detectContext(html, payload string) string {
	lowerHTML := strings.ToLower(html)
	lowerPayload := strings.ToLower(payload)

	// Find payload position
	idx := strings.Index(lowerHTML, lowerPayload)
	if idx == -1 {
		return "Unknown"
	}

	// Check surrounding context
	before := ""
	if idx > 50 {
		before = lowerHTML[idx-50 : idx]
	} else if idx > 0 {
		before = lowerHTML[:idx]
	}

	// Determine context
	if strings.Contains(before, "<script") && !strings.Contains(before, "</script") {
		return "JavaScript context"
	}
	if strings.Contains(before, "href=") || strings.Contains(before, "src=") {
		return "URL attribute context"
	}
	if strings.Contains(before, "onclick=") || strings.Contains(before, "onerror=") {
		return "Event handler context"
	}
	if strings.Contains(before, "style=") {
		return "CSS context"
	}
	if strings.HasSuffix(strings.TrimSpace(before), "=") {
		return "HTML attribute context"
	}

	return "HTML body context"
}

// calculateSeverity determines vulnerability severity based on context
func (s *Scanner) calculateSeverity(context string) string {
	switch context {
	case "JavaScript context", "JavaScript execution":
		return "Critical"
	case "Event handler context":
		return "High"
	case "URL attribute context":
		return "High"
	case "HTML attribute context":
		return "Medium"
	case "CSS context":
		return "Medium"
	default:
		return "Medium"
	}
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

	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 30
	if end > len(html) {
		end = len(html)
	}

	return "..." + html[start:end] + "..."
}

func escapeJS(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}
