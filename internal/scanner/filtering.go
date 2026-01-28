// Package scanner - Character filtering detection implementation
package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultFilterTester implements FilterTester interface
type DefaultFilterTester struct {
	client  *http.Client
	headers map[string]string
	cookies string
}

// FilterTesterConfig holds configuration for filter testing
type FilterTesterConfig struct {
	Timeout    time.Duration
	ProxyURL   string
	Headers    map[string]string
	Cookies    string
	AuthHeader string
}

// NewFilterTester creates a new DefaultFilterTester
func NewFilterTester(client *http.Client, config *FilterTesterConfig) *DefaultFilterTester {
	headers := make(map[string]string)
	if config != nil && config.Headers != nil {
		for k, v := range config.Headers {
			headers[k] = v
		}
	}

	cookies := ""
	if config != nil {
		cookies = config.Cookies
	}

	return &DefaultFilterTester{
		client:  client,
		headers: headers,
		cookies: cookies,
	}
}

// TestFiltering tests which special characters are filtered
func (f *DefaultFilterTester) TestFiltering(ctx context.Context, targetURL, paramName string) []string {
	var filtered []string

	// Generate unique probe for consistency
	baseProbe := fmt.Sprintf("ftest%d", time.Now().UnixNano()%10000)

	for char, encodedForms := range CharacterEncodings {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return filtered
		default:
		}

		if isCharFiltered := f.testSingleChar(ctx, targetURL, paramName, baseProbe, char, encodedForms); isCharFiltered {
			filtered = append(filtered, char)
		}
	}

	return filtered
}

// testSingleChar tests if a single character is filtered
func (f *DefaultFilterTester) testSingleChar(
	ctx context.Context,
	targetURL, paramName, baseProbe, char string,
	encodedForms []string,
) bool {
	testProbe := baseProbe + char

	// Build test URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false // Can't test, assume not filtered
	}

	params := parsedURL.Query()
	params.Set(paramName, testProbe)
	parsedURL.RawQuery = params.Encode()
	testURL := parsedURL.String()

	// Make request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return false
	}

	f.setHeaders(req)

	resp, err := f.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes))
	if err != nil {
		return false
	}

	bodyStr := string(body)

	// Check if base probe is reflected
	if !strings.Contains(bodyStr, baseProbe) {
		return false // Base not reflected, can't determine filtering
	}

	// Check if character appears in any form
	for _, form := range encodedForms {
		probeWithForm := baseProbe + form
		if strings.Contains(bodyStr, probeWithForm) {
			return false // Character found, not filtered
		}
	}

	// Character not found in any form - it's filtered
	return true
}

// setHeaders sets request headers
func (f *DefaultFilterTester) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if f.cookies != "" {
		req.Header.Set("Cookie", f.cookies)
	}

	for key, value := range f.headers {
		req.Header.Set(key, value)
	}
}

// MaxResponseBodyBytes is the maximum response body size to read
const MaxResponseBodyBytes = 1 * 1024 * 1024 // 1MB

// DefaultUserAgent is the default user agent for requests
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
