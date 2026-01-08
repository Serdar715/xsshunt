package waf

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// Detector handles WAF detection
type Detector struct {
	client *http.Client
}

// NewDetector creates a new WAF detector
func NewDetector() *Detector {
	return &Detector{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Detect identifies the WAF protecting the target
func (d *Detector) Detect(targetURL string) (string, error) {
	// Send a probe request with XSS payload
	probeURL := targetURL + "<script>alert(1)</script>"

	req, err := http.NewRequest("GET", probeURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := d.client.Do(req)
	if err != nil {
		// Try without payload
		req, _ = http.NewRequest("GET", targetURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err = d.client.Do(req)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check headers for WAF signatures
	for name, values := range resp.Header {
		headerStr := name + ": " + strings.Join(values, ", ")

		// Cloudflare
		if strings.Contains(strings.ToLower(headerStr), "cloudflare") ||
			strings.Contains(strings.ToLower(headerStr), "cf-ray") {
			return "cloudflare", nil
		}

		// Akamai
		if strings.Contains(strings.ToLower(headerStr), "akamai") ||
			strings.Contains(strings.ToLower(headerStr), "akamaighost") {
			return "akamai", nil
		}

		// CloudFront
		if strings.Contains(strings.ToLower(headerStr), "cloudfront") ||
			strings.Contains(strings.ToLower(headerStr), "x-amz") {
			return "cloudfront", nil
		}

		// Imperva/Incapsula
		if strings.Contains(strings.ToLower(headerStr), "incapsula") ||
			strings.Contains(strings.ToLower(headerStr), "imperva") {
			return "imperva", nil
		}

		// Sucuri
		if strings.Contains(strings.ToLower(headerStr), "sucuri") ||
			strings.Contains(strings.ToLower(headerStr), "x-sucuri") {
			return "sucuri", nil
		}

		// F5 BIG-IP
		if strings.Contains(strings.ToLower(headerStr), "bigip") ||
			strings.Contains(strings.ToLower(headerStr), "f5") {
			return "f5", nil
		}

		// Barracuda
		if strings.Contains(strings.ToLower(headerStr), "barracuda") {
			return "barracuda", nil
		}
	}

	// Check body for WAF signatures
	bodyLower := strings.ToLower(bodyStr)

	if strings.Contains(bodyLower, "cloudflare") {
		return "cloudflare", nil
	}
	if strings.Contains(bodyLower, "akamai") {
		return "akamai", nil
	}
	if strings.Contains(bodyLower, "incapsula") || strings.Contains(bodyLower, "imperva") {
		return "imperva", nil
	}
	if strings.Contains(bodyLower, "wordfence") {
		return "wordfence", nil
	}
	if strings.Contains(bodyLower, "modsecurity") || strings.Contains(bodyLower, "mod_security") {
		return "modsecurity", nil
	}
	if strings.Contains(bodyLower, "sucuri") {
		return "sucuri", nil
	}

	// Check for blocked status codes
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
		return "unknown", nil
	}

	return "", nil
}
