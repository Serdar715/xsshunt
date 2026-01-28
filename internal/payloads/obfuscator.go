package payloads

import (
	"math/rand"
	"strings"
	"time"
)

// Obfuscator handles structural obfuscation of payloads
type Obfuscator struct {
	rnd *rand.Rand
}

// NewObfuscator creates a new payload obfuscator
func NewObfuscator() *Obfuscator {
	return &Obfuscator{
		rnd: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// InjectWhitespace adds random whitespace inside tags
// e.g. <script> -> <script > or < script>
func (o *Obfuscator) InjectWhitespace(payload string) string {
	if strings.HasPrefix(payload, "<script") {
		// Simple injection for common case
		return strings.Replace(payload, "<script", "<script ", 1)
	}
	return payload
}

// InjectNullByte adds null byte to bypass some string filters
// e.g. <script> -> <script%00>
func (o *Obfuscator) InjectNullByte(payload string) string {
	if strings.Contains(payload, ">") {
		// Inject before closing tag
		return strings.Replace(payload, ">", "%00>", 1)
	}
	return payload
}

// InjectComments inserts comments to break keyword detection
// e.g. <script> -> <scr<!--x-->ipt>
func (o *Obfuscator) InjectComments(payload string) string {
	// This is tricky as it depends on exact keyword positions.
	// For demonstration, we target specific keywords.
	keywords := []string{"script", "alert", "confirm", "prompt", "onerror", "onload"}

	obfuscated := payload
	for _, kw := range keywords {
		if strings.Contains(obfuscated, kw) && len(kw) > 2 {
			splitIdx := len(kw) / 2
			newKw := kw[:splitIdx] + "<!--x-->" + kw[splitIdx:]
			obfuscated = strings.Replace(obfuscated, kw, newKw, 1)
		}
	}
	return obfuscated
}

// RandomCase varies the casing of tags
// e.g. <script> -> <ScRiPt>
func (o *Obfuscator) RandomCase(payload string) string {
	var sb strings.Builder
	inTag := false

	for _, r := range payload {
		if r == '<' {
			inTag = true
			sb.WriteRune(r)
			continue
		}
		if r == '>' {
			inTag = false
			sb.WriteRune(r)
			continue
		}

		if inTag {
			// Randomly uppercase
			if o.rnd.Intn(2) == 0 {
				sb.WriteString(strings.ToUpper(string(r)))
			} else {
				sb.WriteString(strings.ToLower(string(r)))
			}
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// GenerateVariants returns multiple obfuscated versions of a payload
func (o *Obfuscator) GenerateVariants(payload string) []string {
	return []string{
		o.InjectWhitespace(payload),
		o.InjectNullByte(payload),
		o.InjectComments(payload),
		o.RandomCase(payload),
	}
}
