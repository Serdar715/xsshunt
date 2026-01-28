package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// AlertVerificationStrategy verifies XSS by listening for JavaScript dialogs (alert/confirm/prompt).
type AlertVerificationStrategy struct {
	// Precompiled Regex patterns for performance
	reFunc        *regexp.Regexp
	reEmpty       *regexp.Regexp
	reTemplate    *regexp.Regexp
	reWrapped     *regexp.Regexp
	reArrayMethod *regexp.Regexp
	reScriptTag   *regexp.Regexp // New: For DOM injection inside scripts

	// Configurable timeouts
	navigationDelay time.Duration
	browserWaitTime time.Duration
}

// NewAlertStrategy creates a new instance of the alert-based verification strategy.
// It pre-compiles regex patterns and sets timeouts.
func NewAlertStrategy(navDelay, browserWait time.Duration) *AlertVerificationStrategy {
	return &AlertVerificationStrategy{
		reFunc:          regexp.MustCompile(`(alert|confirm|prompt)\s*\([^)]*\)`),
		reEmpty:         regexp.MustCompile(`(alert|confirm|prompt)\s*\(\s*\)`),
		reTemplate:      regexp.MustCompile("(alert|confirm|prompt)\\s*`[^`]*`"),
		reWrapped:       regexp.MustCompile(`\((confirm|alert|prompt)` + "``" + `\)`),
		reArrayMethod:   regexp.MustCompile(`\[(\d+)\]\.(find|map|some|every|filter|findIndex)\((confirm|alert|prompt)\)`),
		reScriptTag:     regexp.MustCompile(`(?i)<script[^>]*>`),
		navigationDelay: navDelay,
		browserWaitTime: browserWait,
	}
}

func (s *AlertVerificationStrategy) Name() string {
	return "AlertVerifier"
}

// InjectMarker replaces function calls in the payload with calls containing the marker.
// Also ensures DOM persistence by injecting verify variable.
func (s *AlertVerificationStrategy) InjectMarker(payload, marker string) string {
	newPayload := payload

	// 1. Alert Message Replacement (Existing logic)
	// Replace function calls with arguments: alert(1) -> alert('MARKER')
	newPayload = s.reFunc.ReplaceAllString(newPayload, fmt.Sprintf("${1}('%s')", marker))
	newPayload = s.reEmpty.ReplaceAllString(newPayload, fmt.Sprintf("${1}('%s')", marker))
	newPayload = s.reTemplate.ReplaceAllString(newPayload, fmt.Sprintf("${1}('%s')", marker))
	newPayload = s.reWrapped.ReplaceAllString(newPayload, fmt.Sprintf("(${1}('%s'))", marker))
	newPayload = s.reArrayMethod.ReplaceAllString(newPayload, fmt.Sprintf("[${1}].${2}(function(){${3}('%s')})", marker))
	
	// 2. DOM Persistence Injection (New logic)
	// Even if alert listener fails, this allows us to verify via DOM check
	domInjection := fmt.Sprintf("window['%s']=true;", marker)
	
	if s.reScriptTag.MatchString(newPayload) {
		// <script>alert(1)</script> -> <script>window['MARKER']=true;alert('MARKER')</script>
		// We insert after the open script tag
		// Note: This is a simple regex replacement, might break complex scripts but good for payloads
		newPayload = s.reScriptTag.ReplaceAllStringFunc(newPayload, func(match string) string {
			return match + domInjection
		})
	} else if strings.Contains(strings.ToLower(newPayload), "javascript:") {
		// javascript:alert(1) -> javascript:window['MARKER']=true;alert('MARKER')
		newPayload = strings.Replace(newPayload, "javascript:", "javascript:"+domInjection, 1)
	} else if strings.Contains(strings.ToLower(newPayload), "onerror=") {
		// <img onerror=alert(1)> -> <img onerror=window['MARKER']=true;alert('MARKER')>
		newPayload = strings.Replace(newPayload, "onerror=", "onerror="+domInjection, 1)
	} else if strings.Contains(strings.ToLower(newPayload), "onload=") {
		newPayload = strings.Replace(newPayload, "onload=", "onload="+domInjection, 1)
	} else if strings.Contains(strings.ToLower(newPayload), "onclick=") {
		newPayload = strings.Replace(newPayload, "onclick=", "onclick="+domInjection, 1)
	}
	
	// Fallback for raw JS payloads (not tags)
	if newPayload == payload && !strings.Contains(payload, "<") {
		// e.g. alert(1) -> window['MARKER']=true;alert(1)
		// Only if it looks like JS and executed in JS context
		if strings.Contains(payload, ";") || strings.Contains(payload, "(") {
			newPayload = domInjection + newPayload
		}
	}

	return newPayload
}

// Verify sets up the browser listener and checks if the marker triggers an alert or DOM change.
// Reduces false positives by verifying exact marker match.
func (s *AlertVerificationStrategy) Verify(ctx context.Context, page *rod.Page, urlStr, marker string) (VerificationResult, error) {
	result := VerificationResult{
		Confirmed: false,
	}

	// Enable Page events to ensure dialogs are reported
	if err := (proto.PageEnable{}).Call(page); err != nil {
		return result, fmt.Errorf("failed to enable page events: %w", err)
	}

	var executionConfirmed bool
	var dialogMessage string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Channel to signal when to stop listening
	done := make(chan struct{})

	// Async Dialog Listener with PROPER SYNCHRONIZATION
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		// Safe event listener
		page.EachEvent(func(e *proto.PageJavascriptDialogOpening) bool {
			mu.Lock()
			// Check if message contains our unique marker
			if strings.Contains(e.Message, marker) {
				executionConfirmed = true
				dialogMessage = e.Message
			}
			mu.Unlock()

			// Always handle dialog to prevent blocking functionality
			// We accept it to allow potential chained payloads to execute
			handle := proto.PageHandleJavaScriptDialog{Accept: true}
			_ = handle.Call(page)

			// Check if we should stop listening
			select {
			case <-done:
				return true // Stop listening
			case <-ctx.Done():
				return true // Context cancelled
			default:
				return false // Continue listening
			}
		})
	}()

	// Wait for listener to attach
	time.Sleep(s.navigationDelay)

	// Navigate with timeout context
	navCtx, cancel := context.WithTimeout(ctx, 30*time.Second) // Safety timeout
	defer cancel()
	
	// Navigate but don't fail immediately on timeout as partial load might trigger XSS
	_ = page.Context(navCtx).Navigate(urlStr)

	// Wait for execution
	time.Sleep(s.browserWaitTime)

	// Signal goroutine to stop
	close(done)
	
	// CRITICAL FIX: Wait for goroutine to finish to avoid race conditions
	// Use a channel with timeout to avoid deadlocks
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()
	
	select {
	case <-waitCh:
		// Clean exit
	case <-time.After(1 * time.Second):
		// Force move on if listener is stuck
	}

	// DOM Check Fallback (if alert didn't fire)
	mu.Lock()
	confirmedSoFar := executionConfirmed
	mu.Unlock()

	if !confirmedSoFar {
		checkScript := fmt.Sprintf("window['%s'] === true", marker)
		res, err := page.Eval(checkScript)
		if err == nil && res != nil && res.Value.Bool() {
			mu.Lock()
			executionConfirmed = true
			dialogMessage = "DOM execution verified via window object"
			mu.Unlock()
		}
	}

	if executionConfirmed {
		result.Confirmed = true
		result.Message = dialogMessage
		result.Confidence = 1.0
		if dialogMessage == "DOM execution verified via window object" {
			result.Context = "DOM"
		} else {
			result.Context = "Alert"
		}
	}

	return result, nil
}
