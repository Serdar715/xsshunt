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

const (
	// NavigationDelay defines how long to wait before navigating to ensure listeners are ready.
	NavigationDelay = 500 * time.Millisecond
	// BrowserWaitTime defines how long to wait for the page to stabilize after load.
	BrowserWaitTime = 1500 * time.Millisecond
)

// AlertVerificationStrategy verifies XSS by listening for JavaScript dialogs (alert/confirm/prompt).
type AlertVerificationStrategy struct{}

// NewAlertStrategy creates a new instance of the alert-based verification strategy.
func NewAlertStrategy() *AlertVerificationStrategy {
	return &AlertVerificationStrategy{}
}

func (s *AlertVerificationStrategy) Name() string {
	return "AlertVerifier"
}

// InjectMarker replaces function calls in the payload with calls containing the marker.
// Example: <script>alert(1)</script> -> <script>alert('MARKER')</script>
func (s *AlertVerificationStrategy) InjectMarker(payload, marker string) string {
	// 1. Replace function calls with arguments: alert(1), alert('x'), confirm(anything)
	reFunc := regexp.MustCompile(`(alert|confirm|prompt)\s*\([^)]*\)`)
	newPayload := reFunc.ReplaceAllString(payload, fmt.Sprintf("${1}('%s')", marker))

	// 2. Replace empty function calls: confirm(), alert(), prompt()
	reEmpty := regexp.MustCompile(`(alert|confirm|prompt)\s*\(\s*\)`)
	newPayload = reEmpty.ReplaceAllString(newPayload, fmt.Sprintf("${1}('%s')", marker))

	// 3. Handle template strings: alert`1`, confirm``, alert`anything`
	reTemplate := regexp.MustCompile("(alert|confirm|prompt)\\s*`[^`]*`")
	newPayload = reTemplate.ReplaceAllString(newPayload, fmt.Sprintf("${1}('%s')", marker))

	// 4. Handle wrapped calls: (confirm``), [confirm``], {confirm``}
	reWrapped := regexp.MustCompile(`\((confirm|alert|prompt)` + "``" + `\)`)
	newPayload = reWrapped.ReplaceAllString(newPayload, fmt.Sprintf("(${1}('%s'))", marker))

	// 5. Handle array method calls: [8].find(confirm), [8].map(alert)
	reArrayMethod := regexp.MustCompile(`\[(\d+)\]\.(find|map|some|every|filter|findIndex)\((confirm|alert|prompt)\)`)
	newPayload = reArrayMethod.ReplaceAllString(newPayload, fmt.Sprintf("[${1}].${2}(function(){${3}('%s')})", marker))

	// 6. Fallback: If no replacement happened, try to inject marker
	if newPayload == payload {
		if strings.Contains(payload, "<script>") {
			newPayload = strings.Replace(payload, "<script>", fmt.Sprintf("<script>window['%s']=true;", marker), 1)
		} else if strings.Contains(payload, "onerror=") {
			// Handle onerror handlers
			newPayload = strings.Replace(payload, "onerror=", fmt.Sprintf("onerror=window['%s']=true;", marker), 1)
		} else if strings.Contains(payload, "onload=") {
			newPayload = strings.Replace(payload, "onload=", fmt.Sprintf("onload=window['%s']=true;", marker), 1)
		} else if strings.Contains(payload, ";") {
			newPayload = payload + fmt.Sprintf(";window['%s']=true;", marker)
		}
	}

	return newPayload
}

// Verify sets up the browser listener and checks if the marker triggers an alert or DOM change.
// FALSE POSITIVE AZALTMA: Sadece marker içeren dialog'ları kabul eder.
func (s *AlertVerificationStrategy) Verify(ctx context.Context, page *rod.Page, urlStr, marker string) (bool, string, error) {
	// Enable Page events to ensure dialogs are reported
	_ = proto.PageEnable{}.Call(page)

	var executionConfirmed bool
	var dialogMessage string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Channel to signal when to stop listening
	done := make(chan struct{})

	// Async Dialog Listener with context cancellation (MEMORY LEAK FIX)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Recover from panic in goroutine to avoid crashing scanning
		defer func() {
			if r := recover(); r != nil {
				// Log silently or via a logger interface if available
			}
		}()

		page.EachEvent(func(e *proto.PageJavascriptDialogOpening) bool {
			mu.Lock()
			// FALSE POSITIVE AZALTMA: Sadece marker içeren mesajları kabul et
			if strings.Contains(e.Message, marker) {
				executionConfirmed = true
				dialogMessage = e.Message
			}
			mu.Unlock()

			// Always handle dialog to prevent blocking
			handle := proto.PageHandleJavaScriptDialog{Accept: true}
			_ = handle.Call(page)

			// Check if we should stop listening
			select {
			case <-done:
				return true // Stop listening
			case <-ctx.Done():
				return true // Context cancelled, stop listening
			default:
				return false // Continue listening for more dialogs
			}
		})
	}()

	// Fix Race Condition: Wait for listener to attach
	time.Sleep(NavigationDelay)

	// Navigate
	if err := page.Navigate(urlStr); err != nil {
		// If navigate fails (e.g. timeout), we still check results
		// because partial load might have triggered XSS
	}

	// Wait for execution using detailed sleep instead of WaitLoad which hangs on alerts
	time.Sleep(BrowserWaitTime)

	// Signal goroutine to stop and wait for cleanup
	close(done)

	// DOM Check Fallback
	mu.Lock()
	confirmedSoFar := executionConfirmed
	mu.Unlock()

	if !confirmedSoFar {
		checkScript := fmt.Sprintf("window['%s'] === true", marker)
		res, err := page.Eval(checkScript)
		if err == nil && res.Value.Bool() {
			mu.Lock()
			executionConfirmed = true
			dialogMessage = "DOM execution verified via window object"
			mu.Unlock()
		}
	}

	return executionConfirmed, dialogMessage, nil
}
