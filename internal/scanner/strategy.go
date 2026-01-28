package scanner

import (
	"context"

	"github.com/go-rod/rod"
)

// VerificationStrategy defines the interface for different XSS verification methods.
// This allows switching between Alert-based, DOM-based, or OAST/Blind verification strategies.
// Approach C: Interface Segregation for better maintainability.
type VerificationStrategy interface {
	// Name returns the unique name of the strategy (e.g., "AlertVerifier")
	Name() string

	// InjectMarker modifies the payload to include a unique verification token
	InjectMarker(payload, marker string) string

	// Verify checks for execution of the XSS payload using the browser instance.
	// It returns true if execution is confirmed, followed by the proof/message.
	Verify(ctx context.Context, page *rod.Page, urlStr, marker string) (bool, string, error)
}
