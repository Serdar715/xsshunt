// Package scanner - Custom error types for better error handling
package scanner

import (
	"errors"
	"fmt"
)

// Sentinel errors for common error conditions
var (
	// ErrInvalidURL indicates the URL format is invalid
	ErrInvalidURL = errors.New("invalid URL format")

	// ErrNoParameters indicates no query parameters were found
	ErrNoParameters = errors.New("no parameters found in URL")

	// ErrRequestFailed indicates the HTTP request failed
	ErrRequestFailed = errors.New("HTTP request failed")

	// ErrRequestTimeout indicates the request timed out
	ErrRequestTimeout = errors.New("request timeout")

	// ErrResponseTooLarge indicates response exceeded size limit
	ErrResponseTooLarge = errors.New("response body too large")

	// ErrContextCanceled indicates the operation was canceled
	ErrContextCanceled = errors.New("operation canceled")

	// ErrInvalidPayload indicates the payload is malformed
	ErrInvalidPayload = errors.New("invalid payload format")
)

// ScanError provides detailed error information for scanning operations
type ScanError struct {
	URL       string // The URL being scanned
	Parameter string // The parameter being tested (if applicable)
	Payload   string // The payload being tested (if applicable)
	Operation string // The operation that failed
	Cause     error  // The underlying error
}

// Error implements the error interface
func (e *ScanError) Error() string {
	if e.Parameter != "" {
		return fmt.Sprintf("%s failed for param '%s' on %s: %v",
			e.Operation, e.Parameter, truncateString(e.URL, 50), e.Cause)
	}
	return fmt.Sprintf("%s failed for %s: %v",
		e.Operation, truncateString(e.URL, 50), e.Cause)
}

// Unwrap returns the underlying error for errors.Is/As support
func (e *ScanError) Unwrap() error {
	return e.Cause
}

// NewScanError creates a new ScanError
func NewScanError(operation, url string, cause error) *ScanError {
	return &ScanError{
		URL:       url,
		Operation: operation,
		Cause:     cause,
	}
}

// NewParamError creates a ScanError for parameter-specific failures
func NewParamError(operation, url, param string, cause error) *ScanError {
	return &ScanError{
		URL:       url,
		Parameter: param,
		Operation: operation,
		Cause:     cause,
	}
}

// NewPayloadError creates a ScanError for payload-specific failures
func NewPayloadError(operation, url, param, payload string, cause error) *ScanError {
	return &ScanError{
		URL:       url,
		Parameter: param,
		Payload:   payload,
		Operation: operation,
		Cause:     cause,
	}
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// IsRetryable returns true if the error can be retried
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check for retryable conditions
	if errors.Is(err, ErrRequestTimeout) {
		return true
	}

	return false
}
