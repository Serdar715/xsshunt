// Package scanner - Browser health monitoring with circuit breaker pattern
package scanner

import (
	"sync"
	"time"
)

// BrowserHealthChecker implements the circuit breaker pattern for browser operations.
// It tracks failures and provides graceful degradation when the browser becomes unstable.
type BrowserHealthChecker struct {
	failures      int
	maxFailures   int
	cooldown      time.Duration
	lastFailure   time.Time
	consecutiveOK int
	mu            sync.RWMutex
}

// BrowserHealthConfig holds configuration for the health checker.
type BrowserHealthConfig struct {
	MaxFailures       int           // Max failures before opening circuit
	Cooldown          time.Duration // Time to wait before half-open state
	RecoveryThreshold int           // Consecutive successes needed to close circuit
}

// DefaultBrowserHealthConfig returns sensible defaults for browser health checking.
func DefaultBrowserHealthConfig() BrowserHealthConfig {
	return BrowserHealthConfig{
		MaxFailures:       3,
		Cooldown:          30 * time.Second,
		RecoveryThreshold: 2,
	}
}

// NewBrowserHealthChecker creates a new browser health checker with the given config.
func NewBrowserHealthChecker(cfg BrowserHealthConfig) *BrowserHealthChecker {
	return &BrowserHealthChecker{
		maxFailures: cfg.MaxFailures,
		cooldown:    cfg.Cooldown,
	}
}

// State represents the current state of the circuit breaker.
type CircuitState int

const (
	// CircuitClosed means the browser is healthy, operations proceed normally
	CircuitClosed CircuitState = iota
	// CircuitOpen means the browser is unhealthy, operations should be skipped
	CircuitOpen
	// CircuitHalfOpen means we're testing if the browser has recovered
	CircuitHalfOpen
)

// String returns a human-readable state name.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "Closed (Healthy)"
	case CircuitOpen:
		return "Open (Unhealthy)"
	case CircuitHalfOpen:
		return "Half-Open (Testing)"
	default:
		return "Unknown"
	}
}

// State returns the current circuit breaker state.
func (b *BrowserHealthChecker) State() CircuitState {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.failures < b.maxFailures {
		return CircuitClosed
	}

	if time.Since(b.lastFailure) >= b.cooldown {
		return CircuitHalfOpen
	}

	return CircuitOpen
}

// IsHealthy returns true if browser operations should proceed.
// Returns false if the circuit is open (browser is unstable).
func (b *BrowserHealthChecker) IsHealthy() bool {
	state := b.State()
	return state == CircuitClosed || state == CircuitHalfOpen
}

// RecordFailure records a browser operation failure.
// This increments the failure counter and may open the circuit.
func (b *BrowserHealthChecker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures++
	b.lastFailure = time.Now()
	b.consecutiveOK = 0
}

// RecordSuccess records a successful browser operation.
// This may close the circuit if enough consecutive successes occur.
func (b *BrowserHealthChecker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.consecutiveOK++

	// If we're in half-open state and got enough successes, close the circuit
	if b.failures >= b.maxFailures && b.consecutiveOK >= 2 {
		b.failures = 0
		b.consecutiveOK = 0
	}
}

// Reset clears all failure tracking and closes the circuit.
func (b *BrowserHealthChecker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures = 0
	b.consecutiveOK = 0
	b.lastFailure = time.Time{}
}

// FailureCount returns the current number of failures.
func (b *BrowserHealthChecker) FailureCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.failures
}

// TimeSinceLastFailure returns duration since the last failure.
// Returns 0 if no failures have been recorded.
func (b *BrowserHealthChecker) TimeSinceLastFailure() time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.lastFailure.IsZero() {
		return 0
	}
	return time.Since(b.lastFailure)
}

// ShouldRetry returns true if an operation should be retried based on current state.
// It also returns a suggested delay before retry.
func (b *BrowserHealthChecker) ShouldRetry() (bool, time.Duration) {
	state := b.State()

	switch state {
	case CircuitClosed:
		return true, 0
	case CircuitHalfOpen:
		return true, 500 * time.Millisecond // Small delay for half-open
	case CircuitOpen:
		remaining := b.cooldown - b.TimeSinceLastFailure()
		if remaining > 0 {
			return false, remaining
		}
		return true, 0
	default:
		return false, 0
	}
}
