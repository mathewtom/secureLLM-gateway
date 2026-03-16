// Package ratelimit implements per-user token bucket rate limiting
// with configurable per-role rates.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// RoleRates maps role names to their rate limit parameters.
type RoleRates map[string]Rate

// Rate defines token bucket parameters for a role.
type Rate struct {
	RequestsPerSecond float64 // Sustained refill rate.
	Burst             int     // Maximum bucket capacity.
}

type bucket struct {
	tokens   float64
	capacity float64
	rate     float64
	lastSeen time.Time
}

// Limiter manages per-user token buckets with per-role rates.
// Safe for concurrent use.
type Limiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	roleRates   RoleRates
	defaultRate Rate
	cleanupTTL  time.Duration
	stopCleanup chan struct{}
}

// NewLimiter creates a rate limiter with per-role rates and a background
// goroutine that evicts idle buckets every cleanupInterval.
func NewLimiter(roleRates RoleRates, defaultRate Rate, cleanupInterval, cleanupTTL time.Duration) *Limiter {
	l := &Limiter{
		buckets:     make(map[string]*bucket),
		roleRates:   roleRates,
		defaultRate: defaultRate,
		cleanupTTL:  cleanupTTL,
		stopCleanup: make(chan struct{}),
	}

	go l.cleanup(cleanupInterval)

	return l
}

// Allow checks whether userID may make a request. Returns false with a
// Retry-After duration when the user's bucket is empty.
func (l *Limiter) Allow(userID, role string) (allowed bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[userID]
	if !exists {
		rate := l.rateForRole(role)
		b = &bucket{
			tokens:   float64(rate.Burst),
			capacity: float64(rate.Burst),
			rate:     rate.RequestsPerSecond,
			lastSeen: now,
		}
		l.buckets[userID] = b
	}

	// Refill tokens proportional to elapsed time, capped at capacity.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	// Calculate wait time until one token is available.
	deficit := 1.0 - b.tokens
	waitSeconds := deficit / b.rate
	retryAfter = time.Duration(math.Ceil(waitSeconds)) * time.Second

	return false, retryAfter
}

func (l *Limiter) rateForRole(role string) Rate {
	if r, ok := l.roleRates[role]; ok {
		return r
	}
	return l.defaultRate
}

// cleanup evicts buckets idle longer than cleanupTTL.
func (l *Limiter) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			for id, b := range l.buckets {
				if now.Sub(b.lastSeen) > l.cleanupTTL {
					delete(l.buckets, id)
				}
			}
			l.mu.Unlock()
		case <-l.stopCleanup:
			return
		}
	}
}

// Stop terminates the background cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.stopCleanup)
}
