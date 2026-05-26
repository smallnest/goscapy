package sendrecv

import (
	"context"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// RateLimiter controls the rate of packet transmission.
type RateLimiter interface {
	// Wait blocks until the caller is allowed to send the next packet,
	// or returns an error if ctx is canceled.
	Wait(ctx context.Context) error
}

// TokenBucketLimiter implements RateLimiter using the token bucket algorithm.
// It allows bursts up to the configured burst size while maintaining an
// average rate of pps packets per second.
type TokenBucketLimiter struct {
	mu       sync.Mutex
	tokens   float64
	maxBurst float64
	rate     float64 // tokens per nanosecond
	last     time.Time
}

// NewTokenBucketLimiter creates a rate limiter that allows pps packets per
// second with the given burst size. If burst <= 0, it defaults to
// max(1, min(pps/10, 100)).
func NewTokenBucketLimiter(pps int, burst int) *TokenBucketLimiter {
	if burst <= 0 {
		burst = pps / 10
		if burst > 100 {
			burst = 100
		}
		if burst < 1 {
			burst = 1
		}
	}
	return &TokenBucketLimiter{
		tokens:   float64(burst),
		maxBurst: float64(burst),
		rate:     float64(pps) / 1e9, // tokens per nanosecond
		last:     time.Now(),
	}
}

// Wait blocks until a token is available or ctx is done.
func (l *TokenBucketLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(l.last).Nanoseconds()
	l.last = now
	l.tokens += float64(elapsed) * l.rate
	if l.tokens > l.maxBurst {
		l.tokens = l.maxBurst
	}
	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		l.mu.Unlock()
		return nil
	}
	// Compute how long until we have 1 token.
	deficit := 1.0 - l.tokens
	waitNs := time.Duration(deficit / l.rate)
	l.tokens -= 1.0
	l.mu.Unlock()

	// Sleep for the computed duration.
	if waitNs <= 500*time.Microsecond {
		deadline := now.Add(waitNs)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	} else {
		timer := time.NewTimer(waitNs)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

// SendWithLimiter sends a packet at L3 after waiting for the rate limiter.
func SendWithLimiter(ctx context.Context, pkt *packet.Packet, iface string, limiter RateLimiter) error {
	if err := limiter.Wait(ctx); err != nil {
		return err
	}
	return sendL3(pkt, iface)
}

// SendpWithLimiter sends a packet at L2 after waiting for the rate limiter.
func SendpWithLimiter(ctx context.Context, pkt *packet.Packet, iface string, limiter RateLimiter) error {
	if err := limiter.Wait(ctx); err != nil {
		return err
	}
	return sendL2(pkt, iface)
}
