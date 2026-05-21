package sendrecv

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

func TestTokenBucketLimiterBasic(t *testing.T) {
	limiter := NewTokenBucketLimiter(1000, 1)
	ctx := context.Background()

	// First call should succeed immediately (burst=1 means 1 token available).
	start := time.Now()
	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Millisecond {
		t.Errorf("first Wait took %v, expected near-instant", elapsed)
	}
}

func TestTokenBucketLimiterRate(t *testing.T) {
	pps := 5000
	limiter := NewTokenBucketLimiter(pps, 1)
	ctx := context.Background()

	// Drain the initial burst token.
	limiter.Wait(ctx)

	// Measure time for 100 packets at 5000 pps → should take ~20ms.
	n := 100
	start := time.Now()
	for range n {
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("Wait error: %v", err)
		}
	}
	elapsed := time.Since(start)

	expectedDur := time.Duration(float64(n) / float64(pps) * float64(time.Second))
	tolerance := 0.10 // 10% tolerance
	low := time.Duration(float64(expectedDur) * (1 - tolerance))
	high := time.Duration(float64(expectedDur) * (1 + tolerance))

	if elapsed < low || elapsed > high {
		t.Errorf("100 packets at %d pps took %v, expected %v ± 10%%", pps, elapsed, expectedDur)
	}
}

func TestTokenBucketLimiterBurst(t *testing.T) {
	pps := 1000
	burst := 10
	limiter := NewTokenBucketLimiter(pps, burst)
	ctx := context.Background()

	// All burst tokens should be available immediately.
	start := time.Now()
	for range burst {
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("Wait error: %v", err)
		}
	}
	elapsed := time.Since(start)

	// Burst should complete nearly instantly (< 5ms).
	if elapsed > 5*time.Millisecond {
		t.Errorf("burst of %d took %v, expected < 5ms", burst, elapsed)
	}
}

func TestTokenBucketLimiterContextCancel(t *testing.T) {
	limiter := NewTokenBucketLimiter(1, 1) // 1 pps, very slow
	ctx, cancel := context.WithCancel(context.Background())

	// Drain the initial token.
	limiter.Wait(ctx)

	// Cancel context while waiting.
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := limiter.Wait(ctx)
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestTokenBucketLimiterDefaultBurst(t *testing.T) {
	// pps=1000, burst not specified → default = pps/10 = 100
	limiter := NewTokenBucketLimiter(1000, 0)
	if limiter.maxBurst != 100 {
		t.Errorf("expected default burst=100, got %v", limiter.maxBurst)
	}

	// pps=5, burst not specified → default = max(1, 5/10) = 1
	limiter = NewTokenBucketLimiter(5, 0)
	if limiter.maxBurst != 1 {
		t.Errorf("expected default burst=1, got %v", limiter.maxBurst)
	}

	// pps=50000, burst not specified → default = min(5000, 100) = 100
	limiter = NewTokenBucketLimiter(50000, 0)
	if limiter.maxBurst != 100 {
		t.Errorf("expected default burst=100, got %v", limiter.maxBurst)
	}
}

func TestTokenBucketLimiterConcurrent(t *testing.T) {
	pps := 10000
	limiter := NewTokenBucketLimiter(pps, 10)
	ctx := context.Background()

	// Drain burst.
	for range 10 {
		limiter.Wait(ctx)
	}

	// 4 goroutines each sending 50 packets = 200 total at 10000 pps → ~20ms.
	var wg sync.WaitGroup
	start := time.Now()
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				limiter.Wait(ctx)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	expectedDur := time.Duration(float64(200) / float64(pps) * float64(time.Second))
	tolerance := 0.15 // 15% tolerance for concurrent
	low := time.Duration(float64(expectedDur) * (1 - tolerance))
	high := time.Duration(float64(expectedDur) * (1 + tolerance))

	if elapsed < low || elapsed > high {
		t.Errorf("200 packets from 4 goroutines at %d pps took %v, expected %v ± 15%%", pps, elapsed, expectedDur)
	}
}

func BenchmarkTokenBucketLimiter(b *testing.B) {
	pps := 10000
	n := 500 // Fixed sample size for accuracy measurement.
	limiter := NewTokenBucketLimiter(pps, 1)
	ctx := context.Background()

	// Drain the initial burst token so we measure steady-state.
	limiter.Wait(ctx)

	b.ResetTimer()
	start := time.Now()
	for range n {
		limiter.Wait(ctx)
	}
	elapsed := time.Since(start)
	b.StopTimer()

	actualPPS := float64(n) / elapsed.Seconds()
	expectedPPS := float64(pps)
	errorPct := math.Abs(actualPPS-expectedPPS) / expectedPPS * 100

	b.ReportMetric(actualPPS, "pps")
	b.ReportMetric(errorPct, "%error")

	if errorPct > 5.0 {
		b.Errorf("pps error %.2f%% exceeds 5%% threshold (actual=%.0f, expected=%d)", errorPct, actualPPS, pps)
	}
}
