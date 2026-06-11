package sendrecv

import (
	"context"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

func TestSrLoopOptionsDefaults(t *testing.T) {
	pkt := packet.New()
	o := SrLoopOptions{}.withDefaults(pkt)
	if o.Interval != time.Second {
		t.Errorf("default Interval = %v, want 1s", o.Interval)
	}
	if o.Timeout != time.Second {
		t.Errorf("default Timeout = %v, want 1s (= interval)", o.Timeout)
	}
	if o.Match == nil {
		t.Error("default Match should be non-nil")
	}
}

func TestSrLoopOptionsCustomTimeout(t *testing.T) {
	pkt := packet.New()
	o := SrLoopOptions{Interval: 2 * time.Second}.withDefaults(pkt)
	if o.Timeout != 2*time.Second {
		t.Errorf("Timeout = %v, want 2s (inherits interval)", o.Timeout)
	}
}

// TestSrLoopContextCancel verifies SrLoop returns promptly when the context is
// already cancelled (before opening the receiver path matters, we just check
// the cancellation contract via a cancelled ctx on a likely-failing iface).
func TestSrLoopContextCancelledIface(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pkt := packet.New()
	// With a cancelled context and an invalid interface, SrLoop should not hang.
	done := make(chan struct{})
	go func() {
		_, _ = SrLoop(ctx, pkt, "nonexistent-iface-xyz", SrLoopOptions{Count: 3}, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SrLoop did not return promptly with cancelled context")
	}
}
