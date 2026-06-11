package answer

import (
	"context"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

func TestAnsweringMachineValidation(t *testing.T) {
	// Missing iface.
	am := New(Config{}, Funcs{
		IsRequest: func(*packet.Packet) bool { return true },
		MakeReply: func(*packet.Packet) (*packet.Packet, bool) { return nil, false },
	})
	if _, err := am.Run(context.Background()); err == nil {
		t.Error("expected error for missing interface")
	}

	// Missing callbacks.
	am2 := New(Config{Iface: "lo"}, Funcs{})
	if _, err := am2.Run(context.Background()); err == nil {
		t.Error("expected error for missing callbacks")
	}
}

// TestAnsweringMachineContextCancel ensures Run returns when ctx is cancelled
// even if the receiver fails to open (invalid iface) — it should not hang.
func TestAnsweringMachineContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	am := New(Config{Iface: "nonexistent-iface-xyz"}, Funcs{
		IsRequest: func(*packet.Packet) bool { return true },
		MakeReply: func(p *packet.Packet) (*packet.Packet, bool) { return p, true },
	})

	done := make(chan struct{})
	go func() {
		_, _ = am.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return promptly")
	}
}
