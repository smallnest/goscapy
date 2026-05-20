package sendrecv

import (
	"errors"
	"runtime"
	"testing"
)

func TestPacketMMAPPlatformSupport(t *testing.T) {
	m, err := NewPacketMMAP("lo")
	if runtime.GOOS == "darwin" {
		if !errors.Is(err, ErrNotSupported) {
			t.Fatalf("expected ErrNotSupported on Darwin, got: %v", err)
		}
		return
	}

	if err != nil {
		t.Logf("NewPacketMMAP failed (expected if non-root or interface absent): %v", err)
		return
	}
	defer m.Close()
	t.Log("Successfully setup PacketMMAP interface")
}
