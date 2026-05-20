package sendrecv

import (
	"errors"
	"runtime"
	"testing"
)

func TestUringConnPlatformSupport(t *testing.T) {
	conn, err := DialUringRaw(1) // Proto ICMP
	if runtime.GOOS == "darwin" {
		if !errors.Is(err, ErrNotSupported) {
			t.Fatalf("expected ErrNotSupported on Darwin, got: %v", err)
		}
		return
	}

	// For Linux, it might fail if we are not root or io_uring is disabled.
	if err != nil {
		t.Logf("DialUringRaw failed (expected if non-root or unsupported): %v", err)
		return
	}
	defer conn.Close()
	t.Log("Successfully opened io_uring raw connection")
}
