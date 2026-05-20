package sendrecv

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestZeroCopyNonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping TestZeroCopyNonRoot: running as root")
	}

	conn, err := DialRaw(1)
	if err == nil {
		defer conn.Close()
		t.Fatal("expected DialRaw to fail for non-root user")
	}
}

func TestZeroCopyPlatformSupport(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TestZeroCopyPlatformSupport: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	if runtime.GOOS == "darwin" {
		err = conn.SetZeroCopy(true)
		if !errors.Is(err, ErrNotSupported) {
			t.Errorf("expected ErrNotSupported on darwin, got %v", err)
		}

		err = conn.WaitZeroCopyCompletion(context.Background())
		if !errors.Is(err, ErrNotSupported) {
			t.Errorf("expected ErrNotSupported on darwin, got %v", err)
		}
	} else if runtime.GOOS == "linux" {
		err = conn.SetZeroCopy(true)
		if err != nil {
			t.Fatalf("expected SetZeroCopy(true) to succeed on Linux, got %v", err)
		}

		// Send dummy packet
		err = conn.Send([]byte("zerocopy test payload"), "127.0.0.1")
		if err != nil {
			t.Fatalf("Send failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err = conn.WaitZeroCopyCompletion(ctx)
		if err != nil {
			t.Fatalf("WaitZeroCopyCompletion failed: %v", err)
		}

		// Disable zero copy
		err = conn.SetZeroCopy(false)
		if err != nil {
			t.Fatalf("expected SetZeroCopy(false) to succeed, got %v", err)
		}
	}
}
