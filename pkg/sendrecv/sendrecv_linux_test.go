//go:build linux

package sendrecv

import (
	"testing"
)

func TestLoopbackNameLinux(t *testing.T) {
	if name := loopbackName(); name != "lo" {
		t.Errorf("expected lo, got %q", name)
	}
}
