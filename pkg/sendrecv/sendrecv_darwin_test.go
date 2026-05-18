//go:build darwin

package sendrecv

import (
	"testing"
)

func TestLoopbackNameDarwin(t *testing.T) {
	if name := loopbackName(); name != "lo0" {
		t.Errorf("expected lo0, got %q", name)
	}
}
