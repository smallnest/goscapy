//go:build !linux

package sendrecv

import (
	"fmt"
	"runtime"

	"github.com/smallnest/goscapy/pkg/packet"
)

// Fanout modes (stubs for non-Linux platforms).
const (
	FanoutHash     uint16 = 0
	FanoutLB       uint16 = 1
	FanoutCPU      uint16 = 2
	FanoutRollover uint16 = 3
)

// FanoutReceiver is not supported on this platform.
type FanoutReceiver struct {
	n int
}

// FanoutOption configures a FanoutReceiver.
type FanoutOption func(*FanoutReceiver)

// WithFanoutMode sets the fanout distribution mode.
func WithFanoutMode(mode uint16) FanoutOption {
	return func(f *FanoutReceiver) {}
}

// WithFanoutGroupID sets the fanout group ID.
func WithFanoutGroupID(id uint16) FanoutOption {
	return func(f *FanoutReceiver) {}
}

// OpenFanoutReceiver is not supported on this platform.
func OpenFanoutReceiver(iface string, n int, opts ...FanoutOption) (*FanoutReceiver, error) {
	if n <= 0 {
		n = runtime.NumCPU()
	}
	return nil, fmt.Errorf("sendrecv: PACKET_FANOUT is only supported on Linux")
}

// RecvParallel is not supported on this platform.
func (fr *FanoutReceiver) RecvParallel(handler func(*packet.Packet)) {}

// Close is a no-op on non-Linux platforms.
func (fr *FanoutReceiver) Close() error { return nil }

// NumSockets returns 0 on non-Linux platforms.
func (fr *FanoutReceiver) NumSockets() int { return 0 }
