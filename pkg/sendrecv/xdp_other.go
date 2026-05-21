//go:build !linux

package sendrecv

import (
	"fmt"
	"runtime"
)

// XDP bind flags.
const (
	XDPCopy     uint16 = 1 << 1
	XDPZeroCopy uint16 = 1 << 2
)

// XDPConn is not supported on this platform.
type XDPConn struct{}

// XDPOption configures an XDPConn.
type XDPOption func(*xdpConfig)

type xdpConfig struct {
	ringSize  uint32
	frameSize uint32
	numFrames uint32
	queueID   int
	flags     uint16
}

// WithXDPRingSize sets the ring size.
func WithXDPRingSize(size uint32) XDPOption {
	return func(c *xdpConfig) { c.ringSize = size }
}

// WithXDPFrameSize sets the UMEM frame size.
func WithXDPFrameSize(size uint32) XDPOption {
	return func(c *xdpConfig) { c.frameSize = size }
}

// WithXDPQueueID sets the NIC queue to bind to.
func WithXDPQueueID(id int) XDPOption {
	return func(c *xdpConfig) { c.queueID = id }
}

// WithXDPFlags sets the bind flags.
func WithXDPFlags(flags uint16) XDPOption {
	return func(c *xdpConfig) { c.flags = flags }
}

// OpenXDP is not supported on this platform.
func OpenXDP(iface string, opts ...XDPOption) (*XDPConn, error) {
	return nil, fmt.Errorf("xdp: AF_XDP is only supported on Linux (current: %s/%s)", runtime.GOOS, runtime.GOARCH)
}

// Recv is not supported on this platform.
func (c *XDPConn) Recv() ([]byte, error) {
	return nil, fmt.Errorf("xdp: not supported on this platform")
}

// Send is not supported on this platform.
func (c *XDPConn) Send(data []byte) error {
	return fmt.Errorf("xdp: not supported on this platform")
}

// SendBatch is not supported on this platform.
func (c *XDPConn) SendBatch(packets [][]byte) (int, error) {
	return 0, fmt.Errorf("xdp: not supported on this platform")
}

// Close is a no-op on non-Linux platforms.
func (c *XDPConn) Close() error { return nil }

// Fd returns -1 on non-Linux platforms.
func (c *XDPConn) Fd() int { return -1 }

// FreeFrames returns 0 on non-Linux platforms.
func (c *XDPConn) FreeFrames() int { return 0 }

// LoadXDPProgram is not supported on this platform.
func (c *XDPConn) LoadXDPProgram() (int, error) {
	return -1, fmt.Errorf("xdp: not supported on this platform")
}
