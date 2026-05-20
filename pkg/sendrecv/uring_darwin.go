//go:build darwin

package sendrecv

import (
	"time"
)

// UringConn represents a raw socket connection utilizing io_uring.
type UringConn struct{}

// DialUringRaw returns ErrNotSupported on macOS.
func DialUringRaw(proto int) (*UringConn, error) {
	return nil, ErrNotSupported
}

// Send returns ErrNotSupported on macOS.
func (c *UringConn) Send(data []byte, dst string) (uint64, error) {
	return 0, ErrNotSupported
}

// Recv returns ErrNotSupported on macOS.
func (c *UringConn) Recv(timeout time.Duration) ([]byte, string, error) {
	return nil, "", ErrNotSupported
}

// SendRecvBatch returns ErrNotSupported on macOS.
func (c *UringConn) SendRecvBatch(msgs []BatchMsg) ([]BatchResult, error) {
	return nil, ErrNotSupported
}

// Close closes the connection.
func (c *UringConn) Close() error {
	return nil
}
