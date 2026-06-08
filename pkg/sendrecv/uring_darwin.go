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

// RecvOOB returns ErrNotSupported on macOS.
func (c *UringConn) RecvOOB(timeout time.Duration) ([]byte, []byte, string, error) {
	return nil, nil, "", ErrNotSupported
}

// RecvmsgOOBInto returns ErrNotSupported on macOS.
func (c *UringConn) RecvmsgOOBInto(buf, oobBuf []byte, timeout time.Duration) ([]byte, []byte, string, error) {
	return nil, nil, "", ErrNotSupported
}

// SendRecvBatch returns ErrNotSupported on macOS.
func (c *UringConn) SendRecvBatch(msgs []BatchMsg) ([]BatchResult, error) {
	return nil, ErrNotSupported
}

// SendRecvBatchOOB returns ErrNotSupported on macOS.
func (c *UringConn) SendRecvBatchOOB(msgs []BatchMsg) ([]BatchResultOOB, error) {
	return nil, ErrNotSupported
}

// EnableTimestamping returns ErrNotSupported on macOS.
func (c *UringConn) EnableTimestamping(hardware bool) error {
	return ErrNotSupported
}

// Close closes the connection.
func (c *UringConn) Close() error {
	return nil
}
