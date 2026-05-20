//go:build darwin

package sendrecv

import (
	"context"
	"errors"
)

// ErrNotSupported is returned when zero-copy operations are not supported on the host OS.
var ErrNotSupported = errors.New("zerocopy: not supported on this platform")

const msgZeroCopy = 0

// SetZeroCopy returns ErrNotSupported on macOS.
func (c *RawConn) SetZeroCopy(enable bool) error {
	return ErrNotSupported
}

// WaitZeroCopyCompletion returns ErrNotSupported on macOS.
func (c *RawConn) WaitZeroCopyCompletion(ctx context.Context) error {
	return ErrNotSupported
}
