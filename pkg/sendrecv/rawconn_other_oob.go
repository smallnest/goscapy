//go:build !linux && !darwin

package sendrecv

import (
	"fmt"
	"time"
)

// RecvmsgOOB is not supported on this platform.
func (c *RawConn) RecvmsgOOB(timeout time.Duration) (data []byte, oob []byte, src string, err error) {
	return nil, nil, "", fmt.Errorf("sendrecv: RecvmsgOOB not implemented on this platform")
}

// RecvmsgOOBInto is not supported on this platform.
func (c *RawConn) RecvmsgOOBInto(buf, oobBuf []byte, timeout time.Duration) (n int, oobn int, src string, err error) {
	return 0, 0, "", fmt.Errorf("sendrecv: RecvmsgOOBInto not implemented on this platform")
}

// SendmsgOOB is not supported on this platform.
func (c *RawConn) SendmsgOOB(data []byte, oob []byte, dst string) error {
	return fmt.Errorf("sendrecv: SendmsgOOB not implemented on this platform")
}
