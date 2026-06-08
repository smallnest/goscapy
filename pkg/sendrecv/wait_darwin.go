//go:build darwin

package sendrecv

import (
	"fmt"
	"syscall"
	"time"
)

// waitRecv waits for data on the socket fd using select(2).
func waitRecv(fd int, timeout time.Duration) error {
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	var readFds syscall.FdSet
	readFds.Bits[fd/32] |= 1 << (uint(fd) % 32)

	err := syscall.Select(fd+1, &readFds, nil, nil, &tv)
	if err != nil {
		return fmt.Errorf("sendrecv: select: %w", err)
	}
	if readFds.Bits[fd/32]&(1<<uint(fd%32)) == 0 {
		return fmt.Errorf("%w after %v", ErrTimeout, timeout)
	}
	return nil
}

// isWouldBlock returns true if the error indicates no data available.
func isWouldBlock(err syscall.Errno) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}
