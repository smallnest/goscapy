//go:build linux

package sendrecv

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// waitRecv waits for data on the socket fd using poll(2).
func waitRecv(fd int, timeout time.Duration) error {
	timeoutMs := int(timeout.Milliseconds())
	if timeoutMs <= 0 {
		timeoutMs = 1
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, timeoutMs)
	if err != nil {
		if err == unix.EINTR {
			return fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
		return fmt.Errorf("sendrecv: poll: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w after %v", ErrTimeout, timeout)
	}
	return nil
}

// isWouldBlock returns true if the error indicates no data available.
func isWouldBlock(err syscall.Errno) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}
