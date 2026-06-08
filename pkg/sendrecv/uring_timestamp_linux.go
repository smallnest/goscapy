//go:build linux

package sendrecv

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// EnableTimestamping enables packet timestamping on the UringConn socket.
//
// When hardware is true, the kernel requests hardware (NIC-level) timestamps
// via SO_TIMESTAMPING, falling back to software if the NIC lacks support.
// When hardware is false, nanosecond-resolution software timestamps are
// requested via SO_TIMESTAMPNS.
//
// Timestamps are delivered as control messages in RecvOOB/RecvmsgOOBInto and
// can be parsed with ParseTimestamp.
func (c *UringConn) EnableTimestamping(hardware bool) error {
	if hardware {
		flags := unix.SOF_TIMESTAMPING_SOFTWARE |
			unix.SOF_TIMESTAMPING_RX_SOFTWARE |
			unix.SOF_TIMESTAMPING_RAW_HARDWARE |
			unix.SOF_TIMESTAMPING_RX_HARDWARE
		if err := syscall.SetsockoptInt(c.fd, syscall.SOL_SOCKET, unix.SO_TIMESTAMPING, int(flags)); err != nil {
			return fmt.Errorf("uring: setsockopt SO_TIMESTAMPING: %w", err)
		}
	} else {
		if err := syscall.SetsockoptInt(c.fd, syscall.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
			return fmt.Errorf("uring: setsockopt SO_TIMESTAMPNS: %w", err)
		}
	}
	return nil
}
