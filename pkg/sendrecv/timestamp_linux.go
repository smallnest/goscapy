//go:build linux

package sendrecv

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// EnableTimestamping enables packet timestamping on the raw socket.
//
// When hardware is true, the kernel is asked to request hardware (NIC-level)
// timestamps via SO_TIMESTAMPING. If the NIC or driver does not support
// hardware timestamping, the kernel falls back to software timestamps
// automatically, so the call still succeeds.
//
// When hardware is false, nanosecond-resolution software timestamps are
// requested via SO_TIMESTAMPNS.
//
// Timestamps are delivered as control messages (cmsg) in Recvmsg and can be
// parsed with ParseTimestamp.
func (c *RawConn) EnableTimestamping(hardware bool) error {
	if hardware {
		// SO_TIMESTAMPING with software + hardware flags.
		// The kernel transparently degrades to software if NIC lacks support.
		flags := unix.SOF_TIMESTAMPING_SOFTWARE |
			unix.SOF_TIMESTAMPING_RX_SOFTWARE |
			unix.SOF_TIMESTAMPING_RAW_HARDWARE |
			unix.SOF_TIMESTAMPING_RX_HARDWARE

		if err := syscall.SetsockoptInt(c.fd, syscall.SOL_SOCKET, unix.SO_TIMESTAMPING, int(flags)); err != nil {
			return fmt.Errorf("rawconn: setsockopt SO_TIMESTAMPING: %w", err)
		}
	} else {
		// Software-only path: nanosecond resolution.
		if err := syscall.SetsockoptInt(c.fd, syscall.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
			return fmt.Errorf("rawconn: setsockopt SO_TIMESTAMPNS: %w", err)
		}
	}
	return nil
}
