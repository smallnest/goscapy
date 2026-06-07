//go:build darwin

package sendrecv

import (
	"fmt"
	"syscall"
)

// EnableTimestamping enables packet timestamping on the raw socket.
//
// On macOS the hardware parameter is ignored — only software timestamps
// via SO_TIMESTAMP are available. Timestamps are delivered as control
// messages (cmsg) in Recvmsg and can be parsed with ParseTimestamp.
func (c *RawConn) EnableTimestamping(hardware bool) error {
	if err := syscall.SetsockoptInt(c.fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
		return fmt.Errorf("rawconn: setsockopt SO_TIMESTAMP: %w", err)
	}
	return nil
}
