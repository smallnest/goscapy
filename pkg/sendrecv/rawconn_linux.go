//go:build linux

package sendrecv

import (
	"fmt"
	"syscall"
)

// DialRaw creates a new raw connection using the specified protocol.
// proto=1 is ICMP, 6 is TCP, 17 is UDP.
func DialRaw(proto int) (*RawConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("rawconn: dial: %w", err)
	}
	return &RawConn{fd: fd}, nil
}
