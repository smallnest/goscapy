//go:build linux

package sendrecv

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
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

// DialRaw6 creates a new IPv6 raw connection using the specified protocol.
// proto=58 is ICMPv6, 6 is TCP, 17 is UDP.
// On Linux, IPV6_HDRINCL is set so the caller provides the full IPv6 header.
func DialRaw6(proto int) (*RawConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("rawconn: dial6: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("rawconn: setsockopt IPV6_HDRINCL: %w", err)
	}
	return &RawConn{fd: fd}, nil
}

// AttachBPF attaches a classic BPF program to the RawConn socket.
func (c *RawConn) AttachBPF(instructions []BPFInstruction) error {
	return applyPacketFilter(c.fd, instructions)
}

