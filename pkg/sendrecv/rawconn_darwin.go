//go:build darwin

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

// DialRaw6 creates a new IPv6 raw connection using the specified protocol.
// proto=58 is ICMPv6, 6 is TCP, 17 is UDP.
// On macOS, IPV6_HDRINCL is not supported — the kernel fills the IPv6 header.
// The caller provides only the payload (upper-layer protocol data).
func DialRaw6(proto int) (*RawConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("rawconn: dial6: %w", err)
	}
	return &RawConn{fd: fd}, nil
}

// AttachBPF attaches a classic BPF program to the RawConn socket.
// On macOS, raw sockets do not support direct BPF attachment, so this is a no-op.
func (c *RawConn) AttachBPF(instructions []BPFInstruction) error {
	return nil
}

