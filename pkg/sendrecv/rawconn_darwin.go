//go:build darwin

package sendrecv

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// RawConn represents a raw socket connection on macOS.
type RawConn struct {
	fd int
}

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

// Send transmits raw payload bytes to the target destination IP.
func (c *RawConn) Send(data []byte, dst string) error {
	ip := net.ParseIP(dst)
	if ip == nil {
		return fmt.Errorf("rawconn: invalid destination IP: %s", dst)
	}

	if ip4 := ip.To4(); ip4 != nil {
		var dstIP [4]byte
		copy(dstIP[:], ip4)
		addr := syscall.SockaddrInet4{
			Port: 0,
			Addr: dstIP,
		}
		if err := syscall.Sendto(c.fd, data, 0, &addr); err != nil {
			return fmt.Errorf("rawconn: sendto: %w", err)
		}
		return nil
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return fmt.Errorf("rawconn: invalid destination IP: %s", dst)
	}
	var dstIP [16]byte
	copy(dstIP[:], ip6)
	addr := syscall.SockaddrInet6{
		Port: 0,
		Addr: dstIP,
	}
	if err := syscall.Sendto(c.fd, data, 0, &addr); err != nil {
		return fmt.Errorf("rawconn: sendto IPv6: %w", err)
	}
	return nil
}

// Recv reads one raw packet payload from the socket.
func (c *RawConn) Recv(timeout time.Duration) ([]byte, string, error) {
	buf := make([]byte, 65536)
	n, src, err := c.RecvInto(buf, timeout)
	if err != nil {
		return nil, "", err
	}
	return buf[:n], src, nil
}

// RecvInto reads one raw packet payload into the caller-provided buffer.
func (c *RawConn) RecvInto(buf []byte, timeout time.Duration) (int, string, error) {
	if timeout > 0 {
		tv := syscall.NsecToTimeval(timeout.Nanoseconds())
		var readFds syscall.FdSet
		readFds.Bits[c.fd/32] |= 1 << (uint(c.fd) % 32)
		err := syscall.Select(c.fd+1, &readFds, nil, nil, &tv)
		if err != nil {
			return 0, "", fmt.Errorf("rawconn: select: %w", err)
		}
		if readFds.Bits[c.fd/32]&(1<<uint(c.fd%32)) == 0 {
			return 0, "", fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
	}

	n, from, err := syscall.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) {
			return 0, "", fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
		return 0, "", fmt.Errorf("rawconn: recvfrom: %w", err)
	}

	var srcIP string
	if addr, ok := from.(*syscall.SockaddrInet4); ok {
		srcIP = net.IP(addr.Addr[:]).String()
	} else if addr, ok := from.(*syscall.SockaddrInet6); ok {
		srcIP = net.IP(addr.Addr[:]).String()
	}

	return n, srcIP, nil
}

// Close releases the underlying raw socket descriptor.
func (c *RawConn) Close() error {
	if err := syscall.Close(c.fd); err != nil {
		return fmt.Errorf("rawconn: close: %w", err)
	}
	return nil
}

// SendRaw dials a temporary raw socket, sends data, and closes.
func SendRaw(proto int, data []byte, dst string) error {
	conn, err := DialRaw(proto)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Send(data, dst)
}

// RecvRaw dials a temporary raw socket, receives one packet, and closes.
func RecvRaw(proto int, timeout time.Duration) ([]byte, string, error) {
	conn, err := DialRaw(proto)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	return conn.Recv(timeout)
}
