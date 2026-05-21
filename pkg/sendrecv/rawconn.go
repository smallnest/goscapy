package sendrecv

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// RawConn represents a raw socket connection.
type RawConn struct {
	fd            int
	zeroCopy      bool
	zeroCopyMu    sync.Mutex
	nextSendSeq   uint32
	completed     map[uint32]bool
	lowestPending uint32
}

// Send transmits raw payload bytes to the target destination IP.
// Supports both IPv4 and IPv6 destinations.
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

		flags := 0
		if c.zeroCopy {
			flags = msgZeroCopy
			c.zeroCopyMu.Lock()
			c.nextSendSeq++
			c.zeroCopyMu.Unlock()
		}

		if err := syscall.Sendto(c.fd, data, flags, &addr); err != nil {
			return fmt.Errorf("rawconn: sendto: %w", err)
		}
		return nil
	}

	// IPv6 path.
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

	flags := 0
	if c.zeroCopy {
		flags = msgZeroCopy
		c.zeroCopyMu.Lock()
		c.nextSendSeq++
		c.zeroCopyMu.Unlock()
	}

	if err := syscall.Sendto(c.fd, data, flags, &addr); err != nil {
		return fmt.Errorf("rawconn: sendto IPv6: %w", err)
	}
	return nil
}

// Recv reads one raw packet payload from the socket, returning the payload bytes,
// the source IP string, and any error. If the timeout is exceeded, it returns ErrTimeout.
func (c *RawConn) Recv(timeout time.Duration) ([]byte, string, error) {
	buf := make([]byte, 65536)
	n, src, err := c.RecvInto(buf, timeout)
	if err != nil {
		return nil, "", err
	}
	return buf[:n], src, nil
}

// RecvInto reads one raw packet payload into the caller-provided buffer.
// Returns the number of bytes read and the source IP string.
// The returned data is buf[:n] — valid until the next call or until buf is reused.
func (c *RawConn) RecvInto(buf []byte, timeout time.Duration) (int, string, error) {
	if timeout > 0 {
		timeoutMs := int(timeout.Milliseconds())
		if timeoutMs <= 0 {
			timeoutMs = 1
		}
		fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, timeoutMs)
		if err != nil {
			if err == unix.EINTR {
				return 0, "", fmt.Errorf("%w after %v", ErrTimeout, timeout)
			}
			return 0, "", fmt.Errorf("rawconn: poll: %w", err)
		}
		if n == 0 {
			return 0, "", fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
	}

	n, from, err := syscall.Recvfrom(c.fd, buf, syscall.MSG_DONTWAIT)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return 0, "", fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
		return 0, "", fmt.Errorf("rawconn: recvfrom: %w", err)
	}

	var srcIP string
	if addr, ok := from.(*syscall.SockaddrInet4); ok {
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

// SendRaw dials a temporary raw socket connection, sends the data to the destination IP,
// and closes the connection.
func SendRaw(proto int, data []byte, dst string) error {
	conn, err := DialRaw(proto)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Send(data, dst)
}

// RecvRaw dials a temporary raw socket connection, receives one packet payload within the
// specified timeout, and closes the connection.
func RecvRaw(proto int, timeout time.Duration) ([]byte, string, error) {
	conn, err := DialRaw(proto)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	return conn.Recv(timeout)
}
