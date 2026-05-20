package sendrecv

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
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
func (c *RawConn) Send(data []byte, dst string) error {
	ip := net.ParseIP(dst)
	if ip == nil {
		return fmt.Errorf("rawconn: invalid destination IP: %s", dst)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("rawconn: only IPv4 is supported")
	}

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

// Recv reads one raw packet payload from the socket, returning the payload bytes,
// the source IP string, and any error. If the timeout is exceeded, it returns ErrTimeout.
func (c *RawConn) Recv(timeout time.Duration) ([]byte, string, error) {
	if timeout > 0 {
		tv := syscall.NsecToTimeval(timeout.Nanoseconds())
		if err := syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, "", fmt.Errorf("rawconn: setsockopt SO_RCVTIMEO: %w", err)
		}
	} else {
		tv := syscall.Timeval{Sec: 0, Usec: 0}
		if err := syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, "", fmt.Errorf("rawconn: setsockopt SO_RCVTIMEO: %w", err)
		}
	}

	buf := make([]byte, 65536)
	n, from, err := syscall.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, "", fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
		return nil, "", fmt.Errorf("rawconn: recvfrom: %w", err)
	}

	var srcIP string
	if addr, ok := from.(*syscall.SockaddrInet4); ok {
		srcIP = net.IP(addr.Addr[:]).String()
	}

	return buf[:n], srcIP, nil
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
