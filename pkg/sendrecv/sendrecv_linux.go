//go:build linux

package sendrecv

import (
	"fmt"
	"runtime"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ETH_P_ALL captures all Ethernet protocols.
const _ETH_P_ALL = 0x0003

func loopbackName() string { return "lo" }

// --- L3 Send (AF_INET raw socket) ---

func sendL3(pkt *packet.Packet, iface string) error {
	rawBytes, err := buildL3(pkt)
	if err != nil {
		return fmt.Errorf("sendrecv: L3 build: %w", err)
	}

	dstIP, err := extractDstIP(pkt)
	if err != nil {
		return err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("sendrecv: socket: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("sendrecv: setsockopt IP_HDRINCL: %w", err)
	}

	addr := syscall.SockaddrInet4{Addr: dstIP}
	if err := syscall.Sendto(fd, rawBytes, 0, &addr); err != nil {
		return fmt.Errorf("sendrecv: sendto: %w", err)
	}

	runtime.KeepAlive(rawBytes)
	return nil
}

// --- L2 Send (AF_PACKET) ---

func sendL2(pkt *packet.Packet, iface string) error {
	rawBytes, err := pkt.Build()
	if err != nil {
		return fmt.Errorf("sendrecv: L2 build: %w", err)
	}

	ifaceObj, err := lookupInterface(iface)
	if err != nil {
		return err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(_ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("sendrecv: AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(_ETH_P_ALL),
		Ifindex:  ifaceObj.Index,
		Hatype:   0, // ARPHRD_ETHER would be 1, but 0 works for sending
	}

	if err := syscall.Sendto(fd, rawBytes, 0, &addr); err != nil {
		return fmt.Errorf("sendrecv: AF_PACKET sendto: %w", err)
	}

	runtime.KeepAlive(rawBytes)
	return nil
}

// --- Receiver (AF_PACKET) ---

type afPacketReceiver struct {
	fd    int
	iface string
}

func openReceiver(iface string) (Receiver, error) {
	ifaceObj, err := lookupInterface(iface)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(_ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("sendrecv: AF_PACKET socket: %w", err)
	}

	// Bind to the specific interface.
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(_ETH_P_ALL),
		Ifindex:  ifaceObj.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("sendrecv: AF_PACKET bind: %w", err)
	}

	return &afPacketReceiver{fd: fd, iface: iface}, nil
}

func (r *afPacketReceiver) Recv(timeout time.Duration) (*packet.Packet, error) {
	// Set read timeout via SO_RCVTIMEO.
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(r.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("sendrecv: SO_RCVTIMEO: %w", err)
	}

	buf := make([]byte, 65536)
	n, _, err := syscall.Recvfrom(r.fd, buf, 0)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return nil, fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
		return nil, fmt.Errorf("sendrecv: recvfrom: %w", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("sendrecv: recvfrom returned 0 bytes")
	}

	raw := buf[:n]
	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		return nil, fmt.Errorf("sendrecv: dissect: %w", err)
	}

	return pkt, nil
}

func (r *afPacketReceiver) Close() error {
	return syscall.Close(r.fd)
}

// htons converts a uint16 from host to network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// ensure afPacketReceiver implements Receiver at compile time.
var _ Receiver = (*afPacketReceiver)(nil)
