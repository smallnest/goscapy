//go:build !linux

package sendrecv

import (
	"fmt"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

func openReceiver(iface string) (Receiver, error) {
	return nil, fmt.Errorf("sendrecv: OpenReceiver not implemented on this platform")
}

func openFilteredReceiver(iface string, instructions []BPFInstruction) (Receiver, error) {
	return nil, fmt.Errorf("sendrecv: OpenFilteredReceiver not implemented on this platform")
}

func loopbackName() string {
	return "lo"
}

func sendL3(pkt *packet.Packet, iface string) error {
	return fmt.Errorf("sendrecv: Send not implemented on this platform")
}

func sendL2(pkt *packet.Packet, iface string) error {
	return fmt.Errorf("sendrecv: Sendp not implemented on this platform")
}

type RawConn struct {
	fd int
}

func (c *RawConn) Send(data []byte, dst string) error {
	return fmt.Errorf("rawconn: Send not implemented on this platform")
}

func (c *RawConn) Recv(timeout time.Duration) ([]byte, string, error) {
	return nil, "", fmt.Errorf("rawconn: Recv not implemented on this platform")
}

func (c *RawConn) RecvInto(buf []byte, timeout time.Duration) (int, string, error) {
	return 0, "", fmt.Errorf("rawconn: RecvInto not implemented on this platform")
}

func (c *RawConn) Close() error {
	return nil
}

func DialRaw(proto int) (*RawConn, error) {
	return nil, fmt.Errorf("rawconn: DialRaw not implemented on this platform")
}

func SendRaw(proto int, data []byte, dst string) error {
	return fmt.Errorf("rawconn: SendRaw not implemented on this platform")
}

func RecvRaw(proto int, timeout time.Duration) ([]byte, string, error) {
	return nil, "", fmt.Errorf("rawconn: RecvRaw not implemented on this platform")
}
