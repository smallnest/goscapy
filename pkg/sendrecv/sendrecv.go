package sendrecv

import (
	"errors"
	"fmt"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ErrTimeout is returned by Receiver.Recv when the read timeout is exceeded.
// Sniffing loops can use errors.Is(err, ErrTimeout) to distinguish timeouts
// from fatal errors.
var ErrTimeout = errors.New("sendrecv: recv timeout")

// BPFInstruction represents a single classic BPF instruction.
// It mirrors the layout of struct bpf_insn (BSD/macOS) and struct sock_filter (Linux).
type BPFInstruction struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// Receiver reads raw packets from a network interface.
type Receiver interface {
	// Recv reads one raw packet, dissects it, and returns the parsed Packet.
	// Returns ErrTimeout if the timeout is exceeded.
	Recv(timeout time.Duration) (*packet.Packet, error)
	// Close releases the receiver's resources.
	Close() error
}

// OpenReceiver opens a raw-packet receiver on the given interface.
// The caller must call Close when done.
func OpenReceiver(iface string) (Receiver, error) {
	return openReceiver(iface)
}

// OpenFilteredReceiver opens a raw-packet receiver on the given interface
// with the specified BPF filter applied at the kernel level.
// Pass nil or empty instructions to capture all packets.
func OpenFilteredReceiver(iface string, instructions []BPFInstruction) (Receiver, error) {
	return openFilteredReceiver(iface, instructions)
}

// LoopbackName returns the name of the loopback interface on the current platform
// ("lo0" on macOS, "lo" on Linux).
func LoopbackName() string { return loopbackName() }

// Send sends a packet at L3 (IP level) on the given interface.
// The OS handles L2 framing (Ethernet header).
// If the packet contains an Ethernet layer, it is skipped during build
// (BuildFrom(1) is used).
func Send(pkt *packet.Packet, iface string) error {
	return sendL3(pkt, iface)
}

// Sendp sends a packet at L2 (Ethernet frame) on the given interface.
// The packet must include an Ethernet layer. The entire frame is built
// and written to the wire.
func Sendp(pkt *packet.Packet, iface string) error {
	return sendL2(pkt, iface)
}

// Recv opens a receiver on the given interface, reads one packet, and closes.
// Returns the parsed packet or an error (including timeout).
func Recv(iface string, timeout time.Duration) (*packet.Packet, error) {
	rx, err := OpenReceiver(iface)
	if err != nil {
		return nil, err
	}
	defer rx.Close()

	return rx.Recv(timeout)
}

// SendRecv opens a receiver, sends a packet at L3, then collects response
// packets until timeout. The receiver is opened before sending to avoid
// missing fast responses (e.g. on loopback).
// Returns the sent packet and all received response packets.
func SendRecv(pkt *packet.Packet, iface string, timeout time.Duration) (*packet.Packet, []*packet.Packet, error) {
	// Open receiver before sending to avoid racing with the response.
	rx, err := OpenReceiver(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("sendrecv: SendRecv open receiver: %w", err)
	}
	defer rx.Close()

	if err := Send(pkt, iface); err != nil {
		return nil, nil, fmt.Errorf("sendrecv: SendRecv send: %w", err)
	}

	deadline := time.Now().Add(timeout)
	var responses []*packet.Packet

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		resp, err := rx.Recv(remaining)
		if err != nil {
			// Timeout or other error — stop collecting.
			break
		}
		responses = append(responses, resp)
	}

	return pkt, responses, nil
}

// SendRecv1 sends a packet at L3 and returns the first response, or nil
// if no response is received within the timeout.
func SendRecv1(pkt *packet.Packet, iface string, timeout time.Duration) (*packet.Packet, *packet.Packet, error) {
	_, responses, err := SendRecv(pkt, iface, timeout)
	if err != nil {
		return nil, nil, err
	}
	if len(responses) == 0 {
		return pkt, nil, nil
	}
	return pkt, responses[0], nil
}

// SendRecvFiltered is like SendRecv but applies a BPF filter to the receiver,
// so only packets matching the filter are captured.
func SendRecvFiltered(pkt *packet.Packet, iface string, timeout time.Duration, instructions []BPFInstruction) (*packet.Packet, []*packet.Packet, error) {
	rx, err := OpenFilteredReceiver(iface, instructions)
	if err != nil {
		return nil, nil, fmt.Errorf("sendrecv: SendRecvFiltered open receiver: %w", err)
	}
	defer rx.Close()

	if err := Send(pkt, iface); err != nil {
		return nil, nil, fmt.Errorf("sendrecv: SendRecvFiltered send: %w", err)
	}

	deadline := time.Now().Add(timeout)
	var responses []*packet.Packet

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		resp, err := rx.Recv(remaining)
		if err != nil {
			break
		}
		responses = append(responses, resp)
	}

	return pkt, responses, nil
}

// SendRecvFiltered1 is like SendRecv1 but applies a BPF filter.
func SendRecvFiltered1(pkt *packet.Packet, iface string, timeout time.Duration, instructions []BPFInstruction) (*packet.Packet, *packet.Packet, error) {
	_, responses, err := SendRecvFiltered(pkt, iface, timeout, instructions)
	if err != nil {
		return nil, nil, err
	}
	if len(responses) == 0 {
		return pkt, nil, nil
	}
	return pkt, responses[0], nil
}

// Platform-specific implementations are provided in:
//   - sendrecv_darwin.go (macOS: BPF + AF_INET)
//   - sendrecv_linux.go  (Linux: AF_PACKET + AF_INET)
//
// Each platform file must implement:
//   openReceiver(iface string) (Receiver, error)
//   openFilteredReceiver(iface string, instructions []BPFInstruction) (Receiver, error)
//   sendL3(pkt *packet.Packet, iface string) error
//   sendL2(pkt *packet.Packet, iface string) error
//   loopbackName() string
