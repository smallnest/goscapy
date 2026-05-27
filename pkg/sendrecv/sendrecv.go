package sendrecv

import (
	"errors"
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
	// RecvInto reads one raw packet into the caller-provided buffer, dissects it,
	// and returns the parsed Packet plus the number of bytes read.
	// The returned Packet's internal fields may reference buf directly — the Packet
	// is only valid until the next RecvInto call or until buf is reused.
	// If buf is too small for the received packet, the packet is truncated.
	RecvInto(buf []byte, timeout time.Duration) (*packet.Packet, int, error)
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

// ---- Internal helpers ----

// collectResponses reads packets from rx until the deadline, collecting those
// that match. If match is nil, all packets are collected.
func collectResponses(rx Receiver, deadline time.Time, match MatchFunc, pkt *packet.Packet) []*packet.Packet {
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
		if match == nil || match(pkt, resp) {
			responses = append(responses, resp)
		}
	}
	return responses
}

// collectFirstResponse reads packets from rx until the deadline, returning the
// first that matches. Returns nil, false if none found.
func collectFirstResponse(rx Receiver, deadline time.Time, match MatchFunc, pkt *packet.Packet) (*packet.Packet, bool) {
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		resp, err := rx.Recv(remaining)
		if err != nil {
			break
		}
		if match == nil || match(pkt, resp) {
			return resp, true
		}
	}
	return nil, false
}

// sendAndCollect opens a receiver, sends a packet, and collects responses.
// sendL2 chooses L2 (Sendp) vs L3 (Send). match may be nil to collect all.
func sendAndCollect(pkt *packet.Packet, sendL2 bool, iface string, timeout time.Duration, filter []BPFInstruction, match MatchFunc, firstOnly bool) (*packet.Packet, *packet.Packet, []*packet.Packet, error) {
	var rx Receiver
	var err error

	if len(filter) > 0 {
		rx, err = OpenFilteredReceiver(iface, filter)
	} else {
		rx, err = OpenReceiver(iface)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	defer rx.Close()

	if sendL2 {
		if err := Sendp(pkt, iface); err != nil {
			return nil, nil, nil, err
		}
	} else {
		if err := Send(pkt, iface); err != nil {
			return nil, nil, nil, err
		}
	}

	deadline := time.Now().Add(timeout)

	if firstOnly {
		first, ok := collectFirstResponse(rx, deadline, match, pkt)
		if !ok {
			return pkt, nil, nil, nil
		}
		return pkt, first, nil, nil
	}

	responses := collectResponses(rx, deadline, match, pkt)
	return pkt, nil, responses, nil
}

// ---- Public SendRecv variants ----

// SendRecv opens a receiver, sends a packet at L3, then collects response
// packets until timeout. The receiver is opened before sending to avoid
// missing fast responses (e.g. on loopback).
// Returns the sent packet and all received response packets.
func SendRecv(pkt *packet.Packet, iface string, timeout time.Duration) (*packet.Packet, []*packet.Packet, error) {
	_, _, responses, err := sendAndCollect(pkt, false, iface, timeout, nil, nil, false)
	return pkt, responses, err
}

// SendRecv1 sends a packet at L3 and returns the first response, or nil
// if no response is received within the timeout.
func SendRecv1(pkt *packet.Packet, iface string, timeout time.Duration) (*packet.Packet, *packet.Packet, error) {
	_, first, _, err := sendAndCollect(pkt, false, iface, timeout, nil, nil, true)
	return pkt, first, err
}

// SendRecvFiltered is like SendRecv but applies a BPF filter to the receiver,
// so only packets matching the filter are captured.
func SendRecvFiltered(pkt *packet.Packet, iface string, timeout time.Duration, instructions []BPFInstruction) (*packet.Packet, []*packet.Packet, error) {
	_, _, responses, err := sendAndCollect(pkt, false, iface, timeout, instructions, nil, false)
	return pkt, responses, err
}

// SendRecvFiltered1 is like SendRecv1 but applies a BPF filter.
func SendRecvFiltered1(pkt *packet.Packet, iface string, timeout time.Duration, instructions []BPFInstruction) (*packet.Packet, *packet.Packet, error) {
	_, first, _, err := sendAndCollect(pkt, false, iface, timeout, instructions, nil, true)
	return pkt, first, err
}

// Sr sends a packet at L3 and collects matching response packets.
// It uses the provided MatchFunc (or DefaultMatch if nil) to match responses
// against the sent packet, mimicking Scapy's sr() function.
func Sr(pkt *packet.Packet, iface string, timeout time.Duration, match MatchFunc) (*packet.Packet, []*packet.Packet, error) {
	if match == nil {
		match = DefaultMatch(pkt)
	}
	_, _, responses, err := sendAndCollect(pkt, false, iface, timeout, nil, match, false)
	return pkt, responses, err
}

// Sr1 sends a packet at L3 and returns the first matching response.
// It mimics Scapy's sr1() function. If match is nil, DefaultMatch is used.
func Sr1(pkt *packet.Packet, iface string, timeout time.Duration, match MatchFunc) (*packet.Packet, *packet.Packet, error) {
	if match == nil {
		match = DefaultMatch(pkt)
	}
	_, first, _, err := sendAndCollect(pkt, false, iface, timeout, nil, match, true)
	return pkt, first, err
}

// Srp sends a packet at L2 and collects matching response packets.
// It uses the provided MatchFunc (or DefaultMatch if nil) to match responses
// against the sent packet, mimicking Scapy's srp() function.
func Srp(pkt *packet.Packet, iface string, timeout time.Duration, match MatchFunc) (*packet.Packet, []*packet.Packet, error) {
	if match == nil {
		match = DefaultMatch(pkt)
	}
	_, _, responses, err := sendAndCollect(pkt, true, iface, timeout, nil, match, false)
	return pkt, responses, err
}

// Srp1 sends a packet at L2 and returns the first matching response.
// It mimics Scapy's srp1() function. If match is nil, DefaultMatch is used.
func Srp1(pkt *packet.Packet, iface string, timeout time.Duration, match MatchFunc) (*packet.Packet, *packet.Packet, error) {
	if match == nil {
		match = DefaultMatch(pkt)
	}
	_, first, _, err := sendAndCollect(pkt, true, iface, timeout, nil, match, true)
	return pkt, first, err
}

// Platform-specific implementations are provided in:
//   - sendrecv_darwin.go (macOS: BPF + AF_INET)
//   - sendrecv_linux.go  (Linux: AF_PACKET + AF_INET)
//
// Each platform file must implement:
//
//	openReceiver(iface string) (Receiver, error)
//	openFilteredReceiver(iface string, instructions []BPFInstruction) (Receiver, error)
//	sendL3(pkt *packet.Packet, iface string) error
//	sendL2(pkt *packet.Packet, iface string) error
//	loopbackName() string