// Package answer provides an AnsweringMachine framework, mirroring Scapy's
// AnsweringMachine. It sniffs incoming packets on an interface, decides whether
// each one is a stimulus worth replying to, builds a reply, and sends it.
//
// It is the basis for lightweight service emulation (ARP responder, DHCP/DNS
// server, ICMP echo responder) and honeypots. The framework handles the
// sniff→match→reply→send loop; callers supply two functions:
//
//	IsRequest(pkt) bool                       — is this a stimulus we answer?
//	MakeReply(pkt) (*packet.Packet, bool)     — build the reply (false = skip)
//
// Example (ICMP echo responder):
//
//	am := answer.New(answer.Config{Iface: "eth0"}, answer.Funcs{
//	    IsRequest: func(p *packet.Packet) bool {
//	        ic := p.GetLayer("ICMP")
//	        if ic == nil { return false }
//	        t, _ := ic.Get("type")
//	        return t == layers.ICMPEchoRequest
//	    },
//	    MakeReply: buildEchoReply,
//	})
//	am.Run(ctx)
package answer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Config holds answering-machine configuration.
type Config struct {
	// Iface is the interface to listen and reply on (required).
	Iface string

	// Instructions is an optional pre-compiled BPF filter applied at the
	// kernel level to reduce the packets delivered to IsRequest.
	Instructions []sendrecv.BPFInstruction

	// SendL2, when true, transmits replies as L2 frames (Sendp). Otherwise
	// replies are sent at L3 (Send) and the OS adds the link-layer header.
	// Use L2 for ARP and other link-layer protocols.
	SendL2 bool

	// Count limits the number of replies sent (0 = unlimited).
	Count int

	// ReadTimeout bounds each receive call so the loop can observe context
	// cancellation. Defaults to 1 second.
	ReadTimeout time.Duration
}

// Funcs supplies the decision and reply-construction callbacks.
type Funcs struct {
	// IsRequest reports whether pkt is a stimulus the machine should answer.
	// Required.
	IsRequest func(pkt *packet.Packet) bool

	// MakeReply builds the reply packet for a matched request. Returning
	// (nil, false) skips this request without sending. Required.
	MakeReply func(pkt *packet.Packet) (*packet.Packet, bool)

	// OnReply, if set, is called after each reply is sent (for logging/metrics).
	OnReply func(request, reply *packet.Packet)
}

// AnsweringMachine ties a receiver, a matcher, and a reply builder into a loop.
type AnsweringMachine struct {
	cfg   Config
	funcs Funcs
}

// New creates an AnsweringMachine. It panics if required callbacks are missing,
// matching the fail-fast convention of misconfigured builders.
func New(cfg Config, funcs Funcs) *AnsweringMachine {
	return &AnsweringMachine{cfg: cfg, funcs: funcs}
}

// Funcs returns the machine's decision/reply callbacks. This lets callers
// unit-test a responder's matching and reply-building logic without opening a
// raw socket.
func (am *AnsweringMachine) Funcs() Funcs { return am.funcs }

// Config returns the machine's configuration.
func (am *AnsweringMachine) Config() Config { return am.cfg }

// SetOnReply sets (or replaces) the post-reply callback used for
// logging/metrics, returning the machine for chaining. It is a convenience
// for responders constructed by helper functions that don't expose OnReply.
func (am *AnsweringMachine) SetOnReply(fn func(request, reply *packet.Packet)) *AnsweringMachine {
	am.funcs.OnReply = fn
	return am
}

// Run starts the answering loop and blocks until ctx is cancelled, the count
// limit is reached, or a fatal receive error occurs. It returns the number of
// replies sent and the terminating error (nil or ctx.Err() on clean stop).
func (am *AnsweringMachine) Run(ctx context.Context) (int, error) {
	if am.cfg.Iface == "" {
		return 0, fmt.Errorf("answer: interface is required")
	}
	if am.funcs.IsRequest == nil || am.funcs.MakeReply == nil {
		return 0, fmt.Errorf("answer: IsRequest and MakeReply are required")
	}

	readTimeout := am.cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = time.Second
	}

	rx, err := sendrecv.OpenFilteredReceiver(am.cfg.Iface, am.cfg.Instructions)
	if err != nil {
		return 0, fmt.Errorf("answer: open receiver: %w", err)
	}
	defer func() { _ = rx.Close() }()

	replies := 0
	for am.cfg.Count <= 0 || replies < am.cfg.Count {
		select {
		case <-ctx.Done():
			return replies, ctx.Err()
		default:
		}

		pkt, err := rx.Recv(readTimeout)
		if err != nil {
			if errors.Is(err, sendrecv.ErrTimeout) {
				continue
			}
			return replies, fmt.Errorf("answer: recv: %w", err)
		}

		if !am.funcs.IsRequest(pkt) {
			continue
		}
		reply, ok := am.funcs.MakeReply(pkt)
		if !ok || reply == nil {
			continue
		}

		if am.cfg.SendL2 {
			err = sendrecv.Sendp(reply, am.cfg.Iface)
		} else {
			err = sendrecv.Send(reply, am.cfg.Iface)
		}
		if err != nil {
			return replies, fmt.Errorf("answer: send reply: %w", err)
		}

		replies++
		if am.funcs.OnReply != nil {
			am.funcs.OnReply(pkt, reply)
		}
	}
	return replies, nil
}
