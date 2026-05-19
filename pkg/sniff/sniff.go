package sniff

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// SniffConfig holds sniffing configuration.
type SniffConfig struct {
	// Iface is the network interface to sniff on (required).
	Iface string

	// Filter is a BPF filter expression such as "tcp port 80" (optional).
	// Compiled at runtime via CompileFilter (requires tcpdump on PATH).
	// If both Filter and Instructions are set, Instructions takes precedence.
	Filter string

	// Instructions are pre-compiled BPF instructions (optional).
	// Takes precedence over Filter if both are set.
	Instructions []sendrecv.BPFInstruction

	// Count is the maximum number of packets to capture (0 = unlimited).
	Count int

	// Timeout is the total sniffing duration (0 = no timeout).
	Timeout time.Duration
}

// SniffHandler is called for each captured packet.
// Return true to continue sniffing, false to stop.
type SniffHandler func(pkt *packet.Packet) bool

// Sniff captures packets from the given interface using a callback handler.
// It blocks until the count limit is reached, the timeout expires, or the
// handler returns false.
func Sniff(cfg SniffConfig, handler SniffHandler) error {
	if cfg.Iface == "" {
		return fmt.Errorf("sniff: interface is required")
	}
	if handler == nil {
		return fmt.Errorf("sniff: handler is required")
	}

	instructions, err := resolveFilter(cfg)
	if err != nil {
		return err
	}

	rx, err := sendrecv.OpenFilteredReceiver(cfg.Iface, instructions)
	if err != nil {
		return fmt.Errorf("sniff: open receiver: %w", err)
	}
	defer rx.Close()

	deadline := time.Time{}
	if cfg.Timeout > 0 {
		deadline = time.Now().Add(cfg.Timeout)
	}

	captured := 0
	for {
		// Check count limit.
		if cfg.Count > 0 && captured >= cfg.Count {
			break
		}

		// Check total timeout.
		if !deadline.IsZero() {
			if time.Now().After(deadline) {
				break
			}
		}

		// Determine per-read timeout (1 second default for responsiveness).
		readTimeout := time.Second
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			readTimeout = min(readTimeout, remaining)
		}

		pkt, err := rx.Recv(readTimeout)
		if err != nil {
			if errors.Is(err, sendrecv.ErrTimeout) {
				continue // normal per-read timeout, retry
			}
			return fmt.Errorf("sniff: recv: %w", err)
		}

		captured++
		if !handler(pkt) {
			break
		}
	}

	return nil
}

// SniffChan returns a channel that delivers captured packets and a stop function.
// The channel is closed when sniffing completes (count/timeout reached) or
// when the stop function is called.
func SniffChan(cfg SniffConfig) (<-chan *packet.Packet, func()) {
	ch := make(chan *packet.Packet, 64)
	done := make(chan struct{})
	stop := sync.OnceFunc(func() { close(done) })

	go func() {
		defer close(ch)

		handler := func(pkt *packet.Packet) bool {
			select {
			case ch <- pkt:
				return true
			case <-done:
				return false
			}
		}

		_ = Sniff(cfg, handler)
	}()

	return ch, stop
}

// resolveFilter resolves the filter configuration to BPF instructions.
// Pre-compiled instructions take precedence over filter strings.
func resolveFilter(cfg SniffConfig) ([]sendrecv.BPFInstruction, error) {
	if len(cfg.Instructions) > 0 {
		return cfg.Instructions, nil
	}
	if cfg.Filter == "" {
		return nil, nil // no filter
	}
	return CompileFilter(cfg.Filter)
}
