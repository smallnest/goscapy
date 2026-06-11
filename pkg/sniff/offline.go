package sniff

import (
	"fmt"
	"io"
	"os"

	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/pcap"
)

// OfflineConfig configures offline sniffing from a pcap/pcapng file.
type OfflineConfig struct {
	// Path is the capture file to read (used by SniffOffline). Ignored when an
	// io.Reader is passed directly to SniffOfflineReader.
	Path string

	// Count is the maximum number of packets to process (0 = unlimited).
	Count int

	// Filter is an optional packet-level predicate. Unlike live sniffing,
	// offline filtering is applied in Go (no BPF/tcpdump dependency): a packet
	// is delivered to the handler only if Filter returns true. If nil, all
	// packets pass.
	Filter func(pkt *packet.Packet) bool
}

// SniffOffline reads packets from a pcap or pcapng file and invokes handler
// for each one, mirroring Scapy's sniff(offline=...). It dissects each record
// using the file's link-layer type, applies the optional Go-level Filter, and
// stops when the handler returns false, the count limit is reached, or EOF.
//
// Records that fail to dissect are skipped (offline captures often contain
// truncated or unsupported frames); dissection errors are not fatal.
func SniffOffline(cfg OfflineConfig, handler SniffHandler) error {
	if cfg.Path == "" {
		return fmt.Errorf("sniff: offline path is required")
	}
	f, err := os.Open(cfg.Path)
	if err != nil {
		return fmt.Errorf("sniff: open %q: %w", cfg.Path, err)
	}
	defer func() { _ = f.Close() }()
	return SniffOfflineReader(f, cfg, handler)
}

// SniffOfflineReader is like SniffOffline but reads from an arbitrary
// io.Reader (e.g. a network stream or embedded capture). The cfg.Path field
// is ignored.
func SniffOfflineReader(r io.Reader, cfg OfflineConfig, handler SniffHandler) error {
	if handler == nil {
		return fmt.Errorf("sniff: handler is required")
	}
	rd, err := pcap.NewReader(r)
	if err != nil {
		return fmt.Errorf("sniff: open capture: %w", err)
	}

	processed := 0
	for cfg.Count <= 0 || processed < cfg.Count {
		rec, err := rd.ReadPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("sniff: read packet: %w", err)
		}

		pkt, err := rec.Packet()
		if err != nil {
			continue // skip undissectable records
		}
		if cfg.Filter != nil && !cfg.Filter(pkt) {
			continue
		}

		processed++
		if !handler(pkt) {
			break
		}
	}
	return nil
}

// SniffOfflineChan reads a capture file and returns a channel of dissected
// packets plus a stop function, analogous to SniffChan for live capture.
func SniffOfflineChan(cfg OfflineConfig) (<-chan *packet.Packet, func()) {
	ch := make(chan *packet.Packet, 64)
	done := make(chan struct{})
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			close(done)
		}
	}

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
		_ = SniffOffline(cfg, handler)
	}()

	return ch, stop
}
