// Package packetlist provides PacketList, a batch container for dissected
// packets with timestamps, mirroring Scapy's PacketList (the value returned by
// rdpcap/sniff). It supports slicing, filtering, per-protocol statistics,
// session grouping, and bulk display — the building blocks of offline
// capture analysis.
package packetlist

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// Entry is one captured packet with its capture timestamp and optional raw
// wire bytes (nil if the list was built from already-parsed packets).
type Entry struct {
	Packet *packet.Packet
	Time   time.Time
	Data   []byte
}

// PacketList is an ordered collection of captured packets.
type PacketList struct {
	name    string
	entries []Entry
}

// New creates an empty PacketList with an optional display name.
func New(name string) *PacketList {
	return &PacketList{name: name}
}

// FromPackets builds a PacketList from already-parsed packets, assigning each
// the zero timestamp. Useful for ad-hoc grouping/analysis.
func FromPackets(pkts ...*packet.Packet) *PacketList {
	pl := &PacketList{entries: make([]Entry, 0, len(pkts))}
	for _, p := range pkts {
		pl.entries = append(pl.entries, Entry{Packet: p})
	}
	return pl
}

// Name returns the list's display name.
func (pl *PacketList) Name() string { return pl.name }

// SetName sets the list's display name and returns the list for chaining.
func (pl *PacketList) SetName(name string) *PacketList {
	pl.name = name
	return pl
}

// Len returns the number of packets.
func (pl *PacketList) Len() int { return len(pl.entries) }

// Entries returns the underlying entries (read-only; do not mutate the slice).
func (pl *PacketList) Entries() []Entry { return pl.entries }

// Get returns the i-th packet, or nil if out of range.
func (pl *PacketList) Get(i int) *packet.Packet {
	if i < 0 || i >= len(pl.entries) {
		return nil
	}
	return pl.entries[i].Packet
}

// GetEntry returns the i-th entry and true, or a zero Entry and false.
func (pl *PacketList) GetEntry(i int) (Entry, bool) {
	if i < 0 || i >= len(pl.entries) {
		return Entry{}, false
	}
	return pl.entries[i], true
}

// Append adds a packet with the given timestamp and returns the list.
func (pl *PacketList) Append(pkt *packet.Packet, ts time.Time) *PacketList {
	pl.entries = append(pl.entries, Entry{Packet: pkt, Time: ts})
	return pl
}

// AppendEntry adds a pre-built entry and returns the list.
func (pl *PacketList) AppendEntry(e Entry) *PacketList {
	pl.entries = append(pl.entries, e)
	return pl
}

// Slice returns a new PacketList containing entries [start, end), clamped to
// valid bounds, mirroring Python's pl[start:end].
func (pl *PacketList) Slice(start, end int) *PacketList {
	if start < 0 {
		start = 0
	}
	if end > len(pl.entries) || end < 0 {
		end = len(pl.entries)
	}
	if start > end {
		start = end
	}
	out := &PacketList{name: pl.name, entries: make([]Entry, end-start)}
	copy(out.entries, pl.entries[start:end])
	return out
}

// Filter returns a new PacketList containing only packets for which pred
// returns true, mirroring Scapy's pl.filter().
func (pl *PacketList) Filter(pred func(*packet.Packet) bool) *PacketList {
	out := &PacketList{name: pl.name}
	for _, e := range pl.entries {
		if pred(e.Packet) {
			out.entries = append(out.entries, e)
		}
	}
	return out
}

// FilterProto returns a new PacketList of packets containing the given layer.
func (pl *PacketList) FilterProto(proto string) *PacketList {
	return pl.Filter(func(p *packet.Packet) bool { return p.HasLayer(proto) })
}

// Each invokes fn for every packet in order (with its index).
func (pl *PacketList) Each(fn func(i int, pkt *packet.Packet)) {
	for i, e := range pl.entries {
		fn(i, e.Packet)
	}
}

// Statistics returns a count of packets per top-level protocol-stack string
// (e.g. "Ethernet / IP / TCP"), mirroring the breakdown Scapy prints. The
// result maps the stack signature to its occurrence count.
func (pl *PacketList) Statistics() map[string]int {
	stats := make(map[string]int)
	for _, e := range pl.entries {
		stats[e.Packet.String()]++
	}
	return stats
}

// ProtoCounts returns a count of packets containing each protocol layer.
// Unlike Statistics (which keys on the full stack), this counts how many
// packets include a given layer anywhere in the stack.
func (pl *PacketList) ProtoCounts() map[string]int {
	counts := make(map[string]int)
	for _, e := range pl.entries {
		seen := make(map[string]bool)
		for _, l := range e.Packet.Layers() {
			if !seen[l.Proto()] {
				counts[l.Proto()]++
				seen[l.Proto()] = true
			}
		}
	}
	return counts
}

// Summary returns a multi-line listing, one packet per line, prefixed by
// index, mirroring Scapy's pl.summary().
func (pl *PacketList) Summary() string {
	var b strings.Builder
	for i, e := range pl.entries {
		fmt.Fprintf(&b, "%04d  %s\n", i, e.Packet.Summary())
	}
	return b.String()
}

// String returns a short description like "name <N packets>".
func (pl *PacketList) String() string {
	name := pl.name
	if name == "" {
		name = "PacketList"
	}
	return fmt.Sprintf("%s <%d packets>", name, len(pl.entries))
}

// TimeSpan returns the earliest and latest non-zero timestamps in the list.
// If no entry has a timestamp, both returned times are zero.
func (pl *PacketList) TimeSpan() (first, last time.Time) {
	for _, e := range pl.entries {
		if e.Time.IsZero() {
			continue
		}
		if first.IsZero() || e.Time.Before(first) {
			first = e.Time
		}
		if last.IsZero() || e.Time.After(last) {
			last = e.Time
		}
	}
	return first, last
}

// SortByTime sorts the list in ascending timestamp order (stable) and returns
// it for chaining. Entries with zero timestamps keep their relative order at
// the front.
func (pl *PacketList) SortByTime() *PacketList {
	sort.SliceStable(pl.entries, func(i, j int) bool {
		return pl.entries[i].Time.Before(pl.entries[j].Time)
	})
	return pl
}
