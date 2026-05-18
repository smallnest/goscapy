package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// NewUDP creates a UDP header layer with sensible defaults.
// Defaults: len=8 (header only, no payload), checksum=0 (auto-computed during Build).
func NewUDP() *packet.Layer {
	return packet.NewLayer("UDP", []fields.Field{
		fields.NewShortField("sport", 0),   // source port
		fields.NewShortField("dport", 0),   // destination port
		fields.NewShortField("len", 8),     // length (header + payload), updated during Build
		fields.NewShortField("chksum", 0),  // auto-computed during Build
	})
}

// NewUDPWith creates a UDP header with the given source and destination ports.
func NewUDPWith(sport, dport uint16) *packet.Layer {
	l := NewUDP()
	l.Set("sport", sport)
	l.Set("dport", dport)
	return l
}
