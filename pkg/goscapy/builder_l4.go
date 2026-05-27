package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// TCPBuilder builds TCP header layers.
type TCPBuilder struct {
	layer *packet.Layer
}

// NewTCP creates a TCP header builder with sensible defaults.
func NewTCP() *TCPBuilder {
	return &TCPBuilder{layer: layers.NewTCP()}
}

func (b *TCPBuilder) Layer() *packet.Layer { return b.layer }

// SrcPort sets the source port.
func (b *TCPBuilder) SrcPort(p uint16) *TCPBuilder {
	b.layer.Set("sport", p)
	return b
}

// DstPort sets the destination port.
func (b *TCPBuilder) DstPort(p uint16) *TCPBuilder {
	b.layer.Set("dport", p)
	return b
}

// Flags sets the TCP flags byte (e.g. layers.TCPSyn | layers.TCPAck).
func (b *TCPBuilder) Flags(f uint8) *TCPBuilder {
	b.layer.Set("flags", f)
	return b
}

// Seq sets the sequence number.
func (b *TCPBuilder) Seq(s uint32) *TCPBuilder {
	b.layer.Set("seq", s)
	return b
}

// Ack sets the acknowledgment number.
func (b *TCPBuilder) Ack(a uint32) *TCPBuilder {
	b.layer.Set("ack", a)
	return b
}

// Window sets the window size.
func (b *TCPBuilder) Window(w uint16) *TCPBuilder {
	b.layer.Set("window", w)
	return b
}

// Over stacks an upper layer on top of this TCP layer and returns a PacketBuilder.
func (b *TCPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// UDPBuilder builds UDP header layers.
type UDPBuilder struct {
	layer *packet.Layer
}

// NewUDP creates a UDP header builder with sensible defaults.
func NewUDP() *UDPBuilder {
	return &UDPBuilder{layer: layers.NewUDP()}
}

func (b *UDPBuilder) Layer() *packet.Layer { return b.layer }

// SrcPort sets the source port.
func (b *UDPBuilder) SrcPort(p uint16) *UDPBuilder {
	b.layer.Set("sport", p)
	return b
}

// DstPort sets the destination port.
func (b *UDPBuilder) DstPort(p uint16) *UDPBuilder {
	b.layer.Set("dport", p)
	return b
}

// Over stacks an upper layer on top of this UDP layer and returns a PacketBuilder.
func (b *UDPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
