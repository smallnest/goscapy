package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers/dot1q"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Dot1QBuilder builds 802.1Q VLAN tag layers.
type Dot1QBuilder struct {
	layer *packet.Layer
}

// NewDot1Q creates a Dot1Q VLAN tag builder with default 802.1Q TPID.
func NewDot1Q() *Dot1QBuilder {
	return &Dot1QBuilder{layer: dot1q.NewDot1QLayer()}
}

func (b *Dot1QBuilder) Layer() *packet.Layer { return b.layer }

// VID sets the VLAN ID (12 bits, 0-4095).
func (b *Dot1QBuilder) VID(vid uint16) *Dot1QBuilder {
	tci, _ := b.layer.Get("tci")
	val := (tci.(uint16) & 0xF000) | (vid & 0x0FFF)
	b.layer.Set("tci", val)
	return b
}

// PCP sets the Priority Code Point (3 bits, 0-7).
func (b *Dot1QBuilder) PCP(pcp uint8) *Dot1QBuilder {
	tci, _ := b.layer.Get("tci")
	val := (tci.(uint16) & 0x1FFF) | (uint16(pcp&0x7) << 13)
	b.layer.Set("tci", val)
	return b
}

// DEI sets the Drop Eligible Indicator.
func (b *Dot1QBuilder) DEI(dei bool) *Dot1QBuilder {
	tci, _ := b.layer.Get("tci")
	val := tci.(uint16)
	if dei {
		val |= 0x1000
	} else {
		val &^= 0x1000
	}
	b.layer.Set("tci", val)
	return b
}

// Type sets the inner EtherType.
func (b *Dot1QBuilder) Type(etype uint16) *Dot1QBuilder {
	b.layer.Set("type", etype)
	return b
}

// TPID sets the Tag Protocol Identifier (default 0x8100, or 0x88A8 for QinQ).
func (b *Dot1QBuilder) TPID(tpid uint16) *Dot1QBuilder {
	b.layer.Set("tpid", tpid)
	return b
}

// Over stacks an upper layer on top of this Dot1Q layer and returns a PacketBuilder.
func (b *Dot1QBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
