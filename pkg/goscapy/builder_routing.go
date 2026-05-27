package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers/bgp"
	"github.com/smallnest/goscapy/pkg/layers/lldp"
	"github.com/smallnest/goscapy/pkg/layers/ospf"
	"github.com/smallnest/goscapy/pkg/packet"
)

// LLDPBuilder builds LLDP frame layers.
type LLDPBuilder struct {
	layer *packet.Layer
}

// NewLLDP creates an LLDP builder with default TLV data.
func NewLLDP() *LLDPBuilder {
	return &LLDPBuilder{layer: lldp.NewLLDP()}
}

func (b *LLDPBuilder) Layer() *packet.Layer { return b.layer }

// TLVData sets the raw TLV data bytes.
func (b *LLDPBuilder) TLVData(data []byte) *LLDPBuilder {
	b.layer.Set("tlv_data", data)
	return b
}

// LLDPDU sets the TLV data from a structured LLDPDU.
func (b *LLDPBuilder) LLDPDU(du *lldp.LLDPDU) *LLDPBuilder {
	data, err := du.Serialize()
	if err != nil {
		return b
	}
	b.layer.Set("tlv_data", data)
	return b
}

// OSPFBuilder builds OSPFv2 header layers.
type OSPFBuilder struct {
	layer *packet.Layer
}

// NewOSPF creates an OSPFv2 header builder with default values.
func NewOSPF() *OSPFBuilder {
	return &OSPFBuilder{layer: ospf.NewOSPF()}
}

func (b *OSPFBuilder) Layer() *packet.Layer { return b.layer }

// RouterID sets the OSPF Router ID.
func (b *OSPFBuilder) RouterID(ip string) *OSPFBuilder {
	b.layer.Set("router_id", ip)
	return b
}

// AreaID sets the OSPF Area ID.
func (b *OSPFBuilder) AreaID(ip string) *OSPFBuilder {
	b.layer.Set("area_id", ip)
	return b
}

// Type sets the OSPF message type (Hello, DBD, LSR, LSU, LSAck).
func (b *OSPFBuilder) Type(t uint8) *OSPFBuilder {
	b.layer.Set("type", t)
	return b
}

// Over stacks an upper layer on top of this OSPF layer and returns a PacketBuilder.
func (b *OSPFBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// BGPBuilder builds BGP common header layers.
type BGPBuilder struct {
	layer *packet.Layer
}

// NewBGP creates a BGP common header builder with default values.
func NewBGP() *BGPBuilder {
	return &BGPBuilder{layer: bgp.NewBGP()}
}

func (b *BGPBuilder) Layer() *packet.Layer { return b.layer }

// Type sets the BGP message type (OPEN, UPDATE, NOTIFICATION, KEEPALIVE).
func (b *BGPBuilder) Type(t uint8) *BGPBuilder {
	b.layer.Set("type", t)
	return b
}

// Over stacks an upper layer on top of this BGP layer and returns a PacketBuilder.
func (b *BGPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
