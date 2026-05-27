package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers/erspan"
	"github.com/smallnest/goscapy/pkg/layers/gre"
	"github.com/smallnest/goscapy/pkg/layers/vxlan"
	"github.com/smallnest/goscapy/pkg/packet"
)

// VXLANBuilder builds VXLAN encapsulation layers.
type VXLANBuilder struct {
	layer *packet.Layer
}

// NewVXLAN creates a VXLAN builder with default I flag set.
func NewVXLAN() *VXLANBuilder {
	return &VXLANBuilder{layer: vxlan.NewVXLANLayer()}
}

func (b *VXLANBuilder) Layer() *packet.Layer { return b.layer }

// VNI sets the VXLAN Network Identifier (24 bits, 0-16777215).
func (b *VXLANBuilder) VNI(vni uint32) *VXLANBuilder {
	b.layer.Set("vni", vni&0xFFFFFF)
	return b
}

// Flags sets the VXLAN flags byte.
func (b *VXLANBuilder) Flags(flags uint8) *VXLANBuilder {
	b.layer.Set("flags", flags)
	return b
}

// Over stacks an upper layer on top of this VXLAN layer and returns a PacketBuilder.
func (b *VXLANBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// GREBuilder builds GRE tunnel encapsulation layers.
type GREBuilder struct {
	layer *packet.Layer
}

// NewGRE creates a GRE builder with default ProtocolType=0x0800 (IP).
func NewGRE() *GREBuilder {
	return &GREBuilder{layer: gre.NewGRELayer()}
}

func (b *GREBuilder) Layer() *packet.Layer { return b.layer }

// ProtocolType sets the GRE Protocol Type (e.g. 0x0800 for IP, 0x6558 for Ethernet).
func (b *GREBuilder) ProtocolType(pt uint16) *GREBuilder {
	b.layer.Set("proto", pt)
	return b
}

// Key sets the GRE Key field and enables the K flag.
func (b *GREBuilder) Key(k uint32) *GREBuilder {
	b.layer.Set("key", k)
	flags, _ := b.layer.Get("flagsver")
	b.layer.Set("flagsver", flags.(uint16)|gre.FlagK)
	return b
}

// Seq sets the GRE Sequence Number and enables the S flag.
func (b *GREBuilder) Seq(s uint32) *GREBuilder {
	b.layer.Set("seq", s)
	flags, _ := b.layer.Get("flagsver")
	b.layer.Set("flagsver", flags.(uint16)|gre.FlagS)
	return b
}

// SetChecksum sets the GRE Checksum and enables the C flag.
func (b *GREBuilder) SetChecksum(csum uint16) *GREBuilder {
	b.layer.Set("chksum", csum)
	b.layer.Set("reserved1", uint16(0))
	flags, _ := b.layer.Get("flagsver")
	b.layer.Set("flagsver", flags.(uint16)|gre.FlagC)
	return b
}

// Over stacks an upper layer on top of this GRE layer and returns a PacketBuilder.
func (b *GREBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ERSPANBuilder builds ERSPAN v3 encapsulation layers.
type ERSPANBuilder struct {
	layer *packet.Layer
}

// NewERSPAN creates an ERSPAN v3 builder with default values.
func NewERSPAN() *ERSPANBuilder {
	return &ERSPANBuilder{layer: erspan.NewERSPAN()}
}

func (b *ERSPANBuilder) Layer() *packet.Layer { return b.layer }

// FromERSPAN sets the layer fields from an ERSPAN struct.
func (b *ERSPANBuilder) FromERSPAN(e *erspan.ERSPAN) *ERSPANBuilder {
	data, err := e.Serialize()
	if err != nil {
		return b
	}
	// Set individual fields from serialized data
	b.layer.Set("ver_vlan_hi", data[0])
	b.layer.Set("vlan_lo_cos_bso_en", uint16(data[1])<<8|uint16(data[2]))
	b.layer.Set("session_id_flags", data[3])
	b.layer.Set("reserved", data[4])
	ts := uint32(data[5])<<24 | uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	b.layer.Set("timestamp", ts)
	b.layer.Set("sgt_p_ft", uint16(data[9])<<8|uint16(data[10]))
	b.layer.Set("offset_hw", uint16(data[11])<<8)
	return b
}
