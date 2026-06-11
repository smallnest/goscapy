package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- SCTP ----

// SCTPBuilder builds SCTP common header layers.
type SCTPBuilder struct {
	layer *packet.Layer
}

// NewSCTP creates an SCTP common header builder. The CRC32c checksum is
// computed automatically during Build.
func NewSCTP() *SCTPBuilder {
	return &SCTPBuilder{layer: layers.NewSCTP()}
}

func (b *SCTPBuilder) Layer() *packet.Layer { return b.layer }

// SrcPort sets the source port.
func (b *SCTPBuilder) SrcPort(p uint16) *SCTPBuilder {
	_ = b.layer.Set("sport", p)
	return b
}

// DstPort sets the destination port.
func (b *SCTPBuilder) DstPort(p uint16) *SCTPBuilder {
	_ = b.layer.Set("dport", p)
	return b
}

// VTag sets the verification tag.
func (b *SCTPBuilder) VTag(tag uint32) *SCTPBuilder {
	_ = b.layer.Set("vtag", tag)
	return b
}

// Over stacks an upper layer (chunks) on top of this SCTP layer.
func (b *SCTPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- IGMP ----

// IGMPBuilder builds IGMPv2 message layers.
type IGMPBuilder struct {
	layer *packet.Layer
}

// NewIGMP creates an IGMPv2 message builder. The checksum is computed
// automatically during Build.
func NewIGMP() *IGMPBuilder {
	return &IGMPBuilder{layer: layers.NewIGMP()}
}

func (b *IGMPBuilder) Layer() *packet.Layer { return b.layer }

// Type sets the IGMP message type (e.g. layers.IGMPMembershipQuery).
func (b *IGMPBuilder) Type(t uint8) *IGMPBuilder {
	_ = b.layer.Set("type", t)
	return b
}

// MaxRespTime sets the maximum response time (1/10 second units).
func (b *IGMPBuilder) MaxRespTime(t uint8) *IGMPBuilder {
	_ = b.layer.Set("mrtime", t)
	return b
}

// Group sets the group address.
func (b *IGMPBuilder) Group(addr string) *IGMPBuilder {
	_ = b.layer.Set("gaddr", addr)
	return b
}

// Over stacks an upper layer on top of this IGMP layer.
func (b *IGMPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- MPLS ----

// MPLSBuilder builds MPLS label stack entry layers.
type MPLSBuilder struct {
	layer *packet.Layer
}

// NewMPLS creates an MPLS label stack entry builder. By default it is the
// bottom-of-stack entry (s=1) with TTL 64.
func NewMPLS() *MPLSBuilder {
	return &MPLSBuilder{layer: layers.NewMPLS()}
}

func (b *MPLSBuilder) Layer() *packet.Layer { return b.layer }

// Label sets the 20-bit label, preserving the other LSE fields.
func (b *MPLSBuilder) Label(label uint32) *MPLSBuilder {
	v, _ := b.layer.Get("lse")
	lse := v.(uint32)
	_ = b.layer.Set("lse", layers.MakeMPLSLSE(label, layers.MPLSExp(lse), layers.MPLSBottom(lse), layers.MPLSTTL(lse)))
	return b
}

// Exp sets the 3-bit traffic class (EXP) field, preserving other LSE fields.
func (b *MPLSBuilder) Exp(exp uint8) *MPLSBuilder {
	v, _ := b.layer.Get("lse")
	lse := v.(uint32)
	_ = b.layer.Set("lse", layers.MakeMPLSLSE(layers.MPLSLabel(lse), exp, layers.MPLSBottom(lse), layers.MPLSTTL(lse)))
	return b
}

// Bottom sets the bottom-of-stack flag, preserving other LSE fields.
func (b *MPLSBuilder) Bottom(bottom bool) *MPLSBuilder {
	v, _ := b.layer.Get("lse")
	lse := v.(uint32)
	_ = b.layer.Set("lse", layers.MakeMPLSLSE(layers.MPLSLabel(lse), layers.MPLSExp(lse), bottom, layers.MPLSTTL(lse)))
	return b
}

// TTL sets the 8-bit TTL, preserving other LSE fields.
func (b *MPLSBuilder) TTL(ttl uint8) *MPLSBuilder {
	v, _ := b.layer.Get("lse")
	lse := v.(uint32)
	_ = b.layer.Set("lse", layers.MakeMPLSLSE(layers.MPLSLabel(lse), layers.MPLSExp(lse), layers.MPLSBottom(lse), ttl))
	return b
}

// Over stacks an upper layer on top of this MPLS layer.
func (b *MPLSBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- PPPoE / PPP ----

// PPPoEBuilder builds PPPoE header layers.
type PPPoEBuilder struct {
	layer *packet.Layer
}

// NewPPPoE creates a PPPoE header builder (session stage by default). The
// payload length is computed automatically during Build.
func NewPPPoE() *PPPoEBuilder {
	return &PPPoEBuilder{layer: layers.NewPPPoE()}
}

func (b *PPPoEBuilder) Layer() *packet.Layer { return b.layer }

// Code sets the PPPoE code (e.g. layers.PPPoECodePADI).
func (b *PPPoEBuilder) Code(c uint8) *PPPoEBuilder {
	_ = b.layer.Set("code", c)
	return b
}

// SessionID sets the PPPoE session identifier.
func (b *PPPoEBuilder) SessionID(id uint16) *PPPoEBuilder {
	_ = b.layer.Set("session_id", id)
	return b
}

// Over stacks an upper layer on top of this PPPoE layer.
func (b *PPPoEBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// PPPBuilder builds PPP header layers (used inside a PPPoE session).
type PPPBuilder struct {
	layer *packet.Layer
}

// NewPPP creates a PPP header builder (default protocol IPv4).
func NewPPP() *PPPBuilder {
	return &PPPBuilder{layer: layers.NewPPP()}
}

func (b *PPPBuilder) Layer() *packet.Layer { return b.layer }

// Proto sets the PPP protocol field (e.g. layers.PPPProtoIPv4).
func (b *PPPBuilder) Proto(p uint16) *PPPBuilder {
	_ = b.layer.Set("proto", p)
	return b
}

// Over stacks an upper layer on top of this PPP layer.
func (b *PPPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
