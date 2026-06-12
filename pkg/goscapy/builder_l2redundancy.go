package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- VRRP ----

// VRRPBuilder builds VRRPv2 advertisement layers.
type VRRPBuilder struct {
	layer *packet.Layer
}

// NewVRRP creates a VRRPv2 advertisement builder. The checksum is computed
// automatically during Build.
func NewVRRP() *VRRPBuilder {
	return &VRRPBuilder{layer: layers.NewVRRP()}
}

func (b *VRRPBuilder) Layer() *packet.Layer { return b.layer }

// VRID sets the virtual router identifier.
func (b *VRRPBuilder) VRID(vrid uint8) *VRRPBuilder {
	_ = b.layer.Set("vrid", vrid)
	return b
}

// Priority sets the advertising router's priority (255 = address owner).
func (b *VRRPBuilder) Priority(p uint8) *VRRPBuilder {
	_ = b.layer.Set("priority", p)
	return b
}

// VirtualIP sets a single virtual IP address and ipcount=1.
func (b *VRRPBuilder) VirtualIP(ip string) *VRRPBuilder {
	_ = b.layer.Set("ipcount", uint8(1))
	_ = b.layer.Set("addrs", layers.IPv4Bytes(ip))
	return b
}

// Over stacks an upper layer on top of this VRRP layer.
func (b *VRRPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- HSRP ----

// HSRPBuilder builds HSRPv1 message layers.
type HSRPBuilder struct {
	layer *packet.Layer
}

// NewHSRP creates an HSRP message builder (Hello by default, over UDP 1985).
func NewHSRP() *HSRPBuilder {
	return &HSRPBuilder{layer: layers.NewHSRP()}
}

func (b *HSRPBuilder) Layer() *packet.Layer { return b.layer }

// Opcode sets the HSRP opcode (e.g. layers.HSRPOpHello).
func (b *HSRPBuilder) Opcode(op uint8) *HSRPBuilder {
	_ = b.layer.Set("opcode", op)
	return b
}

// State sets the HSRP state (e.g. layers.HSRPStateActive).
func (b *HSRPBuilder) State(s uint8) *HSRPBuilder {
	_ = b.layer.Set("state", s)
	return b
}

// Group sets the standby group number.
func (b *HSRPBuilder) Group(g uint8) *HSRPBuilder {
	_ = b.layer.Set("group", g)
	return b
}

// Priority sets the router priority.
func (b *HSRPBuilder) Priority(p uint8) *HSRPBuilder {
	_ = b.layer.Set("priority", p)
	return b
}

// VirtualIP sets the virtual IP address.
func (b *HSRPBuilder) VirtualIP(ip string) *HSRPBuilder {
	_ = b.layer.Set("virtualip", ip)
	return b
}

// Over stacks an upper layer on top of this HSRP layer.
func (b *HSRPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- STP ----

// STPBuilder builds Spanning Tree Protocol BPDU layers.
type STPBuilder struct {
	layer *packet.Layer
}

// NewSTP creates an STP Configuration BPDU builder.
func NewSTP() *STPBuilder {
	return &STPBuilder{layer: layers.NewSTP()}
}

func (b *STPBuilder) Layer() *packet.Layer { return b.layer }

// BPDUType sets the BPDU type (e.g. layers.STPBPDUConfig).
func (b *STPBuilder) BPDUType(t uint8) *STPBuilder {
	_ = b.layer.Set("bpdutype", t)
	return b
}

// RootID sets the 8-byte root bridge identifier.
func (b *STPBuilder) RootID(id []byte) *STPBuilder {
	_ = b.layer.Set("rootid", id)
	return b
}

// BridgeID sets the 8-byte transmitting bridge identifier.
func (b *STPBuilder) BridgeID(id []byte) *STPBuilder {
	_ = b.layer.Set("bridgeid", id)
	return b
}

// Over stacks an upper layer on top of this STP layer.
func (b *STPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- EAPOL / EAP ----

// EAPOLBuilder builds IEEE 802.1X EAPOL layers.
type EAPOLBuilder struct {
	layer *packet.Layer
}

// NewEAPOL creates an EAPOL header builder (EAP-Packet by default). The body
// length is computed automatically during Build.
func NewEAPOL() *EAPOLBuilder {
	return &EAPOLBuilder{layer: layers.NewEAPOL()}
}

func (b *EAPOLBuilder) Layer() *packet.Layer { return b.layer }

// Type sets the EAPOL packet type (e.g. layers.EAPOLTypeStart).
func (b *EAPOLBuilder) Type(t uint8) *EAPOLBuilder {
	_ = b.layer.Set("type", t)
	return b
}

// Over stacks an upper layer (e.g. EAP) on top of this EAPOL layer.
func (b *EAPOLBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// EAPBuilder builds EAP packet layers (RFC 3748).
type EAPBuilder struct {
	layer *packet.Layer
}

// NewEAP creates an EAP packet builder. The length is computed automatically
// during Build.
func NewEAP() *EAPBuilder {
	return &EAPBuilder{layer: layers.NewEAP()}
}

func (b *EAPBuilder) Layer() *packet.Layer { return b.layer }

// Code sets the EAP code (e.g. layers.EAPCodeRequest).
func (b *EAPBuilder) Code(c uint8) *EAPBuilder {
	_ = b.layer.Set("code", c)
	return b
}

// ID sets the EAP identifier used to match requests and responses.
func (b *EAPBuilder) ID(id uint8) *EAPBuilder {
	_ = b.layer.Set("id", id)
	return b
}

// Data sets the EAP body (type byte followed by type data).
func (b *EAPBuilder) Data(data []byte) *EAPBuilder {
	_ = b.layer.Set("data", data)
	return b
}

// Over stacks an upper layer on top of this EAP layer.
func (b *EAPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
