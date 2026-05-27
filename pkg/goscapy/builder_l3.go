package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IPBuilder builds IPv4 header layers.
type IPBuilder struct {
	layer *packet.Layer
}

// NewIP creates an IPv4 header builder with sensible defaults (v4, ttl=64).
func NewIP() *IPBuilder {
	return &IPBuilder{layer: layers.NewIP()}
}

func (b *IPBuilder) Layer() *packet.Layer { return b.layer }

// SrcIP sets the source IP address (e.g. "192.168.1.1").
func (b *IPBuilder) SrcIP(ip string) *IPBuilder {
	b.layer.Set("src", ip)
	return b
}

// DstIP sets the destination IP address.
func (b *IPBuilder) DstIP(ip string) *IPBuilder {
	b.layer.Set("dst", ip)
	return b
}

// TTL sets the time-to-live field.
func (b *IPBuilder) TTL(ttl uint8) *IPBuilder {
	b.layer.Set("ttl", ttl)
	return b
}

// Proto sets the protocol field (e.g. layers.IPProtoTCP).
func (b *IPBuilder) Proto(p uint8) *IPBuilder {
	b.layer.Set("proto", p)
	return b
}

// ID sets the identification field.
func (b *IPBuilder) ID(id uint16) *IPBuilder {
	b.layer.Set("id", id)
	return b
}

// Over stacks an upper layer on top of this IP layer and returns a PacketBuilder.
func (b *IPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ICMPBuilder builds ICMP message layers.
type ICMPBuilder struct {
	layer *packet.Layer
}

// NewICMP creates an ICMP message builder (default: Echo Request, type=8).
func NewICMP() *ICMPBuilder {
	return &ICMPBuilder{layer: layers.NewICMP()}
}

func (b *ICMPBuilder) Layer() *packet.Layer { return b.layer }

// Type sets the ICMP type field.
func (b *ICMPBuilder) Type(t uint8) *ICMPBuilder {
	b.layer.Set("type", t)
	return b
}

// Code sets the ICMP code field.
func (b *ICMPBuilder) Code(c uint8) *ICMPBuilder {
	b.layer.Set("code", c)
	return b
}

// ID sets the ICMP identifier field.
func (b *ICMPBuilder) ID(id uint16) *ICMPBuilder {
	b.layer.Set("id", id)
	return b
}

// Seq sets the ICMP sequence number field.
func (b *ICMPBuilder) Seq(seq uint16) *ICMPBuilder {
	b.layer.Set("seq", seq)
	return b
}

// ARPBuilder builds ARP message layers.
type ARPBuilder struct {
	layer *packet.Layer
}

// NewARP creates an ARP message builder with sensible defaults for Ethernet+IPv4.
func NewARP() *ARPBuilder {
	return &ARPBuilder{layer: layers.NewARP()}
}

func (b *ARPBuilder) Layer() *packet.Layer { return b.layer }

// Op sets the ARP operation (layers.ARPWhoHas or layers.ARPIsAt).
func (b *ARPBuilder) Op(op uint16) *ARPBuilder {
	b.layer.Set("op", op)
	return b
}

// SrcMAC sets the sender hardware address.
func (b *ARPBuilder) SrcMAC(mac string) *ARPBuilder {
	b.layer.Set("hwsrc", mac)
	return b
}

// SrcIP sets the sender protocol address.
func (b *ARPBuilder) SrcIP(ip string) *ARPBuilder {
	b.layer.Set("psrc", ip)
	return b
}

// DstMAC sets the target hardware address.
func (b *ARPBuilder) DstMAC(mac string) *ARPBuilder {
	b.layer.Set("hwdst", mac)
	return b
}

// DstIP sets the target protocol address.
func (b *ARPBuilder) DstIP(ip string) *ARPBuilder {
	b.layer.Set("pdst", ip)
	return b
}

// Over stacks an upper layer on top of this ARP layer and returns a PacketBuilder.
func (b *ARPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// IPv6Builder builds IPv6 header layers.
type IPv6Builder struct {
	layer *packet.Layer
}

// NewIPv6 creates an IPv6 header builder with defaults (v6, hop limit=64).
func NewIPv6() *IPv6Builder {
	return &IPv6Builder{layer: layers.NewIPv6()}
}

func (b *IPv6Builder) Layer() *packet.Layer { return b.layer }

// SrcIP sets the source IPv6 address.
func (b *IPv6Builder) SrcIP(ip string) *IPv6Builder {
	b.layer.Set("src", ip)
	return b
}

// DstIP sets the destination IPv6 address.
func (b *IPv6Builder) DstIP(ip string) *IPv6Builder {
	b.layer.Set("dst", ip)
	return b
}

// NH sets the next header field.
func (b *IPv6Builder) NH(nh uint8) *IPv6Builder {
	b.layer.Set("nh", nh)
	return b
}

// HLim sets the hop limit field.
func (b *IPv6Builder) HLim(hlim uint8) *IPv6Builder {
	b.layer.Set("hlim", hlim)
	return b
}

// TC sets the traffic class field (updates the combined ver_tc_fl field).
func (b *IPv6Builder) TC(tc uint8) *IPv6Builder {
	v, _ := b.layer.Get("ver_tc_fl")
	fl := layers.IPv6FlowLabel(v.(uint32))
	b.layer.Set("ver_tc_fl", layers.MakeIPv6VerTCFL(tc, fl))
	return b
}

// FL sets the flow label field (updates the combined ver_tc_fl field).
func (b *IPv6Builder) FL(fl uint32) *IPv6Builder {
	v, _ := b.layer.Get("ver_tc_fl")
	tc := layers.IPv6TrafficClass(v.(uint32))
	b.layer.Set("ver_tc_fl", layers.MakeIPv6VerTCFL(tc, fl))
	return b
}

// Over stacks an upper layer on top of this IPv6 layer and returns a PacketBuilder.
func (b *IPv6Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ICMPv6Builder builds ICMPv6 base header layers.
type ICMPv6Builder struct {
	layer *packet.Layer
}

// NewICMPv6 creates an ICMPv6 base header builder (default: Echo Request, type=128).
func NewICMPv6() *ICMPv6Builder {
	return &ICMPv6Builder{layer: layers.NewICMPv6()}
}

func (b *ICMPv6Builder) Layer() *packet.Layer { return b.layer }

// Type sets the ICMPv6 type field.
func (b *ICMPv6Builder) Type(t uint8) *ICMPv6Builder {
	b.layer.Set("type", t)
	return b
}

// Code sets the ICMPv6 code field.
func (b *ICMPv6Builder) Code(c uint8) *ICMPv6Builder {
	b.layer.Set("code", c)
	return b
}

// Over stacks an upper layer on top of this ICMPv6 layer and returns a PacketBuilder.
func (b *ICMPv6Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
