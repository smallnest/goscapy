// Package goscapy provides an idiomatic Go API for building and serializing
// network packets. It offers two complementary interfaces:
//
//  1. Builder API — fluent method chaining for type-safe, explicit packet construction.
//  2. Shortcut functions — one-liners for common protocol stacks with sensible defaults.
//
// # Builder API
//
//	pkt, _ := goscapy.NewEthernet().
//	    DstMAC("ff:ff:ff:ff:ff:ff").
//	    Over(goscapy.NewIP().DstIP("8.8.8.8")).
//	    Over(goscapy.NewICMP().Type(8)).
//	    Build()
//
// # Shortcut functions
//
//	pkt, _ := goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// LayerBuilder is implemented by all protocol builders.
// It exposes the underlying packet layer for stacking.
type LayerBuilder interface {
	Layer() *packet.Layer
}

// PacketBuilder wraps a Packet and provides chaining methods (Over, Build).
type PacketBuilder struct {
	pkt *packet.Packet
}

// Over stacks another layer on top and returns the PacketBuilder for chaining.
func (pb *PacketBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pb.pkt.Push(upper.Layer())
	return pb
}

// Build serializes the full packet into wire-format bytes.
func (pb *PacketBuilder) Build() ([]byte, error) {
	return pb.pkt.Build()
}

// Packet returns the underlying Packet for advanced use.
func (pb *PacketBuilder) Packet() *packet.Packet {
	return pb.pkt
}

// ---- EthernetBuilder ----

// EthernetBuilder builds Ethernet frame layers.
type EthernetBuilder struct {
	layer *packet.Layer
}

// NewEthernet creates an Ethernet frame builder with default values.
func NewEthernet() *EthernetBuilder {
	return &EthernetBuilder{layer: layers.NewEthernet()}
}

func (b *EthernetBuilder) Layer() *packet.Layer { return b.layer }

// DstMAC sets the destination MAC address (e.g. "ff:ff:ff:ff:ff:ff").
func (b *EthernetBuilder) DstMAC(mac string) *EthernetBuilder {
	b.layer.Set("dst", mac)
	return b
}

// SrcMAC sets the source MAC address.
func (b *EthernetBuilder) SrcMAC(mac string) *EthernetBuilder {
	b.layer.Set("src", mac)
	return b
}

// Type sets the EtherType field (e.g. layers.EtherTypeIPv4).
func (b *EthernetBuilder) Type(t uint16) *EthernetBuilder {
	b.layer.Set("type", t)
	return b
}

// Over stacks an upper layer on top of this Ethernet layer and returns a PacketBuilder.
func (b *EthernetBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- IPBuilder ----

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

// ---- ICMPBuilder ----

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

// ---- TCPBuilder ----

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

// ---- UDPBuilder ----

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

// ---- ARPBuilder ----

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
