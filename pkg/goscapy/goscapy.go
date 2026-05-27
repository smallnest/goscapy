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

