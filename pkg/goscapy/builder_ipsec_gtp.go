package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- ESP (IPsec) ----

// ESPBuilder builds IPsec Encapsulating Security Payload headers.
type ESPBuilder struct {
	layer *packet.Layer
}

// NewESP creates an ESP header builder. The encrypted payload is treated as
// opaque data (goscapy does not perform decryption).
func NewESP() *ESPBuilder {
	return &ESPBuilder{layer: layers.NewESP()}
}

func (b *ESPBuilder) Layer() *packet.Layer { return b.layer }

// SPI sets the Security Parameters Index.
func (b *ESPBuilder) SPI(spi uint32) *ESPBuilder {
	_ = b.layer.Set("spi", spi)
	return b
}

// Seq sets the sequence number.
func (b *ESPBuilder) Seq(seq uint32) *ESPBuilder {
	_ = b.layer.Set("seq", seq)
	return b
}

// Data sets the encrypted payload (plus ESP trailer and ICV).
func (b *ESPBuilder) Data(data []byte) *ESPBuilder {
	_ = b.layer.Set("data", data)
	return b
}

// Over stacks an upper layer on top of this ESP layer.
func (b *ESPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- AH (IPsec) ----

// AHBuilder builds IPsec Authentication Headers.
type AHBuilder struct {
	layer *packet.Layer
}

// NewAH creates an AH header builder. The payload-length field is computed
// from the ICV size during Build.
func NewAH() *AHBuilder {
	return &AHBuilder{layer: layers.NewAH()}
}

func (b *AHBuilder) Layer() *packet.Layer { return b.layer }

// NextHeader sets the protocol of the data AH protects (e.g. layers.IPProtoTCP).
func (b *AHBuilder) NextHeader(nh uint8) *AHBuilder {
	_ = b.layer.Set("nh", nh)
	return b
}

// SPI sets the Security Parameters Index.
func (b *AHBuilder) SPI(spi uint32) *AHBuilder {
	_ = b.layer.Set("spi", spi)
	return b
}

// Seq sets the sequence number.
func (b *AHBuilder) Seq(seq uint32) *AHBuilder {
	_ = b.layer.Set("seq", seq)
	return b
}

// ICV sets the integrity check value.
func (b *AHBuilder) ICV(icv []byte) *AHBuilder {
	_ = b.layer.Set("icv", icv)
	return b
}

// Over stacks an upper layer on top of this AH layer.
func (b *AHBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- GTP ----

// GTPBuilder builds GTPv1 (GTP-U) headers.
type GTPBuilder struct {
	layer *packet.Layer
}

// NewGTP creates a GTPv1 header builder (GTP-U G-PDU by default). The length
// field is computed from the payload during Build.
func NewGTP() *GTPBuilder {
	return &GTPBuilder{layer: layers.NewGTP()}
}

func (b *GTPBuilder) Layer() *packet.Layer { return b.layer }

// MessageType sets the GTP message type (e.g. layers.GTPMsgGPDU).
func (b *GTPBuilder) MessageType(mt uint8) *GTPBuilder {
	_ = b.layer.Set("msgtype", mt)
	return b
}

// TEID sets the Tunnel Endpoint Identifier.
func (b *GTPBuilder) TEID(teid uint32) *GTPBuilder {
	_ = b.layer.Set("teid", teid)
	return b
}

// Over stacks an upper layer (e.g. the inner IP packet) on top of this GTP layer.
func (b *GTPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
