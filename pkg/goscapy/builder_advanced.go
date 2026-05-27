package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers/netflow"
	"github.com/smallnest/goscapy/pkg/layers/quic"
	"github.com/smallnest/goscapy/pkg/layers/voip"
	"github.com/smallnest/goscapy/pkg/packet"
)

// QUICBuilder builds QUIC packet layers.
type QUICBuilder struct {
	layer *packet.Layer
}

// NewQUIC creates a QUIC Long Header builder with default values.
func NewQUIC() *QUICBuilder {
	return &QUICBuilder{layer: quic.NewQUICLongHeader()}
}

func (b *QUICBuilder) Layer() *packet.Layer { return b.layer }

// Version sets the QUIC version.
func (b *QUICBuilder) Version(v uint32) *QUICBuilder {
	b.layer.Set("version", v)
	return b
}

// DCID sets the Destination Connection ID.
func (b *QUICBuilder) DCID(cid []byte) *QUICBuilder {
	b.layer.Set("dcid", cid)
	return b
}

// SCID sets the Source Connection ID.
func (b *QUICBuilder) SCID(cid []byte) *QUICBuilder {
	b.layer.Set("scid", cid)
	return b
}

// Over stacks an upper layer on top of this QUIC layer and returns a PacketBuilder.
func (b *QUICBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// NetflowV5Builder builds Netflow V5 header layers.
type NetflowV5Builder struct {
	layer *packet.Layer
}

// NewNetflowV5 creates a Netflow V5 layer builder.
func NewNetflowV5() *NetflowV5Builder {
	return &NetflowV5Builder{layer: netflow.NewNetflowV5()}
}

func (b *NetflowV5Builder) Layer() *packet.Layer { return b.layer }

func (b *NetflowV5Builder) Count(n uint16) *NetflowV5Builder {
	b.layer.Set("count", n)
	return b
}

func (b *NetflowV5Builder) SysUptime(ms uint32) *NetflowV5Builder {
	b.layer.Set("sys_uptime", ms)
	return b
}

func (b *NetflowV5Builder) UnixSecs(s uint32) *NetflowV5Builder {
	b.layer.Set("unix_secs", s)
	return b
}

func (b *NetflowV5Builder) FlowSequence(seq uint32) *NetflowV5Builder {
	b.layer.Set("flow_sequence", seq)
	return b
}

func (b *NetflowV5Builder) Engine(typ, id uint8) *NetflowV5Builder {
	b.layer.Set("engine_type", typ)
	b.layer.Set("engine_id", id)
	return b
}

func (b *NetflowV5Builder) Sampling(interval uint16) *NetflowV5Builder {
	b.layer.Set("sampling_interval", interval)
	return b
}

func (b *NetflowV5Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// NetflowV9Builder builds Netflow V9 header layers.
type NetflowV9Builder struct {
	layer *packet.Layer
}

// NewNetflowV9 creates a Netflow V9 layer builder.
func NewNetflowV9() *NetflowV9Builder {
	return &NetflowV9Builder{layer: netflow.NewNetflowV9()}
}

func (b *NetflowV9Builder) Layer() *packet.Layer { return b.layer }

func (b *NetflowV9Builder) Count(n uint16) *NetflowV9Builder {
	b.layer.Set("count", n)
	return b
}

func (b *NetflowV9Builder) SysUptime(ms uint32) *NetflowV9Builder {
	b.layer.Set("sys_uptime", ms)
	return b
}

func (b *NetflowV9Builder) UnixSecs(s uint32) *NetflowV9Builder {
	b.layer.Set("unix_secs", s)
	return b
}

func (b *NetflowV9Builder) Sequence(seq uint32) *NetflowV9Builder {
	b.layer.Set("sequence", seq)
	return b
}

func (b *NetflowV9Builder) SourceID(id uint32) *NetflowV9Builder {
	b.layer.Set("source_id", id)
	return b
}

func (b *NetflowV9Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// IPFIXBuilder builds IPFIX message header layers.
type IPFIXBuilder struct {
	layer *packet.Layer
}

// NewIPFIX creates an IPFIX layer builder.
func NewIPFIX() *IPFIXBuilder {
	return &IPFIXBuilder{layer: netflow.NewIPFIX()}
}

func (b *IPFIXBuilder) Layer() *packet.Layer { return b.layer }

func (b *IPFIXBuilder) Length(n uint16) *IPFIXBuilder {
	b.layer.Set("length", n)
	return b
}

func (b *IPFIXBuilder) ExportTime(t uint32) *IPFIXBuilder {
	b.layer.Set("export_time", t)
	return b
}

func (b *IPFIXBuilder) Sequence(seq uint32) *IPFIXBuilder {
	b.layer.Set("sequence", seq)
	return b
}

func (b *IPFIXBuilder) ObservationDomainID(id uint32) *IPFIXBuilder {
	b.layer.Set("observation_domain_id", id)
	return b
}

func (b *IPFIXBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// --- RTP ---

// RTPBuilder constructs an RTP layer.
type RTPBuilder struct{ layer *packet.Layer }

func NewRTP() *RTPBuilder {
	return &RTPBuilder{layer: voip.NewRTP()}
}

func (b *RTPBuilder) Layer() *packet.Layer { return b.layer }

func (b *RTPBuilder) Version(v uint8) *RTPBuilder {
	b0, _ := b.layer.Get("byte0")
	b.layer.Set("byte0", (b0.(uint8)&0x3F)|(v<<6))
	return b
}

func (b *RTPBuilder) PayloadType(pt uint8) *RTPBuilder {
	b1, _ := b.layer.Get("byte1")
	b.layer.Set("byte1", (b1.(uint8)&0x80)|(pt&0x7F))
	return b
}

func (b *RTPBuilder) Marker(m bool) *RTPBuilder {
	b1, _ := b.layer.Get("byte1")
	if m {
		b.layer.Set("byte1", b1.(uint8)|0x80)
	} else {
		b.layer.Set("byte1", b1.(uint8)&0x7F)
	}
	return b
}

func (b *RTPBuilder) Seq(n uint16) *RTPBuilder {
	b.layer.Set("seq", n)
	return b
}

func (b *RTPBuilder) Timestamp(t uint32) *RTPBuilder {
	b.layer.Set("timestamp", t)
	return b
}

func (b *RTPBuilder) SSRC(s uint32) *RTPBuilder {
	b.layer.Set("ssrc", s)
	return b
}

func (b *RTPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// --- RTCP ---

// RTCPBuilder constructs an RTCP layer.
type RTCPBuilder struct{ layer *packet.Layer }

func NewRTCP() *RTCPBuilder {
	return &RTCPBuilder{layer: voip.NewRTCP()}
}

func (b *RTCPBuilder) Layer() *packet.Layer { return b.layer }

func (b *RTCPBuilder) Type(t uint8) *RTCPBuilder {
	b.layer.Set("type", t)
	return b
}

func (b *RTCPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// --- SIP ---

// SIPBuilder constructs a SIP layer.
type SIPBuilder struct{ layer *packet.Layer }

func NewSIP() *SIPBuilder {
	return &SIPBuilder{layer: voip.NewSIP()}
}

func (b *SIPBuilder) Layer() *packet.Layer { return b.layer }

func (b *SIPBuilder) Raw(text string) *SIPBuilder {
	b.layer.Set("raw", text)
	return b
}

func (b *SIPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
