package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers/bt"
	"github.com/smallnest/goscapy/pkg/layers/dot11"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Dot11Builder builds IEEE 802.11 WiFi frame layers.
type Dot11Builder struct {
	layer *packet.Layer
}

// NewDot11 creates an 802.11 frame builder.
func NewDot11() *Dot11Builder {
	return &Dot11Builder{layer: dot11.NewDot11()}
}

func (b *Dot11Builder) Layer() *packet.Layer { return b.layer }

// FC sets the Frame Control bytes directly.
func (b *Dot11Builder) FC(fc0, fc1 uint8) *Dot11Builder {
	b.layer.Set("fc0", fc0)
	b.layer.Set("fc1", fc1)
	return b
}

// TypeSubtype sets frame type and subtype via helper.
func (b *Dot11Builder) TypeSubtype(ftype, subtype, flags uint8) *Dot11Builder {
	fc := dot11.SetFC(ftype, subtype, flags)
	b.layer.Set("fc0", fc[0])
	b.layer.Set("fc1", fc[1])
	return b
}

// Addr1 sets the receiver address (addr1).
func (b *Dot11Builder) Addr1(mac string) *Dot11Builder {
	b.layer.Set("addr1", mac)
	return b
}

// Addr2 sets the transmitter address (addr2).
func (b *Dot11Builder) Addr2(mac string) *Dot11Builder {
	b.layer.Set("addr2", mac)
	return b
}

// Addr3 sets the BSSID/filter address (addr3).
func (b *Dot11Builder) Addr3(mac string) *Dot11Builder {
	b.layer.Set("addr3", mac)
	return b
}

// SC sets the sequence control field.
func (b *Dot11Builder) SC(sc uint16) *Dot11Builder {
	b.layer.Set("sc", sc)
	return b
}

// Duration sets the duration/ID field.
func (b *Dot11Builder) Duration(d uint16) *Dot11Builder {
	b.layer.Set("duration", d)
	return b
}

// Over stacks an upper layer on top of this Dot11 layer.
func (b *Dot11Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// RadioTapBuilder builds RadioTap header layers.
type RadioTapBuilder struct {
	layer *packet.Layer
}

// NewRadioTap creates a RadioTap header builder.
func NewRadioTap() *RadioTapBuilder {
	return &RadioTapBuilder{layer: dot11.NewRadioTap()}
}

func (b *RadioTapBuilder) Layer() *packet.Layer { return b.layer }

// Present sets the presence bitmap.
func (b *RadioTapBuilder) Present(flags uint32) *RadioTapBuilder {
	b.layer.Set("present", flags)
	return b
}

// Data sets the variable-length field data.
func (b *RadioTapBuilder) Data(data []byte) *RadioTapBuilder {
	b.layer.Set("data", data)
	return b
}

// Over stacks an upper layer on top of this RadioTap layer.
func (b *RadioTapBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// HCIBuilder builds Bluetooth HCI layers.
type HCIBuilder struct {
	layer *packet.Layer
}

// NewHCI creates an HCI layer builder.
func NewHCI() *HCIBuilder {
	return &HCIBuilder{layer: bt.NewHCI()}
}

func (b *HCIBuilder) Layer() *packet.Layer { return b.layer }

// Type sets the HCI packet type.
func (b *HCIBuilder) Type(t uint8) *HCIBuilder {
	b.layer.Set("type", t)
	return b
}

// Opcode sets the HCI command opcode or event code.
func (b *HCIBuilder) Opcode(op uint16) *HCIBuilder {
	b.layer.Set("opcode", op)
	return b
}

// Params sets the HCI parameters.
func (b *HCIBuilder) Params(data []byte) *HCIBuilder {
	b.layer.Set("params", data)
	b.layer.Set("param_len", uint8(len(data)))
	return b
}

// Over stacks an upper layer on top of this HCI layer.
func (b *HCIBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// L2CAPBuilder builds Bluetooth L2CAP layers.
type L2CAPBuilder struct {
	layer *packet.Layer
}

// NewL2CAP creates an L2CAP layer builder.
func NewL2CAP() *L2CAPBuilder {
	return &L2CAPBuilder{layer: bt.NewL2CAP()}
}

func (b *L2CAPBuilder) Layer() *packet.Layer { return b.layer }

// CID sets the L2CAP channel ID.
func (b *L2CAPBuilder) CID(cid uint16) *L2CAPBuilder {
	b.layer.Set("cid", cid)
	return b
}

// Data sets the L2CAP payload.
func (b *L2CAPBuilder) Data(data []byte) *L2CAPBuilder {
	b.layer.Set("data", data)
	b.layer.Set("length", uint16(len(data)))
	return b
}

// Over stacks an upper layer on top of this L2CAP layer.
func (b *L2CAPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ATTBuilder builds BLE ATT layers.
type ATTBuilder struct {
	layer *packet.Layer
}

// NewATT creates a BLE ATT layer builder.
func NewATT() *ATTBuilder {
	return &ATTBuilder{layer: bt.NewATT()}
}

func (b *ATTBuilder) Layer() *packet.Layer { return b.layer }

// Opcode sets the ATT opcode.
func (b *ATTBuilder) Opcode(op uint8) *ATTBuilder {
	b.layer.Set("opcode", op)
	return b
}

// Params sets the ATT parameters.
func (b *ATTBuilder) Params(data []byte) *ATTBuilder {
	b.layer.Set("params", data)
	return b
}

// Over stacks an upper layer on top of this ATT layer.
func (b *ATTBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
