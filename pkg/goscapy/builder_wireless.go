package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers/bt"
	"github.com/smallnest/goscapy/pkg/layers/dot11"
	"github.com/smallnest/goscapy/pkg/layers/lorawan"
	"github.com/smallnest/goscapy/pkg/layers/zigbee"
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
	_ = b.layer.Set("fc0", fc0)
	_ = b.layer.Set("fc1", fc1)
	return b
}

// TypeSubtype sets frame type and subtype via helper.
func (b *Dot11Builder) TypeSubtype(ftype, subtype, flags uint8) *Dot11Builder {
	fc := dot11.SetFC(ftype, subtype, flags)
	_ = b.layer.Set("fc0", fc[0])
	_ = b.layer.Set("fc1", fc[1])
	return b
}

// Addr1 sets the receiver address (addr1).
func (b *Dot11Builder) Addr1(mac string) *Dot11Builder {
	_ = b.layer.Set("addr1", mac)
	return b
}

// Addr2 sets the transmitter address (addr2).
func (b *Dot11Builder) Addr2(mac string) *Dot11Builder {
	_ = b.layer.Set("addr2", mac)
	return b
}

// Addr3 sets the BSSID/filter address (addr3).
func (b *Dot11Builder) Addr3(mac string) *Dot11Builder {
	_ = b.layer.Set("addr3", mac)
	return b
}

// SC sets the sequence control field.
func (b *Dot11Builder) SC(sc uint16) *Dot11Builder {
	_ = b.layer.Set("sc", sc)
	return b
}

// Duration sets the duration/ID field.
func (b *Dot11Builder) Duration(d uint16) *Dot11Builder {
	_ = b.layer.Set("duration", d)
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
	_ = b.layer.Set("present", flags)
	return b
}

// Data sets the variable-length field data.
func (b *RadioTapBuilder) Data(data []byte) *RadioTapBuilder {
	_ = b.layer.Set("data", data)
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
	_ = b.layer.Set("type", t)
	return b
}

// Opcode sets the HCI command opcode or event code.
func (b *HCIBuilder) Opcode(op uint16) *HCIBuilder {
	_ = b.layer.Set("opcode", op)
	return b
}

// Params sets the HCI parameters.
func (b *HCIBuilder) Params(data []byte) *HCIBuilder {
	_ = b.layer.Set("params", data)
	_ = b.layer.Set("param_len", uint8(len(data)))
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
	_ = b.layer.Set("cid", cid)
	return b
}

// Data sets the L2CAP payload.
func (b *L2CAPBuilder) Data(data []byte) *L2CAPBuilder {
	_ = b.layer.Set("data", data)
	_ = b.layer.Set("length", uint16(len(data)))
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
	_ = b.layer.Set("opcode", op)
	return b
}

// Params sets the ATT parameters.
func (b *ATTBuilder) Params(data []byte) *ATTBuilder {
	_ = b.layer.Set("params", data)
	return b
}

// Over stacks an upper layer on top of this ATT layer.
func (b *ATTBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- ZigbeeNWK Builder ----

// ZigbeeNWKBuilder builds Zigbee Network Layer frames.
type ZigbeeNWKBuilder struct {
	layer *packet.Layer
}

// NewZigbeeNWK creates a ZigbeeNWK builder.
func NewZigbeeNWK() *ZigbeeNWKBuilder {
	return &ZigbeeNWKBuilder{layer: zigbee.NewZigbeeNWK()}
}

func (b *ZigbeeNWKBuilder) Layer() *packet.Layer { return b.layer }

// FrameControl sets the NWK frame control field.
func (b *ZigbeeNWKBuilder) FrameControl(fc uint16) *ZigbeeNWKBuilder {
	_ = b.layer.Set("frame_control", fc)
	return b
}

// SeqNum sets the NWK sequence number.
func (b *ZigbeeNWKBuilder) SeqNum(seq uint8) *ZigbeeNWKBuilder {
	_ = b.layer.Set("seqnum", seq)
	return b
}

// Dst sets the NWK destination address.
func (b *ZigbeeNWKBuilder) Dst(addr uint16) *ZigbeeNWKBuilder {
	_ = b.layer.Set("dst", addr)
	return b
}

// Src sets the NWK source address.
func (b *ZigbeeNWKBuilder) Src(addr uint16) *ZigbeeNWKBuilder {
	_ = b.layer.Set("src", addr)
	return b
}

// Radius sets the broadcast radius.
func (b *ZigbeeNWKBuilder) Radius(r uint8) *ZigbeeNWKBuilder {
	_ = b.layer.Set("radius", r)
	return b
}

// Over stacks an upper layer on top of this ZigbeeNWK layer.
func (b *ZigbeeNWKBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- ZigbeeAPS Builder ----

// ZigbeeAPSBuilder builds Zigbee Application Support Sub-layer frames.
type ZigbeeAPSBuilder struct {
	layer *packet.Layer
}

// NewZigbeeAPS creates a ZigbeeAPS builder.
func NewZigbeeAPS() *ZigbeeAPSBuilder {
	return &ZigbeeAPSBuilder{layer: zigbee.NewZigbeeAPS()}
}

func (b *ZigbeeAPSBuilder) Layer() *packet.Layer { return b.layer }

// FrameControl sets the APS frame control byte.
func (b *ZigbeeAPSBuilder) FrameControl(fc uint8) *ZigbeeAPSBuilder {
	_ = b.layer.Set("frame_control", fc)
	return b
}

// Cluster sets the cluster ID.
func (b *ZigbeeAPSBuilder) Cluster(cid uint16) *ZigbeeAPSBuilder {
	_ = b.layer.Set("cluster", cid)
	return b
}

// Profile sets the profile ID.
func (b *ZigbeeAPSBuilder) Profile(pid uint16) *ZigbeeAPSBuilder {
	_ = b.layer.Set("profile", pid)
	return b
}

// DstEndpoint sets the destination endpoint.
func (b *ZigbeeAPSBuilder) DstEndpoint(ep uint8) *ZigbeeAPSBuilder {
	_ = b.layer.Set("dst_endpoint", ep)
	return b
}

// SrcEndpoint sets the source endpoint.
func (b *ZigbeeAPSBuilder) SrcEndpoint(ep uint8) *ZigbeeAPSBuilder {
	_ = b.layer.Set("src_endpoint", ep)
	return b
}

// Over stacks an upper layer on top of this ZigbeeAPS layer.
func (b *ZigbeeAPSBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- ZigbeeCluster Builder ----

// ZigbeeClusterBuilder builds Zigbee Cluster Library (ZCL) frames.
type ZigbeeClusterBuilder struct {
	layer *packet.Layer
}

// NewZigbeeCluster creates a ZigbeeCluster builder.
func NewZigbeeCluster() *ZigbeeClusterBuilder {
	return &ZigbeeClusterBuilder{layer: zigbee.NewZigbeeCluster()}
}

func (b *ZigbeeClusterBuilder) Layer() *packet.Layer { return b.layer }

// FrameControl sets the ZCL frame control byte.
func (b *ZigbeeClusterBuilder) FrameControl(fc uint8) *ZigbeeClusterBuilder {
	_ = b.layer.Set("frame_control", fc)
	return b
}

// Command sets the ZCL command identifier.
func (b *ZigbeeClusterBuilder) Command(cmd uint8) *ZigbeeClusterBuilder {
	_ = b.layer.Set("command", cmd)
	return b
}

// Payload sets the ZCL payload.
func (b *ZigbeeClusterBuilder) Payload(data []byte) *ZigbeeClusterBuilder {
	_ = b.layer.Set("payload", data)
	return b
}

// Over stacks an upper layer on top of this ZigbeeCluster layer.
func (b *ZigbeeClusterBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- LoRaWAN Builder ----

// LoRaWANBuilder builds LoRaWAN data frames.
type LoRaWANBuilder struct {
	layer *packet.Layer
}

// NewLoRaWAN creates a LoRaWAN builder.
func NewLoRaWAN() *LoRaWANBuilder {
	return &LoRaWANBuilder{layer: lorawan.NewLoRaWAN()}
}

func (b *LoRaWANBuilder) Layer() *packet.Layer { return b.layer }

// MHDR sets the MAC header byte.
func (b *LoRaWANBuilder) MHDR(mhdr uint8) *LoRaWANBuilder {
	_ = b.layer.Set("mhdr", mhdr)
	return b
}

// DevAddr sets the device address.
func (b *LoRaWANBuilder) DevAddr(addr uint32) *LoRaWANBuilder {
	_ = b.layer.Set("dev_addr", addr)
	return b
}

// FCtrl sets the frame control byte.
func (b *LoRaWANBuilder) FCtrl(fc uint8) *LoRaWANBuilder {
	_ = b.layer.Set("fctrl", fc)
	return b
}

// FCnt sets the frame counter.
func (b *LoRaWANBuilder) FCnt(cnt uint16) *LoRaWANBuilder {
	_ = b.layer.Set("fcnt", cnt)
	return b
}

// Data sets the variable data field (FOpts + FPort + Payload + MIC).
func (b *LoRaWANBuilder) Data(data []byte) *LoRaWANBuilder {
	_ = b.layer.Set("data", data)
	return b
}
