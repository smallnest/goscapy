package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// EtherType values for PPPoE discovery and session stages (RFC 2516).
const (
	EtherTypePPPoEDiscovery uint16 = 0x8863
	EtherTypePPPoESession   uint16 = 0x8864
)

// PPPoE discovery codes (RFC 2516).
const (
	PPPoECodeSession uint8 = 0x00 // session stage data
	PPPoECodePADI    uint8 = 0x09 // Active Discovery Initiation
	PPPoECodePADO    uint8 = 0x07 // Active Discovery Offer
	PPPoECodePADR    uint8 = 0x19 // Active Discovery Request
	PPPoECodePADS    uint8 = 0x65 // Active Discovery Session-confirmation
	PPPoECodePADT    uint8 = 0xA7 // Active Discovery Terminate
)

// Common PPP protocol values carried inside a PPPoE session.
const (
	PPPProtoIPv4 uint16 = 0x0021
	PPPProtoIPv6 uint16 = 0x0057
	PPPProtoLCP  uint16 = 0xC021
	PPPProtoIPCP uint16 = 0x8021
)

// NewPPPoE creates a PPPoE header layer (RFC 2516).
// Wire format (6 bytes):
//
//	ver_type(1) | code(1) | session_id(2) | length(2)
//
// ver_type packs version (high nibble, =1) and type (low nibble, =1) → 0x11.
// The length field is the number of payload bytes following the header and is
// auto-computed during Build. For the session stage the payload is a PPP frame.
func NewPPPoE() *packet.Layer {
	return packet.NewLayer("PPPoE", []fields.Field{
		fields.NewByteField("ver_type", 0x11), // version=1, type=1
		fields.NewByteField("code", PPPoECodeSession),
		fields.NewShortField("session_id", 0),
		fields.NewShortField("len", 0), // payload length, auto-computed during Build
	})
}

// NewPPPoEWith creates a PPPoE header with the given code and session ID.
func NewPPPoEWith(code uint8, sessionID uint16) *packet.Layer {
	l := NewPPPoE()
	_ = l.Set("code", code)
	_ = l.Set("session_id", sessionID)
	return l
}

// pppoeBuildHook auto-computes the PPPoE payload length from the upper layer
// bytes, writing directly into buf.
func pppoeBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]
	_ = layer.Set("len", uint16(len(upperBytes)))
	return layer.SerializeInto(buf)
}

// NewPPP creates a PPP header layer for use inside a PPPoE session (RFC 1661).
// Wire format (2 bytes): protocol(2). The protocol field identifies the
// encapsulated payload (e.g. PPPProtoIPv4 = 0x0021).
func NewPPP() *packet.Layer {
	return packet.NewLayer("PPP", []fields.Field{
		fields.NewShortField("proto", PPPProtoIPv4),
	})
}

// NewPPPWith creates a PPP header with the given protocol value.
func NewPPPWith(proto uint16) *packet.Layer {
	l := NewPPP()
	_ = l.Set("proto", proto)
	return l
}
