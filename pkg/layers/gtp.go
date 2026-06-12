package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// GTP UDP ports (3GPP TS 29.060 / 29.281).
const (
	GTPCPort uint16 = 2123 // GTP-C control plane
	GTPUPort uint16 = 2152 // GTP-U user plane
)

// GTP version/protocol-type bits packed in the first header byte.
const (
	gtpVersionV1 uint8 = 0x20 // version=1 in bits 7-5
	gtpProtoType uint8 = 0x10 // PT=1 (GTP, not GTP')
)

// GTP message types (subset, 3GPP TS 29.281 / 29.060).
const (
	GTPMsgEchoRequest     uint8 = 1
	GTPMsgEchoResponse    uint8 = 2
	GTPMsgErrorIndication uint8 = 26
	GTPMsgGPDU            uint8 = 255 // user-plane T-PDU (GTP-U)
)

// NewGTP creates a GTPv1 header (3GPP TS 29.281, GTP-U user plane).
// Base wire format (8 bytes):
//
//	flags(1) | message type(1) | length(2) | TEID(4)
//
// flags packs version(3), PT(1), and the E/S/PN extension flags. When any of
// E/S/PN is set, an optional 4-byte field (seq(2) + N-PDU(1) + next-ext(1))
// follows; goscapy models GTP with the base 8-byte header and carries the
// payload (e.g. an inner IP packet for GTP-U G-PDU) as the next layer.
//
// length is the number of bytes following the mandatory 8-byte header and is
// auto-computed during Build.
func NewGTP() *packet.Layer {
	return packet.NewLayer("GTP", []fields.Field{
		fields.NewByteField("flags", gtpVersionV1|gtpProtoType),
		fields.NewByteField("msgtype", GTPMsgGPDU),
		fields.NewShortField("len", 0), // payload length, auto-computed during Build
		fields.NewIntField("teid", 0),
	})
}

// NewGTPWith creates a GTPv1 header with the given message type and TEID.
func NewGTPWith(msgType uint8, teid uint32) *packet.Layer {
	l := NewGTP()
	_ = l.Set("msgtype", msgType)
	_ = l.Set("teid", teid)
	return l
}

// GTPVersion extracts the 3-bit version from the flags byte.
func GTPVersion(flags uint8) uint8 { return flags >> 5 }

// GTPHasExtensions reports whether any of the E/S/PN flag bits are set, meaning
// the optional 4-byte sequence/N-PDU/next-extension field is present.
func GTPHasExtensions(flags uint8) bool { return flags&0x07 != 0 }

// gtpBuildHook auto-computes the GTP length field (bytes following the
// mandatory 8-byte header) from the upper-layer payload.
func gtpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]
	_ = layer.Set("len", uint16(len(upperBytes)))
	return layer.SerializeInto(buf)
}

// gtpNextLayer resolves the payload protocol for a GTP-U G-PDU: the user-plane
// payload is an inner IP packet, identified by the first nibble (4 → IPv4,
// 6 → IPv6). Control-plane and signaling messages have no goscapy sub-layer.
func gtpNextLayer(layer *packet.Layer, remaining []byte) string {
	mt, _ := layer.Get("msgtype")
	if mtv, _ := mt.(uint8); mtv != GTPMsgGPDU {
		return ""
	}
	// If extension flags are set, the optional 4-byte field precedes the
	// payload; goscapy does not model it, so only resolve the simple case.
	if fl, _ := layer.Get("flags"); GTPHasExtensions(fl.(uint8)) {
		return ""
	}
	if len(remaining) == 0 {
		return ""
	}
	switch remaining[0] >> 4 {
	case 4:
		return "IP"
	case 6:
		return "IPv6"
	}
	return ""
}
