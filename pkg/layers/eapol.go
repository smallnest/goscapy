package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// EtherTypeEAPOL is the EtherType for IEEE 802.1X EAPOL frames.
const EtherTypeEAPOL uint16 = 0x888E

// EAPOL packet types (IEEE 802.1X-2004).
const (
	EAPOLTypeEAP      uint8 = 0 // EAP-Packet
	EAPOLTypeStart    uint8 = 1 // EAPOL-Start
	EAPOLTypeLogoff   uint8 = 2 // EAPOL-Logoff
	EAPOLTypeKey      uint8 = 3 // EAPOL-Key
	EAPOLTypeASFAlert uint8 = 4 // EAPOL-Encapsulated-ASF-Alert
)

// EAP codes (RFC 3748), carried in the EAPOL body when type = EAP-Packet.
const (
	EAPCodeRequest  uint8 = 1
	EAPCodeResponse uint8 = 2
	EAPCodeSuccess  uint8 = 3
	EAPCodeFailure  uint8 = 4
)

// NewEAPOL creates an EAPOL header (IEEE 802.1X).
// Wire format (4 bytes):
//
//	version(1) | type(1) | length(2) | body (variable)
//
// length is the number of body bytes following the 4-byte header and is
// auto-computed during Build. When type = EAP-Packet, the body is an EAP layer.
func NewEAPOL() *packet.Layer {
	return packet.NewLayer("EAPOL", []fields.Field{
		fields.NewByteField("version", 1),
		fields.NewByteField("type", EAPOLTypeEAP),
		fields.NewShortField("len", 0), // body length, auto-computed during Build
	})
}

// NewEAPOLWith creates an EAPOL header of the given type.
func NewEAPOLWith(eapolType uint8) *packet.Layer {
	l := NewEAPOL()
	_ = l.Set("type", eapolType)
	return l
}

// eapolBuildHook auto-computes the EAPOL body length from the upper-layer bytes.
func eapolBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]
	_ = layer.Set("len", uint16(len(upperBytes)))
	return layer.SerializeInto(buf)
}

// NewEAP creates an EAP packet header (RFC 3748).
// Wire format:
//
//	code(1) | id(1) | length(2) | type(1, present for Request/Response) |
//	type data (variable)
//
// The type field and data are only present for Request (1) and Response (2)
// codes; Success (3) and Failure (4) carry only the 4-byte header. goscapy
// models the common 4-byte header plus a "data" field; for Request/Response the
// first data byte is the EAP method type.
func NewEAP() *packet.Layer {
	return packet.NewLayer("EAP", []fields.Field{
		fields.NewByteField("code", EAPCodeRequest),
		fields.NewByteField("id", 0),
		fields.NewShortField("len", 0), // total EAP length, auto-computed during Build
		fields.NewStrField("data", ""), // type byte + type data (Request/Response only)
	})
}

// NewEAPWith creates an EAP packet with the given code and identifier.
func NewEAPWith(code, id uint8) *packet.Layer {
	l := NewEAP()
	_ = l.Set("code", code)
	_ = l.Set("id", id)
	return l
}

// eapBuildHook auto-computes the EAP length field, which covers the entire EAP
// message (4-byte header + data + any upper bytes).
func eapBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]

	dataLen := 0
	if v, err := layer.Get("data"); err == nil {
		switch t := v.(type) {
		case []byte:
			dataLen = len(t)
		case string:
			dataLen = len(t)
		}
	}
	_ = layer.Set("len", uint16(4+dataLen+len(upperBytes)))
	return layer.SerializeInto(buf)
}
