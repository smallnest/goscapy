// Package radius provides RADIUS (Remote Authentication Dial In User Service)
// protocol layer implementation per RFC 2865.
package radius

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// RADIUS code values (RFC 2865 Section 3).
const (
	CodeAccessRequest   uint8 = 1
	CodeAccessAccept    uint8 = 2
	CodeAccessReject    uint8 = 3
	CodeAccountingReq   uint8 = 4
	CodeAccountingResp  uint8 = 5
	CodeAccessChallenge uint8 = 11
	CodeStatusServer    uint8 = 12
	CodeStatusClient    uint8 = 13
)

// RADIUS AVP (Attribute-Value Pair) type constants (RFC 2865 Section 5).
const (
	AVPUserName      uint8 = 1
	AVPUserPassword  uint8 = 2
	AVPCHAPPassword  uint8 = 3
	AVPNASIP         uint8 = 4
	AVPNASPort       uint8 = 5
	AVPServiceType   uint8 = 6
	AVPFramedProtocol uint8 = 7
	AVPFramedIP      uint8 = 8
	AVPFramedIPNetmask uint8 = 9
	AVPFramedRouting uint8 = 10
	AVPFilterID      uint8 = 11
	AVPFramedMTU     uint8 = 12
	AVPFramedCompression uint8 = 13
	AVPLoginIP       uint8 = 14
	AVPLoginService  uint8 = 15
	AVPLoginTCPPort  uint8 = 16
	AVPReplyMessage  uint8 = 18
	AVPCallbackNumber uint8 = 19
	AVPCallbackID    uint8 = 20
	AVPFramedRoute   uint8 = 22
	AVPFramedIPX     uint8 = 23
	AVPState         uint8 = 24
	AVPClass         uint8 = 25
	AVPVendorSpecific uint8 = 26
	AVPSessionTimeout uint8 = 27
	AVPIdleTimeout   uint8 = 28
	AVPTerminationAction uint8 = 29
	AVPCalledStationID uint8 = 30
	AVPCallingStationID uint8 = 31
	AVPNASIdentifier uint8 = 32
	AVPProxyState    uint8 = 33
	AVPLoginLATService uint8 = 34
	AVPLoginLATNode  uint8 = 35
	AVPLoginLATGroup uint8 = 36
	AVPFramedAppleTalkLink uint8 = 37
	AVPFramedAppleTalkNetwork uint8 = 38
	AVPFramedAppleTalkZone uint8 = 39
	AVPAcctStatusType uint8 = 40
	AVPAcctDelayTime uint8 = 41
	AVPAcctInputOctets uint8 = 42
	AVPAcctOutputOctets uint8 = 43
	AVPAcctSessionID uint8 = 44
	AVPAcctAuthentic uint8 = 45
	AVPAcctSessionTime uint8 = 46
	AVPAcctInputPackets uint8 = 47
	AVPAcctOutputPackets uint8 = 48
	AVPAcctTerminateCause uint8 = 49
	AVPEventTimestamp uint8 = 55
	AVPNASPortType   uint8 = 61
	AVPPortLimit     uint8 = 62
)

// Header size: code(1) + id(1) + length(2) + authenticator(16) = 20 bytes.
const radiusHeaderLen = 20

// NewRADIUS creates a RADIUS layer with Access-Request defaults.
func NewRADIUS() *packet.Layer {
	return packet.NewLayer("RADIUS", []fields.Field{
		fields.NewByteField("code", CodeAccessRequest),
		fields.NewByteField("id", 0),
		fields.NewShortField("length", radiusHeaderLen),
		fields.NewStrFixedField("authenticator", 16, make([]byte, 16)),
		fields.NewStrField("avps", ""),
	})
}

// CodeName returns the name for a RADIUS code value.
func CodeName(code uint8) string {
	switch code {
	case CodeAccessRequest:
		return "Access-Request"
	case CodeAccessAccept:
		return "Access-Accept"
	case CodeAccessReject:
		return "Access-Reject"
	case CodeAccountingReq:
		return "Accounting-Request"
	case CodeAccountingResp:
		return "Accounting-Response"
	case CodeAccessChallenge:
		return "Access-Challenge"
	case CodeStatusServer:
		return "Status-Server"
	case CodeStatusClient:
		return "Status-Client"
	default:
		return fmt.Sprintf("Unknown(%d)", code)
	}
}

// ---- AVP parsing and building ----

// ParseRADIUSAVPs parses TLV-encoded RADIUS AVPs from raw bytes.
// RADIUS AVPs are: Type(1B) + Length(1B, includes Type+Length) + Value.
// This differs from fields.TLVOption where Length is just the value length.
func ParseRADIUSAVPs(data []byte) ([]fields.TLVOption, error) {
	var opts []fields.TLVOption
	rest := data
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, fmt.Errorf("radius: AVP truncated at %d bytes", len(rest))
		}
		typ := rest[0]
		avl := int(rest[1]) // AVP length includes Type(1) + Length(1) + Value
		if avl < 3 {
			return nil, fmt.Errorf("radius: AVP type %d has invalid length %d", typ, avl)
		}
		if len(rest) < avl {
			return nil, fmt.Errorf("radius: AVP type %d needs %d bytes, have %d", typ, avl, len(rest))
		}
		opts = append(opts, fields.TLVOption{
			Type:   typ,
			Length: uint8(avl - 2), // store value length only, matching TLVOption convention
			Value:  rest[2:avl],
		})
		rest = rest[avl:]
	}
	return opts, nil
}

// BuildRADIUSAVPs serializes RADIUS AVPs to wire format.
// Each AVP is: Type(1B) + Length(1B, = 2 + len(Value)) + Value.
// Returns an error if any value exceeds 253 bytes (max AVP value length per RFC 2865).
func BuildRADIUSAVPs(avps []fields.TLVOption) ([]byte, error) {
	var buf []byte
	for _, a := range avps {
		if len(a.Value) > 253 {
			return nil, fmt.Errorf("radius: AVP type %d value too long (%d bytes, max 253)", a.Type, len(a.Value))
		}
		avl := 2 + len(a.Value)
		buf = append(buf, a.Type, byte(avl))
		buf = append(buf, a.Value...)
	}
	return buf, nil
}

// GetRADIUSAVP returns the first AVP matching the given type, or nil.
func GetRADIUSAVP(avps []fields.TLVOption, typ uint8) *fields.TLVOption {
	return fields.GetTLV(avps, typ)
}

// ---- Convenience AVP constructors ----

// NewUserNameAVP creates a User-Name AVP (type 1).
func NewUserNameAVP(name string) fields.TLVOption {
	return fields.TLVOption{Type: AVPUserName, Value: []byte(name)}
}

// NewNASIPAVP creates a NAS-IP-Address AVP (type 4).
func NewNASIPAVP(ip string) fields.TLVOption {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		parsed = net.IPv4zero
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	return fields.TLVOption{Type: AVPNASIP, Value: ip4}
}

// NewNASPortAVP creates a NAS-Port AVP (type 5).
func NewNASPortAVP(port uint32) fields.TLVOption {
	return fields.TLVOption{Type: AVPNASPort, Value: uint32BE(port)}
}

// NewServiceTypeAVP creates a Service-Type AVP (type 6).
func NewServiceTypeAVP(svc uint32) fields.TLVOption {
	return fields.TLVOption{Type: AVPServiceType, Value: uint32BE(svc)}
}

// NewFramedIPAVP creates a Framed-IP-Address AVP (type 8).
func NewFramedIPAVP(ip string) fields.TLVOption {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		parsed = net.IPv4zero
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	return fields.TLVOption{Type: AVPFramedIP, Value: ip4}
}

// NewStateAVP creates a State AVP (type 24).
func NewStateAVP(state []byte) fields.TLVOption {
	return fields.TLVOption{Type: AVPState, Value: state}
}

// NewNASIdentifierAVP creates a NAS-Identifier AVP (type 32).
func NewNASIdentifierAVP(id string) fields.TLVOption {
	return fields.TLVOption{Type: AVPNASIdentifier, Value: []byte(id)}
}

// NewVendorSpecificAVP creates a Vendor-Specific AVP (type 26).
// The value must include the Vendor-ID (4 bytes) + vendor-specific sub-attributes.
func NewVendorSpecificAVP(vendorID uint32, subAttrs []byte) fields.TLVOption {
	val := append(uint32BE(vendorID), subAttrs...)
	return fields.TLVOption{Type: AVPVendorSpecific, Value: val}
}

func uint32BE(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
	return b
}
