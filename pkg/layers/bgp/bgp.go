// Package bgp implements BGP-4 (Border Gateway Protocol, RFC 4271).
//
// BGP is the inter-domain routing protocol used to exchange routing information
// between autonomous systems. It runs over TCP port 179.
//
// This package implements:
//   - BGP common header (19 bytes: 16-byte marker + 2-byte length + 1-byte type)
//   - OPEN message
//   - UPDATE message
//   - KEEPALIVE message (header only)
//   - NOTIFICATION message
//   - Path attribute TLV encoding
//
// Packet-level only, no FSM.
package bgp

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// BGP message type constants.
const (
	TypeOpen         uint8 = 1 // OPEN
	TypeUpdate       uint8 = 2 // UPDATE
	TypeNotification uint8 = 3 // NOTIFICATION
	TypeKeepalive    uint8 = 4 // KEEPALIVE
	TypeRouteRefresh uint8 = 5 // ROUTE-REFRESH
)

// BGP header size (fixed: 16 marker + 2 length + 1 type).
const HeaderSize = 19

// BGP maximum message size.
const MaxMessageSize = 4096

// BGP Marker (16 bytes of 0xFF).
var Marker = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// BGP path attribute type codes.
const (
	AttrOrigin           uint8 = 1  // ORIGIN
	AttrASPath           uint8 = 2  // AS_PATH
	AttrNextHop          uint8 = 3  // NEXT_HOP
	AttrMED              uint8 = 4  // MULTI_EXIT_DISC
	AttrLocalPref        uint8 = 5  // LOCAL_PREF
	AttrAtomicAggregate  uint8 = 6  // ATOMIC_AGGREGATE
	AttrAggregator       uint8 = 7  // AGGREGATOR
	AttrCommunity        uint8 = 8  // COMMUNITY
	AttrOriginatorID     uint8 = 9  // ORIGINATOR_ID
	AttrClusterList      uint8 = 10 // CLUSTER_LIST
	AttrMPReachNLRI      uint8 = 14 // MP_REACH_NLRI
	AttrMPUnreachNLRI    uint8 = 15 // MP_UNREACH_NLRI
	AttrExtCommunities   uint8 = 16 // EXTENDED_COMMUNITIES
	AttrAS4Path          uint8 = 17 // AS4_PATH
	AttrAS4Aggregator    uint8 = 18 // AS4_AGGREGATOR
	AttrLargeCommunity   uint8 = 32 // LARGE_COMMUNITY
)

// Path attribute flag bits.
const (
	FlagOptional     uint8 = 0x80 // Optional
	FlagTransitive   uint8 = 0x40 // Transitive
	FlagPartial      uint8 = 0x20 // Partial
	FlagExtLength    uint8 = 0x10 // Extended Length
)

// BGP Origin values.
const (
	OriginIGP        uint8 = 0 // IGP
	OriginEGP        uint8 = 1 // EGP
	OriginIncomplete uint8 = 2 // INCOMPLETE
)

// NewBGP creates a BGP common header layer.
// Wire format (19 bytes):
//
//	marker(16, all 0xFF) | length(2) | type(1)
func NewBGP() *packet.Layer {
	return packet.NewLayer("BGP", []fields.Field{
		fields.NewStrFixedField("marker", 16, Marker), // 16 bytes of 0xFF
		fields.NewShortField("len", HeaderSize),        // Total message length
		fields.NewByteField("type", TypeOpen),           // Message type
	})
}

// NewBGPOpen creates a BGP OPEN message body layer.
// Wire format (10 bytes + optional parameters):
//
//	version(1) | my_as(2) | hold_time(2) | bgp_id(4) | opt_param_len(1) | opt_params[]
func NewBGPOpen() *packet.Layer {
	return packet.NewLayer("BGP Open", []fields.Field{
		fields.NewByteField("version", 4),                    // BGP version 4
		fields.NewShortField("my_as", 0),                     // Autonomous System Number
		fields.NewShortField("hold_time", 0),                 // Hold Time (seconds)
		fields.NewIPField("bgp_id", nil),                     // BGP Identifier (Router ID)
		fields.NewByteField("opt_param_len", 0),              // Optional Parameters Length
		fields.NewStrField("opt_params", ""),                  // Optional Parameters
	})
}

// NewBGPUpdate creates a BGP UPDATE message body layer.
// Wire format:
//
//	withdrawn_routes_len(2) | withdrawn_routes[] | path_attr_len(2) | path_attrs[] | nlri[]
func NewBGPUpdate() *packet.Layer {
	return packet.NewLayer("BGP Update", []fields.Field{
		fields.NewShortField("withdrawn_len", 0),             // Withdrawn Routes Length
		fields.NewStrField("withdrawn", ""),                   // Withdrawn Routes
		fields.NewShortField("path_attr_len", 0),             // Path Attributes Length
		fields.NewStrField("path_attrs", ""),                  // Path Attributes
		fields.NewStrField("nlri", ""),                        // NLRI (Network Layer Reachability Info)
	})
}

// NewBGPNotification creates a BGP NOTIFICATION message body layer.
// Wire format (2 bytes + data):
//
//	error_code(1) | error_subcode(1) | data[]
func NewBGPNotification() *packet.Layer {
	return packet.NewLayer("BGP Notification", []fields.Field{
		fields.NewByteField("error_code", 0),                 // Error Code
		fields.NewByteField("error_subcode", 0),              // Error Subcode
		fields.NewStrField("data", ""),                        // Error Data
	})
}

// NewBGPKeepalive creates a BGP KEEPALIVE message body (empty).
// KEEPALIVE is just the 19-byte header with no body.
func NewBGPKeepalive() *packet.Layer {
	return packet.NewLayer("BGP Keepalive", []fields.Field{})
}

// PathAttr represents a BGP path attribute with TLV encoding.
type PathAttr struct {
	Flags    uint8 // Attribute flags
	TypeCode uint8 // Attribute type code
	Value    []byte
}

// Serialize converts a PathAttr to wire-format bytes.
func (a *PathAttr) Serialize() []byte {
	valueLen := len(a.Value)
	useExtLen := valueLen > 255 || (a.Flags&FlagExtLength) != 0

	var buf []byte
	buf = append(buf, a.Flags)
	buf = append(buf, a.TypeCode)

	if useExtLen {
		buf = append(buf, byte(valueLen>>8), byte(valueLen))
	} else {
		buf = append(buf, byte(valueLen))
	}
	buf = append(buf, a.Value...)
	return buf
}

// ParsePathAttr parses a single path attribute from raw bytes.
// Returns the parsed attribute and the number of bytes consumed.
func ParsePathAttr(data []byte) (*PathAttr, int, error) {
	if len(data) < 3 {
		return nil, 0, fmt.Errorf("bgp: path attribute needs at least 3 bytes, got %d", len(data))
	}

	attr := &PathAttr{
		Flags:    data[0],
		TypeCode: data[1],
	}

	offset := 2
	var valueLen int

	if attr.Flags&FlagExtLength != 0 {
		if len(data) < 4 {
			return nil, 0, fmt.Errorf("bgp: extended length path attribute truncated")
		}
		valueLen = int(binary.BigEndian.Uint16(data[2:4]))
		offset = 4
	} else {
		valueLen = int(data[2])
		offset = 3
	}

	if offset+valueLen > len(data) {
		return nil, 0, fmt.Errorf("bgp: path attribute value truncated: need %d, have %d", offset+valueLen, len(data))
	}

	attr.Value = make([]byte, valueLen)
	copy(attr.Value, data[offset:offset+valueLen])

	return attr, offset + valueLen, nil
}

// ParsePathAttrs parses a sequence of path attributes from raw bytes.
func ParsePathAttrs(data []byte) ([]PathAttr, error) {
	var attrs []PathAttr
	remaining := data

	for len(remaining) > 0 {
		attr, consumed, err := ParsePathAttr(remaining)
		if err != nil {
			return attrs, err
		}
		attrs = append(attrs, *attr)
		remaining = remaining[consumed:]
	}

	return attrs, nil
}

// SerializePathAttrs serializes a list of path attributes.
func SerializePathAttrs(attrs []PathAttr) []byte {
	var buf []byte
	for _, a := range attrs {
		buf = append(buf, a.Serialize()...)
	}
	return buf
}

// NLRIPrefix represents a BGP NLRI prefix in CIDR encoding.
type NLRIPrefix struct {
	PrefixLen uint8
	Prefix    []byte // Significant bytes only (ceil(PrefixLen/8))
}

// Serialize converts an NLRI prefix to wire format.
func (n *NLRIPrefix) Serialize() []byte {
	buf := []byte{n.PrefixLen}
	buf = append(buf, n.Prefix...)
	return buf
}

// ParseNLRIPrefix parses an NLRI prefix from raw bytes.
func ParseNLRIPrefix(data []byte) (*NLRIPrefix, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("bgp: NLRI needs at least 1 byte")
	}
	prefixLen := data[0]
	byteLen := (int(prefixLen) + 7) / 8
	if len(data) < 1+byteLen {
		return nil, 0, fmt.Errorf("bgp: NLRI prefix truncated: need %d bytes, have %d", 1+byteLen, len(data))
	}
	prefix := make([]byte, byteLen)
	copy(prefix, data[1:1+byteLen])
	return &NLRIPrefix{PrefixLen: prefixLen, Prefix: prefix}, 1 + byteLen, nil
}

// BGPCapability represents a BGP capability (used in OPEN optional parameters).
type BGPCapability struct {
	Code   uint8
	Data   []byte
}

// SerializeCapability serializes a BGP capability to wire format.
func SerializeCapability(cap BGPCapability) []byte {
	var buf []byte
	buf = append(buf, cap.Code)
	buf = append(buf, byte(len(cap.Data)))
	buf = append(buf, cap.Data...)
	return buf
}

// BuildOpenOptParams builds the optional parameters for an OPEN message
// containing capabilities.
func BuildOpenOptParams(caps []BGPCapability) []byte {
	var capData []byte
	for _, c := range caps {
		capData = append(capData, SerializeCapability(c)...)
	}

	// Wrap in parameter type 2 (Capabilities)
	var params []byte
	params = append(params, 2)                   // param_type = Capabilities
	params = append(params, byte(len(capData)))   // param_length
	params = append(params, capData...)
	return params
}
