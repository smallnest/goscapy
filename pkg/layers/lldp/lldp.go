// Package lldp implements the Link Layer Discovery Protocol (IEEE 802.1AB).
//
// LLDP allows network devices to advertise their identity and capabilities
// to directly connected neighbors. Each LLDPDU contains a sequence of TLVs
// (Type-Length-Value), terminated by an End TLV.
//
// The 4 mandatory TLV types are:
//   - Chassis ID (type 1)
//   - Port ID (type 2)
//   - Time to Live (type 3)
//   - End (type 0)
package lldp

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// LLDP TLV type constants (7-bit type field in TLV header).
const (
	TLVEnd       uint8 = 0 // End Of LLDPDU
	TLVChassisID uint8 = 1 // Chassis ID
	TLVPortID    uint8 = 2 // Port ID
	TLVTTL       uint8 = 3 // Time To Live
)

// Chassis ID subtypes (for Chassis ID TLV value).
const (
	ChassisIDSubtypeMACAddr   uint8 = 4 // MAC Address
	ChassisIDSubtypeIPAddr    uint8 = 5 // Network Address (IP)
	ChassisIDSubtypePortComp  uint8 = 1 // Chassis Component
	ChassisIDSubtypeIntfAlias uint8 = 2 // Interface Alias
	ChassisIDSubtypePortMac   uint8 = 3 // Port Component
	ChassisIDSubtypeIfaceName uint8 = 6 // Interface Name
	ChassisIDSubtypeLocal     uint8 = 7 // Locally Assigned
)

// Port ID subtypes (for Port ID TLV value).
const (
	PortIDSubtypeIntfAlias uint8 = 1 // Interface Alias
	PortIDSubtypePortComp  uint8 = 2 // Port Component
	PortIDSubtypeMACAddr   uint8 = 3 // MAC Address
	PortIDSubtypeIPAddr    uint8 = 4 // Network Address (IP)
	PortIDSubtypeIfaceName uint8 = 5 // Interface Name
	PortIDSubtypeAgentCID  uint8 = 6 // Agent Circuit ID
	PortIDSubtypeLocal     uint8 = 7 // Locally Assigned
)

// LLDPDU represents a complete LLDP Data Unit with TLV entries.
// The wire format is a sequence of TLVs where each TLV header is 2 bytes:
//   bits 0-6:  Type (7 bits)
//   bits 7-15: Length (9 bits) = length of the Value field
// Followed by Value (Length bytes).
// The LLDPDU is terminated by an End TLV (type=0, length=0).
type LLDPDU struct {
	TLVs []TLV
}

// TLV represents a single LLDP TLV entry.
type TLV struct {
	Type   uint8 // 7-bit type
	Value  []byte
}

// NewLLDP creates an LLDP layer with default mandatory TLVs:
// Chassis ID (MAC), Port ID (MAC), TTL (120s), and End.
func NewLLDP() *packet.Layer {
	return packet.NewLayer("LLDP", []fields.Field{
		fields.NewStrField("tlv_data", ""), // raw TLV bytes
	})
}

// NewLLDPDU creates a default LLDPDU with mandatory TLVs.
func NewLLDPDU() *LLDPDU {
	return &LLDPDU{
		TLVs: []TLV{
			{Type: TLVChassisID, Value: append([]byte{ChassisIDSubtypeMACAddr}, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}...)},
			{Type: TLVPortID, Value: append([]byte{PortIDSubtypeMACAddr}, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}...)},
			{Type: TLVTTL, Value: []byte{0x00, 0x78}}, // 120 seconds
			{Type: TLVEnd, Value: nil},
		},
	}
}

// Serialize converts the LLDPDU to wire-format bytes.
func (du *LLDPDU) Serialize() ([]byte, error) {
	var buf []byte
	for _, tlv := range du.TLVs {
		// TLV header: Type (7 bits) | Length (9 bits)
		typ := tlv.Type & 0x7F
		length := len(tlv.Value) & 0x01FF
		header := uint16(typ)<<9 | uint16(length)
		buf = append(buf, byte(header>>8), byte(header))
		buf = append(buf, tlv.Value...)
	}
	return buf, nil
}

// ParseLLDPDU parses raw bytes into an LLDPDU.
func ParseLLDPDU(data []byte) (*LLDPDU, error) {
	var tlvs []TLV
	remaining := data

	for len(remaining) >= 2 {
		header := binary.BigEndian.Uint16(remaining[0:2])
		typ := uint8(header >> 9)       // upper 7 bits
		length := int(header & 0x01FF)  // lower 9 bits

		if len(remaining) < 2+length {
			return nil, fmt.Errorf("lldp: TLV type %d: need %d bytes, have %d", typ, 2+length, len(remaining))
		}

		var value []byte
		if length > 0 {
			value = make([]byte, length)
			copy(value, remaining[2:2+length])
		}

		tlvs = append(tlvs, TLV{Type: typ, Value: value})
		remaining = remaining[2+length:]

		if typ == TLVEnd {
			break
		}
	}

	if len(tlvs) == 0 {
		return nil, fmt.Errorf("lldp: no TLVs found")
	}

	return &LLDPDU{TLVs: tlvs}, nil
}

// ChassisID returns the Chassis ID TLV value, or nil if not found.
func (du *LLDPDU) ChassisID() *TLV {
	return du.FindTLV(TLVChassisID)
}

// PortID returns the Port ID TLV value, or nil if not found.
func (du *LLDPDU) PortID() *TLV {
	return du.FindTLV(TLVPortID)
}

// TTL returns the Time To Live TLV value as uint16, or 0 if not found.
func (du *LLDPDU) TTL() uint16 {
	tlv := du.FindTLV(TLVTTL)
	if tlv == nil || len(tlv.Value) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(tlv.Value[0:2])
}

// FindTLV returns the first TLV with the given type, or nil.
func (du *LLDPDU) FindTLV(typ uint8) *TLV {
	for i := range du.TLVs {
		if du.TLVs[i].Type == typ {
			return &du.TLVs[i]
		}
	}
	return nil
}

// BuildLLDP serializes an LLDPDU and sets it as the layer's tlv_data field.
func BuildLLDP(du *LLDPDU, layer *packet.Layer) error {
	data, err := du.Serialize()
	if err != nil {
		return err
	}
	return layer.Set("tlv_data", data)
}

// ParseLLDP parses tlv_data from a layer into an LLDPDU.
func ParseLLDP(layer *packet.Layer) (*LLDPDU, error) {
	val, err := layer.Get("tlv_data")
	if err != nil {
		return nil, err
	}
	var data []byte
	switch v := val.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return nil, fmt.Errorf("lldp: unexpected tlv_data type %T", val)
	}
	return ParseLLDPDU(data)
}
