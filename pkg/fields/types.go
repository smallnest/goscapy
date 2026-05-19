package fields

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// ---- integer fields ----

// ByteField is a 1-byte unsigned integer field.
type ByteField struct{ Desc }

// NewByteField creates a 1-byte unsigned integer field.
func NewByteField(name string, defVal uint8) *ByteField {
	return &ByteField{Desc: Desc{name: name, size: 1, defVal: defVal}}
}

func (f *ByteField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint8)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint8, got %T", f.name, val)
	}
	return []byte{v}, nil
}

func (f *ByteField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 1); err != nil {
		return nil, 0, err
	}
	return b[0], 1, nil
}

// XByteField is a 1-byte field that displays as hex.
type XByteField struct{ ByteField }

// NewXByteField creates a 1-byte hex-display field.
func NewXByteField(name string, defVal uint8) *XByteField {
	return &XByteField{ByteField: *NewByteField(name, defVal)}
}

// ShortField is a 2-byte big-endian unsigned integer field.
type ShortField struct{ Desc }

// NewShortField creates a 2-byte big-endian unsigned integer field.
func NewShortField(name string, defVal uint16) *ShortField {
	return &ShortField{Desc: Desc{name: name, size: 2, defVal: defVal}}
}

func (f *ShortField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint16)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint16, got %T", f.name, val)
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b, nil
}

func (f *ShortField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 2); err != nil {
		return nil, 0, err
	}
	return binary.BigEndian.Uint16(b[:2]), 2, nil
}

// LEShortField is a 2-byte little-endian unsigned integer field.
type LEShortField struct{ Desc }

// NewLEShortField creates a 2-byte little-endian unsigned integer field.
func NewLEShortField(name string, defVal uint16) *LEShortField {
	return &LEShortField{Desc: Desc{name: name, size: 2, defVal: defVal}}
}

func (f *LEShortField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint16)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint16, got %T", f.name, val)
	}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b, nil
}

func (f *LEShortField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 2); err != nil {
		return nil, 0, err
	}
	return binary.LittleEndian.Uint16(b[:2]), 2, nil
}

// ThreeBytesField is a 3-byte big-endian unsigned integer field.
type ThreeBytesField struct{ Desc }

// NewThreeBytesField creates a 3-byte big-endian unsigned integer field.
func NewThreeBytesField(name string, defVal uint32) *ThreeBytesField {
	return &ThreeBytesField{Desc: Desc{name: name, size: 3, defVal: defVal}}
}

func (f *ThreeBytesField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint32)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint32, got %T", f.name, val)
	}
	if v > 0xFFFFFF {
		return nil, fmt.Errorf("fields: %s value %d exceeds 3 bytes", f.name, v)
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b[1:], nil
}

func (f *ThreeBytesField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 3); err != nil {
		return nil, 0, err
	}
	tmp := make([]byte, 4)
	copy(tmp[1:], b[:3])
	return binary.BigEndian.Uint32(tmp), 3, nil
}

// IntField is a 4-byte big-endian unsigned integer field.
type IntField struct{ Desc }

// NewIntField creates a 4-byte big-endian unsigned integer field.
func NewIntField(name string, defVal uint32) *IntField {
	return &IntField{Desc: Desc{name: name, size: 4, defVal: defVal}}
}

func (f *IntField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint32)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint32, got %T", f.name, val)
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b, nil
}

func (f *IntField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 4); err != nil {
		return nil, 0, err
	}
	return binary.BigEndian.Uint32(b[:4]), 4, nil
}

// SignedIntField is a 4-byte big-endian signed integer field.
type SignedIntField struct{ Desc }

// NewSignedIntField creates a 4-byte big-endian signed integer field.
func NewSignedIntField(name string, defVal int32) *SignedIntField {
	return &SignedIntField{Desc: Desc{name: name, size: 4, defVal: defVal}}
}

func (f *SignedIntField) Pack(val any) ([]byte, error) {
	v, ok := val.(int32)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects int32, got %T", f.name, val)
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b, nil
}

func (f *SignedIntField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 4); err != nil {
		return nil, 0, err
	}
	return int32(binary.BigEndian.Uint32(b[:4])), 4, nil
}

// LEIntField is a 4-byte little-endian unsigned integer field.
type LEIntField struct{ Desc }

// NewLEIntField creates a 4-byte little-endian unsigned integer field.
func NewLEIntField(name string, defVal uint32) *LEIntField {
	return &LEIntField{Desc: Desc{name: name, size: 4, defVal: defVal}}
}

func (f *LEIntField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint32)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint32, got %T", f.name, val)
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b, nil
}

func (f *LEIntField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 4); err != nil {
		return nil, 0, err
	}
	return binary.LittleEndian.Uint32(b[:4]), 4, nil
}

// LongField is an 8-byte big-endian unsigned integer field.
type LongField struct{ Desc }

// NewLongField creates an 8-byte big-endian unsigned integer field.
func NewLongField(name string, defVal uint64) *LongField {
	return &LongField{Desc: Desc{name: name, size: 8, defVal: defVal}}
}

func (f *LongField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint64)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint64, got %T", f.name, val)
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b, nil
}

func (f *LongField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 8); err != nil {
		return nil, 0, err
	}
	return binary.BigEndian.Uint64(b[:8]), 8, nil
}

// LELongField is an 8-byte little-endian unsigned integer field.
type LELongField struct{ Desc }

// NewLELongField creates an 8-byte little-endian unsigned integer field.
func NewLELongField(name string, defVal uint64) *LELongField {
	return &LELongField{Desc: Desc{name: name, size: 8, defVal: defVal}}
}

func (f *LELongField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint64)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint64, got %T", f.name, val)
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b, nil
}

func (f *LELongField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 8); err != nil {
		return nil, 0, err
	}
	return binary.LittleEndian.Uint64(b[:8]), 8, nil
}

// ---- bit field ----

// BitField is a field that occupies a specified number of bits (1-8) within a single byte.
type BitField struct {
	Desc
	bitSize uint8
}

// NewBitField creates a bit field of the given size in bits (1-8).
func NewBitField(name string, defVal uint8, bitSize uint8) *BitField {
	return &BitField{
		Desc:    Desc{name: name, size: 0, defVal: defVal}, // size 0: must be handled by bit-group during pack
		bitSize: bitSize,
	}
}

// BitSize returns the number of bits this field occupies.
func (f *BitField) BitSize() uint8 { return f.bitSize }

func (f *BitField) Pack(val any) ([]byte, error) {
	v, ok := val.(uint8)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects uint8, got %T", f.name, val)
	}
	mask := uint8((1 << f.bitSize) - 1)
	if v > mask {
		return nil, fmt.Errorf("fields: %s value %d exceeds %d bits", f.name, v, f.bitSize)
	}
	return []byte{v & mask}, nil
}

func (f *BitField) Unpack(b []byte) (any, int, error) {
	if len(b) < 1 {
		return nil, 0, fmt.Errorf("fields: %s needs 1 byte", f.name)
	}
	mask := uint8((1 << f.bitSize) - 1)
	return b[0] & mask, 0, nil // consumed 0: outer bit-group manages byte offset
}

// ---- address fields ----

// MACField is a 6-byte MAC address field.
type MACField struct{ Desc }

// NewMACField creates a 6-byte MAC address field.
func NewMACField(name string, defVal net.HardwareAddr) *MACField {
	return &MACField{Desc: Desc{name: name, size: 6, defVal: defVal}}
}

func (f *MACField) Pack(val any) ([]byte, error) {
	switch v := val.(type) {
	case net.HardwareAddr:
		if len(v) != 6 {
			return nil, fmt.Errorf("fields: %s MAC must be 6 bytes, got %d", f.name, len(v))
		}
		return []byte(v), nil
	case string:
		mac, err := net.ParseMAC(v)
		if err != nil {
			return nil, fmt.Errorf("fields: %s invalid MAC %q: %w", f.name, v, err)
		}
		return []byte(mac), nil
	case []byte:
		if len(v) != 6 {
			return nil, fmt.Errorf("fields: %s MAC must be 6 bytes, got %d", f.name, len(v))
		}
		return v, nil
	default:
		return nil, fmt.Errorf("fields: %s expects net.HardwareAddr, string, or []byte, got %T", f.name, val)
	}
}

func (f *MACField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 6); err != nil {
		return nil, 0, err
	}
	mac := net.HardwareAddr(bytes.Clone(b[:6]))
	return mac, 6, nil
}

// IPField is a 4-byte IPv4 address field.
type IPField struct{ Desc }

// NewIPField creates a 4-byte IPv4 address field.
func NewIPField(name string, defVal net.IP) *IPField {
	return &IPField{Desc: Desc{name: name, size: 4, defVal: defVal}}
}

func (f *IPField) Pack(val any) ([]byte, error) {
	switch v := val.(type) {
	case net.IP:
		ip4 := v.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("fields: %s requires IPv4 address, got %v", f.name, v)
		}
		return []byte(ip4), nil
	case string:
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("fields: %s invalid IP %q", f.name, v)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("fields: %s requires IPv4 address, got %v", f.name, v)
		}
		return []byte(ip4), nil
	default:
		return nil, fmt.Errorf("fields: %s expects net.IP or string, got %T", f.name, val)
	}
}

func (f *IPField) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 4); err != nil {
		return nil, 0, err
	}
	ip := net.IP(bytes.Clone(b[:4]))
	return ip, 4, nil
}

// IPv6Field is a 16-byte IPv6 address field.
type IPv6Field struct{ Desc }

// NewIPv6Field creates a 16-byte IPv6 address field.
func NewIPv6Field(name string, defVal net.IP) *IPv6Field {
	return &IPv6Field{Desc: Desc{name: name, size: 16, defVal: defVal}}
}

func (f *IPv6Field) Pack(val any) ([]byte, error) {
	switch v := val.(type) {
	case net.IP:
		ip16 := v.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("fields: %s requires IPv6 address, got %v", f.name, v)
		}
		return []byte(ip16), nil
	case string:
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("fields: %s invalid IP %q", f.name, v)
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("fields: %s requires IPv6 address, got %v", f.name, v)
		}
		return []byte(ip16), nil
	case []byte:
		if len(v) != 16 {
			return nil, fmt.Errorf("fields: %s IPv6 must be 16 bytes, got %d", f.name, len(v))
		}
		return v, nil
	default:
		return nil, fmt.Errorf("fields: %s expects net.IP, string, or []byte, got %T", f.name, val)
	}
}

func (f *IPv6Field) Unpack(b []byte) (any, int, error) {
	if err := validateSize(f.name, b, 16); err != nil {
		return nil, 0, err
	}
	ip := net.IP(bytes.Clone(b[:16]))
	return ip, 16, nil
}

// ---- string / payload fields ----

// StrField is a variable-length string field whose size is determined
// by consuming all remaining bytes from the buffer during unpacking.
type StrField struct{ Desc }

// NewStrField creates a variable-length string field.
func NewStrField(name string, defVal string) *StrField {
	return &StrField{Desc: Desc{name: name, size: 0, defVal: defVal}}
}

func (f *StrField) Pack(val any) ([]byte, error) {
	switch v := val.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("fields: %s expects string or []byte, got %T", f.name, val)
	}
}

func (f *StrField) Unpack(b []byte) (any, int, error) {
	return b, len(b), nil
}

// StrLenField is a string field whose length is determined by another field's value.
type StrLenField struct {
	Desc
	lengthFrom string
}

// NewStrLenField creates a string field whose size is read from the named field at build time.
func NewStrLenField(name string, defVal string, lengthFrom string) *StrLenField {
	return &StrLenField{
		Desc:       Desc{name: name, size: 0, defVal: defVal},
		lengthFrom: lengthFrom,
	}
}

// LengthFrom returns the name of the field that holds this field's length.
func (f *StrLenField) LengthFrom() string { return f.lengthFrom }

func (f *StrLenField) Pack(val any) ([]byte, error) {
	switch v := val.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("fields: %s expects string or []byte, got %T", f.name, val)
	}
}

func (f *StrLenField) Unpack(b []byte) (any, int, error) {
	return b, len(b), nil
}

// ---- nested packet fields ----

// PacketField holds a nested sub-packet identified by name via a registry.
type PacketField struct {
	Desc
	pktName string // registered name of the sub-packet type
}

// NewPacketField creates a field that holds a nested packet.
// pktName is the registered protocol name used to resolve the packet type during unpacking.
func NewPacketField(name string, pktName string) *PacketField {
	return &PacketField{
		Desc:    Desc{name: name, size: 0},
		pktName: pktName,
	}
}

// PktName returns the registered name of the sub-packet type.
func (f *PacketField) PktName() string { return f.pktName }

func (f *PacketField) Pack(val any) ([]byte, error) {
	// Packing a sub-packet is handled by the packet layer logic.
	v, ok := val.([]byte)
	if !ok {
		return nil, fmt.Errorf("fields: %s expects []byte for sub-packet, got %T", f.name, val)
	}
	return v, nil
}

func (f *PacketField) Unpack(b []byte) (any, int, error) {
	return b, len(b), nil
}

// ---- conditional field ----

// condition is a function that checks whether a field should be included based on the
// current packet values.
type condition func(values map[string]any) bool

// ConditionalField wraps another field and only includes it if the condition is true.
type ConditionalField struct {
	Field
	cond condition
}

// NewConditionalField creates a field that is only present when cond returns true.
// cond receives the current packet's values map.
func NewConditionalField(f Field, cond condition) *ConditionalField {
	return &ConditionalField{Field: f, cond: cond}
}

// Active returns whether this field should be included given the current values.
func (f *ConditionalField) Active(values map[string]any) bool {
	return f.cond(values)
}
