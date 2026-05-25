package fields

import (
	"encoding/binary"
	"fmt"
	"net"
)

// PackInto writes the serialized value directly into buf starting at offset 0.
// Returns the number of bytes written. No heap allocations.
// The caller must ensure buf has sufficient capacity.

func (f *ByteField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint8)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint8, got %T", f.name, val)
	}
	buf[0] = v
	return 1, nil
}

func (f *ShortField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint16)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint16, got %T", f.name, val)
	}
	binary.BigEndian.PutUint16(buf, v)
	return 2, nil
}

func (f *LEShortField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint16)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint16, got %T", f.name, val)
	}
	binary.LittleEndian.PutUint16(buf, v)
	return 2, nil
}

func (f *ThreeBytesField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint32)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint32, got %T", f.name, val)
	}
	if v > 0xFFFFFF {
		return 0, fmt.Errorf("fields: %s value %d exceeds 3 bytes", f.name, v)
	}
	buf[0] = byte(v >> 16)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v)
	return 3, nil
}

func (f *IntField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint32)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint32, got %T", f.name, val)
	}
	binary.BigEndian.PutUint32(buf, v)
	return 4, nil
}

func (f *SignedIntField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(int32)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects int32, got %T", f.name, val)
	}
	binary.BigEndian.PutUint32(buf, uint32(v))
	return 4, nil
}

func (f *LEIntField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint32)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint32, got %T", f.name, val)
	}
	binary.LittleEndian.PutUint32(buf, v)
	return 4, nil
}

func (f *LongField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint64)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint64, got %T", f.name, val)
	}
	binary.BigEndian.PutUint64(buf, v)
	return 8, nil
}

func (f *LELongField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint64)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint64, got %T", f.name, val)
	}
	binary.LittleEndian.PutUint64(buf, v)
	return 8, nil
}

func (f *BitField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.(uint8)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects uint8, got %T", f.name, val)
	}
	mask := uint8((1 << f.bitSize) - 1)
	if v > mask {
		return 0, fmt.Errorf("fields: %s value %d exceeds %d bits", f.name, v, f.bitSize)
	}
	buf[0] = v & mask
	return 1, nil
}

func (f *MACField) PackInto(buf []byte, val any) (int, error) {
	switch v := val.(type) {
	case net.HardwareAddr:
		if len(v) != 6 {
			return 0, fmt.Errorf("fields: %s MAC must be 6 bytes, got %d", f.name, len(v))
		}
		copy(buf, v)
		return 6, nil
	case string:
		mac, err := net.ParseMAC(v)
		if err != nil {
			return 0, fmt.Errorf("fields: %s invalid MAC %q: %w", f.name, v, err)
		}
		copy(buf, mac)
		return 6, nil
	case []byte:
		if len(v) != 6 {
			return 0, fmt.Errorf("fields: %s MAC must be 6 bytes, got %d", f.name, len(v))
		}
		copy(buf, v)
		return 6, nil
	default:
		return 0, fmt.Errorf("fields: %s expects net.HardwareAddr, string, or []byte, got %T", f.name, val)
	}
}

func (f *IPField) PackInto(buf []byte, val any) (int, error) {
	switch v := val.(type) {
	case net.IP:
		ip4 := v.To4()
		if ip4 == nil {
			return 0, fmt.Errorf("fields: %s requires IPv4 address, got %v", f.name, v)
		}
		copy(buf, ip4)
		return 4, nil
	case string:
		ip := net.ParseIP(v)
		if ip == nil {
			return 0, fmt.Errorf("fields: %s invalid IP %q", f.name, v)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return 0, fmt.Errorf("fields: %s requires IPv4 address, got %v", f.name, v)
		}
		copy(buf, ip4)
		return 4, nil
	default:
		return 0, fmt.Errorf("fields: %s expects net.IP or string, got %T", f.name, val)
	}
}

func (f *IPv6Field) PackInto(buf []byte, val any) (int, error) {
	switch v := val.(type) {
	case net.IP:
		ip16 := v.To16()
		if ip16 == nil {
			return 0, fmt.Errorf("fields: %s requires IPv6 address, got %v", f.name, v)
		}
		copy(buf, ip16)
		return 16, nil
	case string:
		ip := net.ParseIP(v)
		if ip == nil {
			return 0, fmt.Errorf("fields: %s invalid IP %q", f.name, v)
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return 0, fmt.Errorf("fields: %s requires IPv6 address, got %v", f.name, v)
		}
		copy(buf, ip16)
		return 16, nil
	case []byte:
		if len(v) != 16 {
			return 0, fmt.Errorf("fields: %s IPv6 must be 16 bytes, got %d", f.name, len(v))
		}
		copy(buf, v)
		return 16, nil
	default:
		return 0, fmt.Errorf("fields: %s expects net.IP, string, or []byte, got %T", f.name, val)
	}
}

func (f *StrField) PackInto(buf []byte, val any) (int, error) {
	switch v := val.(type) {
	case string:
		copy(buf, v)
		return len(v), nil
	case []byte:
		copy(buf, v)
		return len(v), nil
	default:
		return 0, fmt.Errorf("fields: %s expects string or []byte, got %T", f.name, val)
	}
}

func (f *StrLenField) PackInto(buf []byte, val any) (int, error) {
	switch v := val.(type) {
	case string:
		copy(buf, v)
		return len(v), nil
	case []byte:
		copy(buf, v)
		return len(v), nil
	default:
		return 0, fmt.Errorf("fields: %s expects string or []byte, got %T", f.name, val)
	}
}

func (f *StrFixedField) PackInto(buf []byte, val any) (int, error) {
	var raw []byte
	switch v := val.(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	default:
		return 0, fmt.Errorf("fields: %s expects string or []byte, got %T", f.name, val)
	}
	if len(raw) > f.size {
		return 0, fmt.Errorf("fields: %s value %d bytes exceeds fixed size %d", f.name, len(raw), f.size)
	}
	for i := len(raw); i < f.size; i++ {
		buf[i] = 0
	}
	copy(buf, raw)
	return f.size, nil
}

func (f *PacketField) PackInto(buf []byte, val any) (int, error) {
	v, ok := val.([]byte)
	if !ok {
		return 0, fmt.Errorf("fields: %s expects []byte for sub-packet, got %T", f.name, val)
	}
	copy(buf, v)
	return len(v), nil
}

func (f *ConditionalField) PackInto(buf []byte, val any) (int, error) {
	if pi, ok := f.Field.(interface{ PackInto([]byte, any) (int, error) }); ok {
		return pi.PackInto(buf, val)
	}
	b, err := f.Field.Pack(val)
	if err != nil {
		return 0, err
	}
	copy(buf, b)
	return len(b), nil
}
