package fields

import (
	"bytes"
	"fmt"
)

// TLVOption represents a single Type-Length-Value option found in protocols
// like DHCP (RFC 2132), NDP (RFC 4861), and DNS EDNS (RFC 6891).
type TLVOption struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// ParseTLV parses a sequence of TLV options from raw bytes.
// Each option is encoded as: Type (1 byte) + Length (1 byte) + Value (Length bytes).
// Type 0 terminates parsing (End-of-Options / Pad marker).
func ParseTLV(data []byte) ([]TLVOption, error) {
	var opts []TLVOption
	rest := data
	for len(rest) > 0 {
		typ := rest[0]
		if typ == 0 {
			break
		}
		if len(rest) < 2 {
			return nil, fmt.Errorf("fields: TLV truncated: type %d without length byte", typ)
		}
		length := rest[1]
		needed := 2 + int(length)
		if len(rest) < needed {
			return nil, fmt.Errorf("fields: TLV type %d needs %d bytes, got %d", typ, needed, len(rest))
		}
		opts = append(opts, TLVOption{
			Type:   typ,
			Length: length,
			Value:  bytes.Clone(rest[2:needed]),
		})
		rest = rest[needed:]
	}
	return opts, nil
}

// BuildTLV serializes a list of TLV options into wire-format bytes.
// The End-of-Options marker (type=0) is NOT automatically appended; callers
// should append it explicitly if their protocol requires it.
func BuildTLV(opts []TLVOption) []byte {
	var buf bytes.Buffer
	for _, o := range opts {
		buf.WriteByte(o.Type)
		buf.WriteByte(o.Length)
		buf.Write(o.Value)
	}
	return buf.Bytes()
}

// Nested parses this option's Value as nested TLV options.
func (o *TLVOption) Nested() ([]TLVOption, error) {
	return ParseTLV(o.Value)
}

// Get returns the first option with the given type, or nil.
func GetTLV(opts []TLVOption, typ uint8) *TLVOption {
	for i := range opts {
		if opts[i].Type == typ {
			return &opts[i]
		}
	}
	return nil
}

// GetAll returns all options with the given type.
func GetAllTLV(opts []TLVOption, typ uint8) []TLVOption {
	var result []TLVOption
	for _, o := range opts {
		if o.Type == typ {
			result = append(result, o)
		}
	}
	return result
}