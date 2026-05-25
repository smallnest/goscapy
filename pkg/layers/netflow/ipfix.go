package netflow

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IPFIX constants.
const (
	IPFIXVersion uint16 = 10

	// Set IDs.
	IPFIXTemplateSetID     uint16 = 2
	IPFIXOptionTemplateSetID uint16 = 3
	// Data Set IDs: 256-65535

	IPFIXHeaderLen = 16
)

// NewIPFIX creates an IPFIX message header layer.
func NewIPFIX() *packet.Layer {
	return packet.NewLayer("IPFIX", []fields.Field{
		fields.NewShortField("version", IPFIXVersion),
		fields.NewShortField("length", 0),
		fields.NewIntField("export_time", 0),
		fields.NewIntField("sequence", 0),
		fields.NewIntField("observation_domain_id", 0),
	})
}

// IPFIXTemplateField defines a field in an IPFIX template.
// If Pen != 0, this is an enterprise field.
type IPFIXTemplateField struct {
	Type uint16
	Len  uint16
	Pen  uint32 // 0 = IANA field, nonzero = enterprise
}

// IPFIXTemplate represents an IPFIX template.
type IPFIXTemplate struct {
	TemplateID uint16
	FieldCount uint16
	Fields     []IPFIXTemplateField
}

// IPFIXSet represents a generic IPFIX set.
type IPFIXSet struct {
	ID   uint16
	Data []byte
}

// PackIPFIXTemplate serializes an IPFIX template.
func PackIPFIXTemplate(t IPFIXTemplate) []byte {
	size := 4 // templateID(2) + fieldCount(2)
	for _, f := range t.Fields {
		size += 4 // type(2) + len(2)
		if f.Pen != 0 {
			size += 4 // enterprise number
		}
	}
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:], t.TemplateID)
	binary.BigEndian.PutUint16(buf[2:], t.FieldCount)
	off := 4
	for _, f := range t.Fields {
		typ := f.Type
		if f.Pen != 0 {
			typ |= 0x8000 // enterprise bit
		}
		binary.BigEndian.PutUint16(buf[off:], typ)
		binary.BigEndian.PutUint16(buf[off+2:], f.Len)
		off += 4
		if f.Pen != 0 {
			binary.BigEndian.PutUint32(buf[off:], f.Pen)
			off += 4
		}
	}
	return buf
}

// ParseIPFIXTemplate parses an IPFIX template.
func ParseIPFIXTemplate(data []byte) (IPFIXTemplate, error) {
	if len(data) < 4 {
		return IPFIXTemplate{}, fmt.Errorf("ipfix: template header needs 4 bytes, got %d", len(data))
	}
	t := IPFIXTemplate{
		TemplateID: binary.BigEndian.Uint16(data[0:]),
		FieldCount: binary.BigEndian.Uint16(data[2:]),
	}
	off := 4
	for i := 0; i < int(t.FieldCount); i++ {
		if off+4 > len(data) {
			return t, fmt.Errorf("ipfix: truncated template field %d", i)
		}
		typ := binary.BigEndian.Uint16(data[off:])
	flen := binary.BigEndian.Uint16(data[off+2:])
		off += 4

		f := IPFIXTemplateField{Type: typ & 0x7FFF, Len: flen}
		if typ&0x8000 != 0 {
			if off+4 > len(data) {
				return t, fmt.Errorf("ipfix: truncated enterprise number at field %d", i)
			}
			f.Pen = binary.BigEndian.Uint32(data[off:])
			off += 4
		}
		t.Fields = append(t.Fields, f)
	}
	return t, nil
}

// PackIPFIXSet serializes an IPFIX set.
func PackIPFIXSet(s IPFIXSet) []byte {
	totalLen := 4 + len(s.Data)
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:], s.ID)
	binary.BigEndian.PutUint16(buf[2:], uint16(totalLen))
	copy(buf[4:], s.Data)
	return buf
}

// ParseIPFIXSets parses all sets from IPFIX payload.
func ParseIPFIXSets(data []byte) ([]IPFIXSet, error) {
	var sets []IPFIXSet
	off := 0
	for off < len(data) {
		if off+4 > len(data) {
			return nil, fmt.Errorf("ipfix: truncated set header at offset %d", off)
		}
		id := binary.BigEndian.Uint16(data[off:])
		length := binary.BigEndian.Uint16(data[off+2:])
		if length < 4 {
			return nil, fmt.Errorf("ipfix: invalid set length %d at offset %d", length, off)
		}
		if off+int(length) > len(data) {
			return nil, fmt.Errorf("ipfix: set overruns buffer at offset %d (length=%d, remaining=%d)", off, length, len(data)-off)
		}
		sets = append(sets, IPFIXSet{
			ID:   id,
			Data: data[off+4 : off+int(length)],
		})
		off += int(length)
	}
	return sets, nil
}

// DecodeIPFIXData decodes an IPFIX data set using a cached template.
// Supports variable-length fields (len=65535): first byte is length, then data.
func DecodeIPFIXData(s IPFIXSet, t IPFIXTemplate) ([][]any, error) {
	if len(t.Fields) == 0 {
		return nil, fmt.Errorf("ipfix: empty template %d", t.TemplateID)
	}

	var records [][]any
	off := 0
	for off < len(s.Data) {
		var vals []any
		ok := true
		for _, f := range t.Fields {
			if off >= len(s.Data) {
				ok = false
				break
			}
			fieldLen := int(f.Len)
			if fieldLen == 65535 {
				if off >= len(s.Data) {
					ok = false
					break
				}
				first := s.Data[off]
				if first < 255 {
					fieldLen = int(first)
					off++
				} else {
					if off+3 > len(s.Data) {
						ok = false
						break
					}
					fieldLen = int(binary.BigEndian.Uint16(s.Data[off+1:]))
					off += 3
				}
			} else if fieldLen == 0 {
				return nil, fmt.Errorf("ipfix: template %d has zero-length field (type=%d)", t.TemplateID, f.Type)
			}
			if off+fieldLen > len(s.Data) {
				ok = false
				break
			}
			v := decodeIPFIXField(f, s.Data[off:off+fieldLen])
			vals = append(vals, v)
			off += fieldLen
		}
		if ok && len(vals) == len(t.Fields) {
			records = append(records, vals)
		} else {
			break
		}
	}
	return records, nil
}

func decodeIPFIXField(f IPFIXTemplateField, data []byte) any {
	if f.Pen != 0 {
		return append([]byte{}, data...)
	}
	switch len(data) {
	case 1:
		return data[0]
	case 2:
		return binary.BigEndian.Uint16(data)
	case 4:
		return binary.BigEndian.Uint32(data)
	case 8:
		return binary.BigEndian.Uint64(data)
	default:
		return append([]byte{}, data...)
	}
}
