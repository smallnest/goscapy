package netflow

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// NetflowV9 constants.
const (
	NetflowV9Version uint16 = 9

	// FlowSet IDs.
	FlowSetTemplateID    uint16 = 0
	FlowSetOptionTemplateID uint16 = 1
	// Data FlowSet IDs: 256-65535

	NetflowV9HeaderLen = 20
)

// NewNetflowV9 creates a Netflow V9 header layer.
func NewNetflowV9() *packet.Layer {
	return packet.NewLayer("NetflowV9", []fields.Field{
		fields.NewShortField("version", NetflowV9Version),
		fields.NewShortField("count", 0),
		fields.NewIntField("sys_uptime", 0),
		fields.NewIntField("unix_secs", 0),
		fields.NewIntField("sequence", 0),
		fields.NewIntField("source_id", 0),
	})
}

// V9TemplateField defines a field in a V9 template.
type V9TemplateField struct {
	Type  uint16
	Len   uint16
}

// V9Template represents a Netflow V9 template flowset.
type V9Template struct {
	TemplateID   uint16
	FieldCount   uint16
	Fields       []V9TemplateField
}

// V9FlowSet represents a generic flow set.
type V9FlowSet struct {
	ID   uint16
	Data []byte
}

// PackV9Template serializes a template into a flow set body (after ID+Length).
func PackV9Template(t V9Template) []byte {
	size := 4 + len(t.Fields)*4 // templateID(2) + fieldCount(2) + fields
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:], t.TemplateID)
	binary.BigEndian.PutUint16(buf[2:], t.FieldCount)
	off := 4
	for _, f := range t.Fields {
		binary.BigEndian.PutUint16(buf[off:], f.Type)
		binary.BigEndian.PutUint16(buf[off+2:], f.Len)
		off += 4
	}
	return buf
}

// ParseV9Template parses a template from a template flow set body.
func ParseV9Template(data []byte) (V9Template, error) {
	if len(data) < 4 {
		return V9Template{}, fmt.Errorf("netflow: template header needs 4 bytes, got %d", len(data))
	}
	t := V9Template{
		TemplateID: binary.BigEndian.Uint16(data[0:]),
		FieldCount: binary.BigEndian.Uint16(data[2:]),
	}
	if len(data) < 4+int(t.FieldCount)*4 {
		return t, fmt.Errorf("netflow: template needs %d bytes for %d fields, got %d",
			4+int(t.FieldCount)*4, t.FieldCount, len(data))
	}
	t.Fields = make([]V9TemplateField, t.FieldCount)
	for i := range t.FieldCount {
		t.Fields[i] = V9TemplateField{
			Type: binary.BigEndian.Uint16(data[4+i*4:]),
			Len:  binary.BigEndian.Uint16(data[4+i*4+2:]),
		}
	}
	return t, nil
}

// PackV9FlowSet serializes a flow set (ID + Length + Data).
func PackV9FlowSet(fs V9FlowSet) []byte {
	totalLen := 4 + len(fs.Data)
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:], fs.ID)
	binary.BigEndian.PutUint16(buf[2:], uint16(totalLen))
	copy(buf[4:], fs.Data)
	return buf
}

// ParseV9FlowSets parses all flow sets from V9 payload data.
func ParseV9FlowSets(data []byte) ([]V9FlowSet, error) {
	var sets []V9FlowSet
	off := 0
	for off < len(data) {
		if off+4 > len(data) {
			return nil, fmt.Errorf("netflow: truncated flow set header at offset %d", off)
		}
		id := binary.BigEndian.Uint16(data[off:])
		length := binary.BigEndian.Uint16(data[off+2:])
		if length < 4 {
			return nil, fmt.Errorf("netflow: invalid flow set length %d at offset %d", length, off)
		}
		if off+int(length) > len(data) {
			return nil, fmt.Errorf("netflow: flow set overruns buffer at offset %d (length=%d, remaining=%d)", off, length, len(data)-off)
		}
		sets = append(sets, V9FlowSet{
			ID:   id,
			Data: data[off+4 : off+int(length)],
		})
		off += int(length)
	}
	return sets, nil
}

// TemplateCache stores parsed V9 templates keyed by (source_id, template_id).
type TemplateCache struct {
	templates map[uint32]map[uint16]V9Template // sourceID -> templateID -> template
}

// NewTemplateCache creates a new template cache.
func NewTemplateCache() *TemplateCache {
	return &TemplateCache{templates: make(map[uint32]map[uint16]V9Template)}
}

// Store saves a template for the given source.
func (c *TemplateCache) Store(sourceID uint32, t V9Template) {
	if c.templates[sourceID] == nil {
		c.templates[sourceID] = make(map[uint16]V9Template)
	}
	c.templates[sourceID][t.TemplateID] = t
}

// Get retrieves a template for the given source.
func (c *TemplateCache) Get(sourceID uint32, templateID uint16) (V9Template, bool) {
	src, ok := c.templates[sourceID]
	if !ok {
		return V9Template{}, false
	}
	t, ok := src[templateID]
	return t, ok
}

// DecodeDataFlowSet decodes a data flow set using a cached template.
// Returns field values as [][]any (one slice per record).
func DecodeDataFlowSet(fs V9FlowSet, t V9Template) ([][]any, error) {
	if len(t.Fields) == 0 {
		return nil, fmt.Errorf("netflow: empty template %d", t.TemplateID)
	}
	recordLen := 0
	for _, f := range t.Fields {
		if f.Len == 0 {
			return nil, fmt.Errorf("netflow: template %d has zero-length field (type=%d)", t.TemplateID, f.Type)
		}
		recordLen += int(f.Len)
	}

	var records [][]any
	off := 0
	for off+recordLen <= len(fs.Data) {
		var vals []any
		for _, f := range t.Fields {
			end := off + int(f.Len)
			v := decodeField(f, fs.Data[off:end])
			vals = append(vals, v)
			off = end
		}
		records = append(records, vals)
	}
	return records, nil
}

func decodeField(f V9TemplateField, data []byte) any {
	switch f.Len {
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
