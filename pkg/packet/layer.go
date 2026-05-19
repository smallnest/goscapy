package packet

import (
	"bytes"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
)

// Layer represents a single protocol layer within a network packet.
// It holds the protocol's field definitions and the runtime values for each field.
type Layer struct {
	proto  string
	fields []fields.Field
	values map[string]any
}

// NewLayer creates a layer for the given protocol name and field list.
// All fields are initialized to their default values.
func NewLayer(proto string, fds []fields.Field) *Layer {
	values := make(map[string]any, len(fds))
	for _, f := range fds {
		// Skip nested conditional fields during defaults — they activate dynamically.
		if cf, ok := f.(*fields.ConditionalField); ok {
			if cf.Active(values) {
				values[f.Name()] = f.DefaultVal()
			}
			continue
		}
		values[f.Name()] = f.DefaultVal()
	}
	return &Layer{proto: proto, fields: fds, values: values}
}

// Proto returns the protocol name (e.g. "Ethernet", "IP").
func (l *Layer) Proto() string { return l.proto }

// Fields returns the layer's field definitions in order.
func (l *Layer) Fields() []fields.Field { return l.fields }

// Get returns the value of a field by name.
func (l *Layer) Get(name string) (any, error) {
	v, ok := l.values[name]
	if !ok {
		return nil, fmt.Errorf("packet: layer %s has no field %q", l.proto, name)
	}
	return v, nil
}

// Set sets the value of a field by name.
func (l *Layer) Set(name string, val any) error {
	if _, ok := l.values[name]; !ok {
		return fmt.Errorf("packet: layer %s has no field %q", l.proto, name)
	}
	l.values[name] = val
	return nil
}

// GetField returns the value of a field by its index in the fields list.
func (l *Layer) GetField(idx int) (any, error) {
	if idx < 0 || idx >= len(l.fields) {
		return nil, fmt.Errorf("packet: field index %d out of range [0, %d)", idx, len(l.fields))
	}
	name := l.fields[idx].Name()
	return l.values[name], nil
}

// SetField sets a field's value by its index in the fields list.
func (l *Layer) SetField(idx int, val any) error {
	if idx < 0 || idx >= len(l.fields) {
		return fmt.Errorf("packet: field index %d out of range [0, %d)", idx, len(l.fields))
	}
	name := l.fields[idx].Name()
	return l.Set(name, val)
}

// Values returns a copy of the current field values.
func (l *Layer) Values() map[string]any {
	cp := make(map[string]any, len(l.values))
	for k, v := range l.values {
		cp[k] = v
	}
	return cp
}

// FindField finds a field definition by name, returning nil if not found.
func (l *Layer) FindField(name string) fields.Field {
	for _, f := range l.fields {
		if f.Name() == name {
			return f
		}
	}
	return nil
}

// FieldIndex returns the index of a field by name, or -1 if not found.
func (l *Layer) FieldIndex(name string) int {
	for i, f := range l.fields {
		if f.Name() == name {
			return i
		}
	}
	return -1
}

// Over stacks upper on top of this layer and returns a Packet.
// Registered bindings are applied: if a BindingRule exists for
// (upper.Proto, this.Proto), this layer's bound field is set automatically.
func (l *Layer) Over(upper *Layer) *Packet {
	applyBindings(l, upper)
	return NewFrom(l, upper)
}

// ParseFields deserializes raw bytes into field values in definition order.
// It iterates through the layer's fields, calling Unpack on each one to
// extract values from the byte stream. For ConditionalField, the condition
// is evaluated after earlier fields have been parsed.
// Returns the total number of bytes consumed.
func (l *Layer) ParseFields(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	offset := 0
	for _, f := range l.fields {
		// Handle conditional fields: check if active given values parsed so far.
		if cf, ok := f.(*fields.ConditionalField); ok {
			if !cf.Active(l.values) {
				continue
			}
		}

		val, consumed, err := f.Unpack(data[offset:])
		if err != nil {
			return offset, fmt.Errorf("packet: layer %s field %s: %w", l.proto, f.Name(), err)
		}
		l.values[f.Name()] = val
		offset += consumed
	}

	return offset, nil
}

// SerializeFields packs all active fields into bytes in definition order.
// ConditionalField values are only included if Active() returns true.
// This is the naive serialization used as the first pass of Build.
func (l *Layer) SerializeFields() ([]byte, error) {
	var buf bytes.Buffer
	for _, f := range l.fields {
		// Skip inactive conditional fields.
		if cf, ok := f.(*fields.ConditionalField); ok {
			if !cf.Active(l.values) {
				continue
			}
		}
		val, exists := l.values[f.Name()]
		if !exists {
			continue
		}
		b, err := f.Pack(val)
		if err != nil {
			return nil, fmt.Errorf("packet: layer %s field %s: %w", l.proto, f.Name(), err)
		}
		buf.Write(b)
	}
	return buf.Bytes(), nil
}
