// Package fields provides the field type system for protocol packet definitions.
// Each field describes a single piece of a protocol header, knows how to serialize
// and deserialize itself, and carries metadata like default values and size.
package fields

import (
	"fmt"
)

// Field defines the interface for all protocol field types.
// Concrete implementations handle conversion between Go values and raw bytes.
type Field interface {
	// Name returns the field's name as used in the protocol definition.
	Name() string

	// FixedSize returns the number of bytes this field occupies in the wire format.
	// Returns 0 for variable-length fields like StrField or PacketField.
	FixedSize() int

	// DefaultVal returns the field's default value when not explicitly set.
	DefaultVal() interface{}

	// Pack serializes the given value into wire-format bytes.
	Pack(val interface{}) ([]byte, error)

	// Unpack deserializes raw bytes and returns the parsed value plus bytes consumed.
	Unpack(b []byte) (val interface{}, consumed int, err error)
}

// Desc holds common metadata for all field types.
type Desc struct {
	name    string
	size    int
	defVal  interface{}
	lengthOf string // field name this field measures the length of
}

// Name returns the field name.
func (d *Desc) Name() string { return d.name }

// FixedSize returns the wire-format size in bytes.
func (d *Desc) FixedSize() int { return d.size }

// DefaultVal returns the default value.
func (d *Desc) DefaultVal() interface{} { return d.defVal }

// LengthOf returns the name of the field whose length this field measures.
func (d *Desc) LengthOf() string { return d.lengthOf }

// SetLengthOf marks this field as measuring the length of another field.
func (d *Desc) SetLengthOf(name string) { d.lengthOf = name }

// validateSize checks that b has at least want bytes available.
func validateSize(fname string, b []byte, want int) error {
	if len(b) < want {
		return fmt.Errorf("fields: %s needs %d bytes, got %d", fname, want, len(b))
	}
	return nil
}