package packet

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
)

// Packet is a stack of protocol layers forming a complete network packet.
// Layers are ordered from lowest (e.g. Ethernet) to highest (e.g. TCP + payload).
type Packet struct {
	layers []*Layer
}

// New creates an empty packet.
func New() *Packet {
	return &Packet{}
}

// NewFrom creates a packet initialized with the given layers.
func NewFrom(layers ...*Layer) *Packet {
	return &Packet{layers: layers}
}

// Layers returns the packet's layers.
func (p *Packet) Layers() []*Layer { return p.layers }

// Push adds a layer on top of the packet (after the current highest layer).
func (p *Packet) Push(layer *Layer) {
	p.layers = append(p.layers, layer)
}

// Insert adds a layer below all current layers (becomes the new lowest layer).
func (p *Packet) Insert(layer *Layer) {
	p.layers = append([]*Layer{layer}, p.layers...)
}

// GetLayer returns the first layer matching the protocol name, or nil.
func (p *Packet) GetLayer(proto string) *Layer {
	for _, l := range p.layers {
		if l.Proto() == proto {
			return l
		}
	}
	return nil
}

// HasLayer reports whether the packet contains a layer with the given protocol name.
func (p *Packet) HasLayer(proto string) bool {
	return p.GetLayer(proto) != nil
}

// First returns the lowest layer (usually the link layer).
func (p *Packet) First() *Layer {
	if len(p.layers) == 0 {
		return nil
	}
	return p.layers[0]
}

// Last returns the highest layer.
func (p *Packet) Last() *Layer {
	if len(p.layers) == 0 {
		return nil
	}
	return p.layers[len(p.layers)-1]
}

// Len returns the number of layers.
func (p *Packet) Len() int { return len(p.layers) }

// String returns a summary of the packet's layer stack.
func (p *Packet) String() string {
	s := ""
	for i, l := range p.layers {
		if i > 0 {
			s += " / "
		}
		s += l.Proto()
	}
	return s
}

// Copy returns a shallow copy of the packet (shares layer objects).
func (p *Packet) Copy() *Packet {
	cp := &Packet{layers: make([]*Layer, len(p.layers))}
	copy(cp.layers, p.layers)
	return cp
}

// Validate checks that all layers have consistent field values.
func (p *Packet) Validate() error {
	for i, l := range p.layers {
		for _, f := range l.Fields() {
			if cf, ok := f.(*fields.ConditionalField); ok {
				if cf.Active(l.values) {
					if _, exists := l.values[f.Name()]; !exists {
						return fmt.Errorf("packet: layer %d (%s) conditional field %q is active but has no value", i, l.Proto(), f.Name())
					}
				}
			}
		}
	}
	return nil
}