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
// Returns the packet for chaining.
func (p *Packet) Push(layer *Layer) *Packet {
	p.layers = append(p.layers, layer)
	return p
}

// Insert adds a layer below all current layers (becomes the new lowest layer).
// Returns the packet for chaining.
func (p *Packet) Insert(layer *Layer) *Packet {
	p.layers = append([]*Layer{layer}, p.layers...)
	return p
}

// InsertAfter inserts a layer immediately after the first layer matching the
// given protocol name. If no matching layer is found, the layer is pushed on top.
// Returns the packet for chaining.
//
// Example: packet [Ethernet, IPv6, TCP] → InsertAfter("IPv6", hopByHop)
//
//	→ [Ethernet, IPv6, hopByHop, TCP]
func (p *Packet) InsertAfter(proto string, layer *Layer) *Packet {
	for i, l := range p.layers {
		if l.Proto() == proto {
			p.layers = append(p.layers[:i+1], append([]*Layer{layer}, p.layers[i+1:]...)...)
			return p
		}
	}
	// Not found, push on top.
	p.layers = append(p.layers, layer)
	return p
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

// GetLayers returns all layers matching the protocol name, in stack order.
// This is useful for tunneled packets (e.g. VXLAN) where the same protocol
// may appear both in the outer encapsulation and inner payload.
//
// Example: a VXLAN packet has [Ethernet, IP, UDP, VXLAN, Ethernet, IP, UDP, Payload].
// GetLayers("IP") returns [outer IP, inner IP].
// GetLayers("UDP") returns [outer UDP, inner UDP].
func (p *Packet) GetLayers(proto string) []*Layer {
	var result []*Layer
	for _, l := range p.layers {
		if l.Proto() == proto {
			result = append(result, l)
		}
	}
	return result
}

// GetNthLayer returns the n-th (0-indexed) layer matching the protocol name, or nil.
// GetNthLayer("IP", 0) is equivalent to GetLayer("IP").
func (p *Packet) GetNthLayer(proto string, n int) *Layer {
	count := 0
	for _, l := range p.layers {
		if l.Proto() == proto {
			if count == n {
				return l
			}
			count++
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

// Sync re-applies all binding rules between consecutive layer pairs.
// Call this after modifying field values on a layer that is part of a packet
// to keep lower-layer protocol type fields consistent.
func (p *Packet) Sync() {
	for i := range len(p.layers) - 1 {
		applyBindings(p.layers[i], p.layers[i+1])
	}
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

// Build serializes the entire packet into wire-format bytes.
// It applies binding rules (Sync), then serializes all layers bottom-to-top,
// calling registered BuildHooks for derived field computation (checksums, lengths).
func (p *Packet) Build() ([]byte, error) {
	return p.BuildFrom(0)
}

// BuildFrom serializes the packet starting from the given layer index.
// BuildFrom(0) is equivalent to Build().
// BuildFrom(1) skips the lowest layer (e.g., build from IP onward, no Ethernet).
func (p *Packet) BuildFrom(startIdx int) ([]byte, error) {
	if startIdx < 0 || startIdx >= len(p.layers) {
		return nil, fmt.Errorf("packet: BuildFrom index %d out of range [0, %d)", startIdx, len(p.layers))
	}

	// Ensure binding rules are applied.
	p.Sync()

	n := len(p.layers)

	// Phase 1: Serialize all layers. For layers with hooks, skip naive serialization
	// and let the hook handle it entirely.
	layerBytes := make([][]byte, n)
	for i := startIdx; i < n; i++ {
		if lookupBuildHook(p.layers[i].Proto()) != nil {
			continue // hook will serialize this layer
		}
		raw, err := p.layers[i].SerializeFields()
		if err != nil {
			return nil, err
		}
		layerBytes[i] = raw
	}

	// Phase 2: Compute cumulative sizes from each layer to the end.
	// For hooked layers, compute size without allocating.
	cumSize := make([]int, n+1)
	for i := n - 1; i >= startIdx; i-- {
		if layerBytes[i] != nil {
			cumSize[i] = cumSize[i+1] + len(layerBytes[i])
		} else {
			cumSize[i] = cumSize[i+1] + p.layers[i].WireSize()
		}
	}

	// Allocate the full output buffer and fill with serialized bytes.
	total := make([]byte, cumSize[startIdx])
	offset := 0
	for i := startIdx; i < n; i++ {
		var sz int
		if layerBytes[i] != nil {
			copy(total[offset:], layerBytes[i])
			sz = len(layerBytes[i])
		} else {
			sz = p.layers[i].WireSize()
		}
		offset += sz
	}

	// Phase 3: Call build hooks bottom-to-top.
	// For each layer, upperBytes = total[layerEnd:] (bytes of all layers above this one).
	curOffset := 0
	for i := startIdx; i < n; i++ {
		var origLen int
		if layerBytes[i] != nil {
			origLen = len(layerBytes[i])
		} else {
			origLen = p.layers[i].WireSize()
		}
		layerEnd := curOffset + origLen
		upper := total[layerEnd:]

		hook := lookupBuildHook(p.layers[i].Proto())
		if hook != nil {
			fixed, err := hook(p, i, upper)
			if err != nil {
				return nil, fmt.Errorf("packet: build hook for %s: %w", p.layers[i].Proto(), err)
			}
			if len(fixed) != origLen {
				return nil, fmt.Errorf("packet: build hook for %s returned %d bytes, expected %d", p.layers[i].Proto(), len(fixed), origLen)
			}
			copy(total[curOffset:layerEnd], fixed)
		}

		curOffset = layerEnd
	}

	return total, nil
}

// BuildInto serializes the packet into the provided buffer.
// Returns the slice buf[0:n] containing the serialized bytes.
// The buffer must have sufficient capacity; use Build to let the packet allocate.
func (p *Packet) BuildInto(buf []byte) ([]byte, error) {
	return p.BuildFromInto(0, buf)
}

// BuildFromInto serializes the packet starting from the given layer index into buf.
func (p *Packet) BuildFromInto(startIdx int, buf []byte) ([]byte, error) {
	if startIdx < 0 || startIdx >= len(p.layers) {
		return nil, fmt.Errorf("packet: BuildFromInto index %d out of range [0, %d)", startIdx, len(p.layers))
	}

	p.Sync()
	n := len(p.layers)

	// Serialize non-hooked layers and compute sizes.
	layerOffsets := make([]int, n+1) // start offset of each layer
	curOff := 0
	for i := startIdx; i < n; i++ {
		layerOffsets[i] = curOff
		if lookupBuildHook(p.layers[i].Proto()) != nil {
			curOff += p.layers[i].WireSize()
			continue
		}
		written, err := p.layers[i].SerializeInto(buf[curOff:])
		if err != nil {
			return nil, err
		}
		curOff += written
	}
	layerOffsets[n] = curOff

	// Run hooks.
	for i := startIdx; i < n; i++ {
		hook := lookupBuildHook(p.layers[i].Proto())
		if hook == nil {
			continue
		}
		origLen := layerOffsets[i+1] - layerOffsets[i]
		upper := buf[layerOffsets[i+1]:]
		fixed, err := hook(p, i, upper)
		if err != nil {
			return nil, fmt.Errorf("packet: build hook for %s: %w", p.layers[i].Proto(), err)
		}
		if len(fixed) != origLen {
			return nil, fmt.Errorf("packet: build hook for %s returned %d bytes, expected %d", p.layers[i].Proto(), len(fixed), origLen)
		}
		copy(buf[layerOffsets[i]:], fixed)
	}

	return buf[:curOff], nil
}
