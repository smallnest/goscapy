package packet

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/fields"
)

// LayerJSON is the JSON representation of a single protocol layer: its protocol
// name and an ordered-by-definition map of field name → display value.
type LayerJSON struct {
	Proto  string         `json:"proto"`
	Fields map[string]any `json:"fields"`
}

// PacketJSON is the JSON representation of a packet: its layer-stack summary
// and each layer's fields.
type PacketJSON struct {
	Summary string      `json:"summary"`
	Layers  []LayerJSON `json:"layers"`
}

// ToJSON returns the packet as a JSON document describing every layer and
// field, mirroring Scapy's pkt.json()/conversion helpers. Field values are
// rendered in a JSON-friendly form: IP and MAC addresses as strings, byte
// slices as lowercase hex strings, and integers as numbers. This is intended
// for interchange with other tooling, not for byte-exact reconstruction (use
// Build for that).
func (p *Packet) ToJSON() ([]byte, error) {
	return json.Marshal(p.JSON())
}

// ToJSONIndent is like ToJSON but pretty-prints with the given indentation.
func (p *Packet) ToJSONIndent(prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(p.JSON(), prefix, indent)
}

// JSON returns the packet's structured JSON representation as a Go value,
// without marshaling. Useful for embedding in larger documents.
func (p *Packet) JSON() PacketJSON {
	out := PacketJSON{
		Summary: p.Summary(),
		Layers:  make([]LayerJSON, 0, len(p.layers)),
	}
	for _, l := range p.layers {
		out.Layers = append(out.Layers, l.JSON())
	}
	return out
}

// JSON returns the layer's structured JSON representation: its protocol name
// and a map of active field names to JSON-friendly values.
func (l *Layer) JSON() LayerJSON {
	lj := LayerJSON{Proto: l.proto, Fields: make(map[string]any)}
	for _, f := range l.fields {
		if cf, ok := f.(*fields.ConditionalField); ok && !cf.Active(l.values) {
			continue
		}
		name := f.Name()
		val, exists := l.values[name]
		if !exists {
			continue
		}
		lj.Fields[name] = jsonValue(val)
	}
	return lj
}

// jsonValue converts a field value into a JSON-friendly representation:
// addresses and byte slices become strings, integers stay numeric.
func jsonValue(val any) any {
	switch v := val.(type) {
	case net.IP:
		return v.String()
	case net.HardwareAddr:
		return v.String()
	case []byte:
		return fmt.Sprintf("%x", v)
	case string:
		return v
	default:
		return v
	}
}
