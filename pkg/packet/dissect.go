package packet

import (
	"fmt"
)

// LayerFactory creates a new empty Layer for the given protocol name.
type LayerFactory func() *Layer

// HeaderSizeFunc returns the actual header size in bytes for a layer,
// given the values already parsed from the wire.
type HeaderSizeFunc func(layer *Layer) int

// DissectorFunc identifies a protocol from raw bytes and returns the protocol
// name. It may also return a skip count for protocols that consume a known
// prefix (e.g., Ethernet always consumes 14 bytes before upper-layer parsing).
type DissectorFunc func(data []byte) (proto string, skip int, err error)

// maxTunnelDepth limits recursive tunnel dissection to prevent stack overflow.
const maxTunnelDepth = 8

type dissectReg struct {
	factories     map[string]LayerFactory
	nextLayer     map[string]map[uint64]string // proto → field value → next proto name
	keyField      map[string]string            // proto → field name used for next-layer lookup
	headerSizeFn  map[string]HeaderSizeFunc    // proto → function to compute variable header size
	dissectors    map[string]DissectorFunc     // proto → function to identify this protocol from raw bytes
	tunnelPayload map[string]string            // proto → inner proto for tunnel-encapsulated payloads
}

var dissectRegistry = dissectReg{
	factories:     make(map[string]LayerFactory),
	nextLayer:     make(map[string]map[uint64]string),
	keyField:      make(map[string]string),
	headerSizeFn:  make(map[string]HeaderSizeFunc),
	dissectors:    make(map[string]DissectorFunc),
	tunnelPayload: make(map[string]string),
}

// RegisterLayer registers a layer factory for the given protocol name.
func RegisterLayer(proto string, factory LayerFactory) {
	dissectRegistry.factories[proto] = factory
}

// RegisterNextLayer registers a mapping from a key field value to the next
// upper-layer protocol name.
func RegisterNextLayer(proto string, keyValue uint64, nextProto string) {
	if dissectRegistry.nextLayer[proto] == nil {
		dissectRegistry.nextLayer[proto] = make(map[uint64]string)
	}
	dissectRegistry.nextLayer[proto][keyValue] = nextProto
}

// RegisterKeyField registers which field of a layer is used to determine
// the next upper-layer protocol.
func RegisterKeyField(proto, fieldName string) {
	dissectRegistry.keyField[proto] = fieldName
}

// RegisterHeaderSizeFunc registers a function that computes the actual wire
// header size for a protocol layer after its fields have been parsed.
func RegisterHeaderSizeFunc(proto string, fn HeaderSizeFunc) {
	dissectRegistry.headerSizeFn[proto] = fn
}

// RegisterDissector registers a protocol identification function that can
// determine the starting protocol from raw bytes.
func RegisterDissector(proto string, fn DissectorFunc) {
	dissectRegistry.dissectors[proto] = fn
}

// RegisterHeuristic registers a heuristic rule: when lowerProto's field equals
// value, the next upper-layer protocol is nextProto. This is a convenience
// wrapper that combines RegisterKeyField and RegisterNextLayer with automatic
// type conversion.
//
// Example:
//
//	RegisterHeuristic("UDP", "dport", uint16(53), "DNS")
//	RegisterHeuristic("Ethernet", "type", uint16(0x86DD), "IPv6")
func RegisterHeuristic(lowerProto, field string, value any, nextProto string) {
	RegisterKeyField(lowerProto, field)
	RegisterNextLayer(lowerProto, toUint64(value), nextProto)
}

// RegisterTunnelPayload marks a protocol as a tunnel whose payload starts
// with the given inner protocol. During dissection, when a tunnel layer is
// parsed, the remaining bytes are recursively dissected starting from
// innerProto.
func RegisterTunnelPayload(proto, innerProto string) {
	dissectRegistry.tunnelPayload[proto] = innerProto
}

// Dissect parses raw bytes into a structured Packet.
//
// The first layer is identified by calling startFn. Subsequent layers are
// resolved based on the lower layer's key field value or registered heuristics.
//
// For backward compatibility, startFn receives the full raw byte slice and
// returns the protocol name.
func Dissect(raw []byte, startFn func([]byte) (string, error)) (*Packet, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("packet: Dissect: empty input")
	}
	if startFn == nil {
		return nil, fmt.Errorf("packet: Dissect: startFn is nil")
	}

	firstProto, err := startFn(raw)
	if err != nil {
		return nil, fmt.Errorf("packet: Dissect: %w", err)
	}

	return dissect(raw, firstProto, 0)
}

// DissectByProto parses raw bytes starting from the named protocol. The
// protocol must have been registered via RegisterLayer.
func DissectByProto(raw []byte, firstProto string) (*Packet, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("packet: DissectByProto: empty input")
	}
	if _, ok := dissectRegistry.factories[firstProto]; !ok {
		return nil, fmt.Errorf("packet: DissectByProto: unknown protocol %q", firstProto)
	}
	return dissect(raw, firstProto, 0)
}

// dissect is the internal recursive dissection engine. depth tracks tunnel
// nesting to prevent infinite recursion on malformed packets.
func dissect(raw []byte, firstProto string, depth int) (*Packet, error) {
	if depth > maxTunnelDepth {
		return nil, fmt.Errorf("packet: Dissect: max tunnel depth %d exceeded", maxTunnelDepth)
	}

	pkt := New()
	remaining := raw
	currentProto := firstProto

	for currentProto != "" {
		factory, ok := dissectRegistry.factories[currentProto]
		if !ok {
			break
		}

		layer := factory()
		consumed, err := layer.ParseFields(remaining)
		if err != nil {
			return nil, fmt.Errorf("packet: Dissect: layer %s: %w", currentProto, err)
		}

		actualHeaderSize := consumed
		if sizeFn, hasFn := dissectRegistry.headerSizeFn[currentProto]; hasFn {
			if hs := sizeFn(layer); hs > consumed {
				actualHeaderSize = hs
			}
		}

		if actualHeaderSize > len(remaining) {
			return nil, fmt.Errorf("packet: Dissect: layer %s: header size %d exceeds remaining bytes %d",
				currentProto, actualHeaderSize, len(remaining))
		}

		pkt.Push(layer)
		remaining = remaining[actualHeaderSize:]

		// Check if this is a tunnel protocol — if so, recursively dissect the payload.
		if innerProto, isTunnel := dissectRegistry.tunnelPayload[currentProto]; isTunnel {
			if len(remaining) == 0 {
				break
			}
			innerPkt, err := dissect(remaining, innerProto, depth+1)
			if err != nil {
				return nil, fmt.Errorf("packet: Dissect: tunnel %s: %w", currentProto, err)
			}
			for _, l := range innerPkt.Layers() {
				pkt.Push(l)
			}
			break
		}

		if len(remaining) == 0 {
			break
		}

		// Resolve next layer via key field or heuristics.
		currentProto = resolveNextLayer(currentProto, layer)
	}

	// Wrap leftover bytes as Raw payload.
	if len(remaining) > 0 {
		rawLayer := makeRawLayer(remaining)
		pkt.Push(rawLayer)
	}

	return pkt, nil
}

// resolveNextLayer determines the next upper-layer protocol based on the
// current layer's key field value.
func resolveNextLayer(proto string, layer *Layer) string {
	keyField, hasKey := dissectRegistry.keyField[proto]
	if !hasKey {
		return ""
	}

	keyVal, err := layer.Get(keyField)
	if err != nil {
		return ""
	}

	numeric := toUint64(keyVal)

	nextMap, hasMap := dissectRegistry.nextLayer[proto]
	if !hasMap {
		return ""
	}

	next, found := nextMap[numeric]
	if !found {
		return ""
	}
	return next
}

// toUint64 converts common integer types to uint64 for map lookup.
func toUint64(v any) uint64 {
	switch val := v.(type) {
	case uint8:
		return uint64(val)
	case uint16:
		return uint64(val)
	case uint32:
		return uint64(val)
	case uint64:
		return val
	case int:
		return uint64(val)
	case int32:
		return uint64(val)
	case int64:
		return uint64(val)
	default:
		return 0
	}
}

// makeRawLayer creates a Raw layer with the given payload.
func makeRawLayer(payload []byte) *Layer {
	factory, ok := dissectRegistry.factories["Raw"]
	if ok {
		layer := factory()
		layer.Set("load", payload)
		return layer
	}
	layer := &Layer{
		proto:  "Raw",
		values: map[string]any{"load": payload},
	}
	return layer
}