package packet

import (
	"fmt"
)

// LayerFactory creates a new empty Layer for the given protocol name.
// Used by Dissect to instantiate layers during parsing.
type LayerFactory func() *Layer

// HeaderSizeFunc returns the actual header size in bytes for a layer,
// given the values already parsed from the wire. This is needed for
// protocols with variable-length headers (e.g., IP with options,
// TCP with options). If the function returns 0 or a value <= the
// fixed fields size, ParseFields consumed all header bytes already.
type HeaderSizeFunc func(layer *Layer) int

// dissectRegistry maps protocol names to their factory functions and
// provides next-layer resolution based on a key field value.
var dissectRegistry struct {
	factories    map[string]LayerFactory
	nextLayer    map[string]map[uint64]string // proto → field value → next proto name
	keyField     map[string]string            // proto → field name used for next-layer lookup
	headerSizeFn map[string]HeaderSizeFunc    // proto → function to compute variable header size
}

func init() {
	dissectRegistry.factories = make(map[string]LayerFactory)
	dissectRegistry.nextLayer = make(map[string]map[uint64]string)
	dissectRegistry.keyField = make(map[string]string)
	dissectRegistry.headerSizeFn = make(map[string]HeaderSizeFunc)
}

// RegisterLayer registers a layer factory for the given protocol name.
// Typically called from init() in layer definition files.
func RegisterLayer(proto string, factory LayerFactory) {
	dissectRegistry.factories[proto] = factory
}

// RegisterNextLayer registers a mapping from a key field value to the next
// upper-layer protocol name. For example, Ethernet.type=0x0800 → "IP".
func RegisterNextLayer(proto string, keyValue uint64, nextProto string) {
	if dissectRegistry.nextLayer[proto] == nil {
		dissectRegistry.nextLayer[proto] = make(map[uint64]string)
	}
	dissectRegistry.nextLayer[proto][keyValue] = nextProto
}

// RegisterKeyField registers which field of a layer is used to determine
// the next upper-layer protocol. For Ethernet, this is "type"; for IP, "proto".
func RegisterKeyField(proto, fieldName string) {
	dissectRegistry.keyField[proto] = fieldName
}

// RegisterHeaderSizeFunc registers a function that computes the actual wire
// header size for a protocol layer after its fields have been parsed.
// This is needed for protocols with variable-length headers.
// If not registered, the header size is assumed to equal the sum of fixed
// field sizes (i.e., what ParseFields consumed).
func RegisterHeaderSizeFunc(proto string, fn HeaderSizeFunc) {
	dissectRegistry.headerSizeFn[proto] = fn
}

// Dissect parses raw bytes into a structured Packet by automatically
// identifying and parsing protocol layers from the bottom up.
//
// The first layer is identified by calling startFn to determine which protocol
// to begin parsing. Subsequent layers are resolved based on the lower layer's
// key field value (e.g., Ethernet.type → IP, IP.proto → TCP/UDP/ICMP).
//
// Any remaining bytes after all identified layers are wrapped in a Raw layer.
func Dissect(raw []byte, startFn func([]byte) (string, error)) (*Packet, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("packet: Dissect: empty input")
	}
	if startFn == nil {
		return nil, fmt.Errorf("packet: Dissect: startFn is nil")
	}

	// Determine the first protocol.
	firstProto, err := startFn(raw)
	if err != nil {
		return nil, fmt.Errorf("packet: Dissect: %w", err)
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

		// Check if the protocol has a variable-length header that extends beyond
		// the fixed fields we just parsed (e.g., IP options, TCP options).
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

		if len(remaining) == 0 {
			break
		}

		// Determine the next layer.
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

	// Convert the key value to uint64 for map lookup.
	var numeric uint64
	switch v := keyVal.(type) {
	case uint8:
		numeric = uint64(v)
	case uint16:
		numeric = uint64(v)
	case uint32:
		numeric = uint64(v)
	case uint64:
		numeric = v
	default:
		return ""
	}

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

// makeRawLayer creates a Raw layer with the given payload.
func makeRawLayer(payload []byte) *Layer {
	factory, ok := dissectRegistry.factories["Raw"]
	if ok {
		layer := factory()
		layer.Set("load", payload)
		return layer
	}
	// Fallback: create a minimal layer with a single "load" field.
	// This shouldn't normally happen if layers package is imported.
	layer := &Layer{
		proto:  "Raw",
		values: map[string]any{"load": payload},
	}
	return layer
}
