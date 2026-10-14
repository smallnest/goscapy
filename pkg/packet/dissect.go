package packet

import (
	"fmt"
	"slices"
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

// PostParseHook is called after a layer's fixed fields are parsed and the
// actual header size is determined. It receives the "extra" bytes between
// the fixed fields and the full header boundary (e.g., TCP/IP options).
// The hook can parse these bytes and store results in the layer via Set.
type PostParseHook func(layer *Layer, extra []byte) error

// NextLayerFunc determines the next upper-layer protocol by inspecting the
// parsed layer and the remaining (not-yet-consumed) payload bytes. It is used
// for protocols whose next layer is not encoded in a single key field —
// for example MPLS, where the inner protocol is guessed from the first nibble
// of the payload. Returning "" falls back to key-field / heuristic resolution.
type NextLayerFunc func(layer *Layer, remaining []byte) string

// TotalLenFunc returns the total on-wire length (header + payload) that a
// parsed layer declares for itself, e.g. the IPv4 "len" field. Bytes beyond it
// are link-layer padding/trailer (an Ethernet frame is padded to 60 bytes) and
// do not belong to the upper layers. Return 0 when the length is unknown.
type TotalLenFunc func(layer *Layer) int

type dissectReg struct {
	factories      map[string]LayerFactory
	nextLayer      map[string]map[uint64]string // proto → field value → next proto name
	keyFields      map[string][]string          // proto → field names tried in order for next-layer lookup
	headerSizeFn   map[string]HeaderSizeFunc    // proto → function to compute variable header size
	dissectors     map[string]DissectorFunc     // proto → function to identify this protocol from raw bytes
	tunnelPayload  map[string]string            // proto → inner proto for tunnel-encapsulated payloads
	postParseHooks map[string]PostParseHook     // proto → hook called after fixed fields are parsed
	nextLayerFns   map[string]NextLayerFunc     // proto → function resolving next layer from payload
	totalLenFns    map[string]TotalLenFunc      // proto → function returning the layer's declared total length
	guessed        map[string]map[string]bool   // lower proto → next protos chosen only by heuristic (RegisterHeuristic)
}

// dissectRegistry holds all protocol dissection registrations.
// Must be populated during init() only; read-only after program startup.
// Not safe for concurrent writes.
var dissectRegistry = dissectReg{
	factories:      make(map[string]LayerFactory),
	nextLayer:      make(map[string]map[uint64]string),
	keyFields:      make(map[string][]string),
	headerSizeFn:   make(map[string]HeaderSizeFunc),
	dissectors:     make(map[string]DissectorFunc),
	tunnelPayload:  make(map[string]string),
	postParseHooks: make(map[string]PostParseHook),
	nextLayerFns:   make(map[string]NextLayerFunc),
	totalLenFns:    make(map[string]TotalLenFunc),
	guessed:        make(map[string]map[string]bool),
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

// RegisterKeyField registers a field of a layer used to determine the next
// upper-layer protocol. A protocol may have several key fields (UDP/TCP are
// matched on both dport and sport); they are tried in registration order.
func RegisterKeyField(proto, fieldName string) {
	if !slices.Contains(dissectRegistry.keyFields[proto], fieldName) {
		dissectRegistry.keyFields[proto] = append(dissectRegistry.keyFields[proto], fieldName)
	}
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
	if dissectRegistry.guessed[lowerProto] == nil {
		dissectRegistry.guessed[lowerProto] = make(map[string]bool)
	}
	dissectRegistry.guessed[lowerProto][nextProto] = true
}

// RegisterPostParseHook registers a hook called after a layer's fixed fields
// are parsed and the actual header size is computed. The hook receives the
// "extra" header bytes (e.g., TCP options, IP options) that fall between
// the fixed field boundary and the full header size.
func RegisterPostParseHook(proto string, hook PostParseHook) {
	dissectRegistry.postParseHooks[proto] = hook
}

// RegisterNextLayerFunc registers a custom next-layer resolver for proto.
// It takes precedence over key-field / heuristic resolution and is used by
// protocols (such as MPLS) whose next layer must be inferred from the payload
// rather than a single header field.
func RegisterNextLayerFunc(proto string, fn NextLayerFunc) {
	dissectRegistry.nextLayerFns[proto] = fn
}

// RegisterTotalLenFunc registers a function reporting the total length a
// layer declares for itself, so dissection can drop trailing link-layer
// padding instead of handing it to the upper layers as payload.
func RegisterTotalLenFunc(proto string, fn TotalLenFunc) {
	dissectRegistry.totalLenFns[proto] = fn
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
	guessed := false // currentProto was picked by a heuristic, not a definite binding

	for currentProto != "" {
		factory, ok := dissectRegistry.factories[currentProto]
		if !ok {
			break
		}

		layer := factory()
		consumed, err := layer.ParseFields(remaining)
		if err != nil {
			if !guessed {
				return nil, fmt.Errorf("packet: Dissect: layer %s: %w", currentProto, err)
			}
			// The layer was only guessed (e.g. from a port number) and the
			// bytes don't fit it: keep them as a Raw payload, like Scapy does,
			// rather than failing the layers already parsed.
			break
		}

		actualHeaderSize := consumed
		if sizeFn, hasFn := dissectRegistry.headerSizeFn[currentProto]; hasFn {
			if hs := sizeFn(layer); hs > 0 {
				actualHeaderSize = hs
			}
		}

		if actualHeaderSize > len(remaining) {
			return nil, fmt.Errorf("packet: Dissect: layer %s: header size %d exceeds remaining bytes %d",
				currentProto, actualHeaderSize, len(remaining))
		}

		if hook, hasHook := dissectRegistry.postParseHooks[currentProto]; hasHook {
			if actualHeaderSize > consumed {
				if err := hook(layer, remaining[consumed:actualHeaderSize]); err != nil {
					return nil, fmt.Errorf("packet: Dissect: layer %s post-parse: %w", currentProto, err)
				}
			}
		}

		// Drop bytes beyond the layer's declared length (link-layer padding).
		if fn, ok := dissectRegistry.totalLenFns[currentProto]; ok {
			if total := fn(layer); total >= actualHeaderSize && total < len(remaining) {
				remaining = remaining[:total]
			}
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
				if guessed {
					break // not really this tunnel: keep the payload as Raw
				}
				return nil, fmt.Errorf("packet: Dissect: tunnel %s: %w", currentProto, err)
			}
			for _, l := range innerPkt.Layers() {
				pkt.Push(l)
			}
			// The inner dissection consumed all remaining bytes (it appends its
			// own Raw layer for any trailer); clear remaining so the leftover
			// handling below does not append a second, duplicate Raw layer.
			remaining = nil
			break
		}

		if len(remaining) == 0 {
			break
		}

		// Resolve next layer via custom func, then key field or heuristics.
		if fn, ok := dissectRegistry.nextLayerFns[currentProto]; ok {
			if next := fn(layer, remaining); next != "" {
				currentProto, guessed = next, false
				continue
			}
		}
		next := resolveNextLayer(currentProto, layer)
		currentProto, guessed = next, dissectRegistry.guessed[currentProto][next]
	}

	// Wrap leftover bytes as Raw payload.
	if len(remaining) > 0 {
		rawLayer := makeRawLayer(remaining)
		pkt.Push(rawLayer)
	}

	return pkt, nil
}

// resolveNextLayer determines the next upper-layer protocol from the current
// layer's key fields, returning the first one whose value has a mapping.
func resolveNextLayer(proto string, layer *Layer) string {
	nextMap := dissectRegistry.nextLayer[proto]
	for _, keyField := range dissectRegistry.keyFields[proto] {
		keyVal, err := layer.Get(keyField)
		if err != nil {
			continue
		}
		if next, found := nextMap[toUint64(keyVal)]; found {
			return next
		}
	}
	return ""
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

// makeRawLayer creates a Raw layer with the given payload bytes.
func makeRawLayer(payload []byte) *Layer {
	factory, ok := dissectRegistry.factories["Raw"]
	if ok {
		layer := factory()
		_ = layer.Set("load", payload)
		return layer
	}
	layer := &Layer{
		proto:  "Raw",
		values: map[string]any{"load": payload},
	}
	return layer
}
