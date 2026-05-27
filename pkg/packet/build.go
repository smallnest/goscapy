package packet

// BuildHook is called during Packet.Build() for each layer that has a
// registered hook matching its protocol name.
//
// Parameters:
//   - pkt:       the full packet being built
//   - layerIdx:  index of this layer within pkt.Layers()
//   - upperBytes: concatenated bytes of all layers above this one (already serialized)
//   - buf:        pre-sized buffer for this layer's serialized output
//
// The hook should set derived field values (length, checksum, etc.) on the layer,
// then serialize directly into buf. Returns the number of bytes written.
type BuildHook func(pkt *Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error)

// buildHooks maps protocol names to their BuildHook functions.
// Must be populated during init() only; read-only after program startup.
// Not safe for concurrent writes.
var buildHooks map[string]BuildHook

func init() {
	buildHooks = make(map[string]BuildHook)
}

// RegisterBuildHook registers a build hook for the given protocol name.
// Must be called during init() only; not safe for concurrent use after startup.
func RegisterBuildHook(proto string, hook BuildHook) {
	buildHooks[proto] = hook
}

// lookupBuildHook returns the registered hook for proto, or nil.
func lookupBuildHook(proto string) BuildHook {
	return buildHooks[proto]
}
