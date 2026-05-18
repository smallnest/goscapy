package packet

// BuildHook is called during Packet.Build() for each layer that has a
// registered hook matching its protocol name.
//
// Parameters:
//   - pkt:       the full packet being built
//   - layerIdx:  index of this layer within pkt.Layers()
//   - upperBytes: concatenated bytes of all layers above this one (already serialized)
//
// The hook should set derived field values (length, checksum, etc.) on the layer,
// then return the final wire bytes by calling layer.SerializeFields().
type BuildHook func(pkt *Packet, layerIdx int, upperBytes []byte) ([]byte, error)

var buildHooks map[string]BuildHook

func init() {
	buildHooks = make(map[string]BuildHook)
}

// RegisterBuildHook registers a build hook for the given protocol name.
// Typically called from init() in layer definition files.
func RegisterBuildHook(proto string, hook BuildHook) {
	buildHooks[proto] = hook
}

// lookupBuildHook returns the registered hook for proto, or nil.
func lookupBuildHook(proto string) BuildHook {
	return buildHooks[proto]
}
