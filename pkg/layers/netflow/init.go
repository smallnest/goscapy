package netflow

import (
	"github.com/smallnest/goscapy/pkg/packet"
)

func init() {
	// Heuristic: UDP port 2055 → Netflow (V5/V9/IPFIX).
	packet.RegisterHeuristic("UDP", "dport", uint16(2055), "NetflowV5")
	packet.RegisterHeuristic("UDP", "sport", uint16(2055), "NetflowV5")
	// Also match common alternate ports.
	packet.RegisterHeuristic("UDP", "dport", uint16(9996), "NetflowV5")
	packet.RegisterHeuristic("UDP", "sport", uint16(9996), "NetflowV5")

	// Register layer factories.
	packet.RegisterLayer("NetflowV5", NewNetflowV5)
	packet.RegisterLayer("NetflowV9", NewNetflowV9)
	packet.RegisterLayer("IPFIX", NewIPFIX)

	// Register variable header size for version-based auto-detection.
	packet.RegisterHeaderSizeFunc("NetflowV5", func(layer *packet.Layer) int {
		return 24
	})
	packet.RegisterHeaderSizeFunc("NetflowV9", func(layer *packet.Layer) int {
		return 20
	})
	packet.RegisterHeaderSizeFunc("IPFIX", func(layer *packet.Layer) int {
		return 16
	})
}

// DetectNetflowVersion reads the version from raw bytes and returns the layer name.
func DetectNetflowVersion(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	ver := uint16(data[0])<<8 | uint16(data[1])
	switch ver {
	case 5:
		return "NetflowV5"
	case 9:
		return "NetflowV9"
	case 10:
		return "IPFIX"
	default:
		return ""
	}
}
