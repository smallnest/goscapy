package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// NewUDP creates a UDP header layer with sensible defaults.
// Defaults: len=8 (header only, no payload), checksum=0 (auto-computed during Build).
func NewUDP() *packet.Layer {
	return packet.NewLayer("UDP", []fields.Field{
		fields.NewShortField("sport", 0),  // source port
		fields.NewShortField("dport", 0),  // destination port
		fields.NewShortField("len", 8),    // length (header + payload), updated during Build
		fields.NewShortField("chksum", 0), // auto-computed during Build
	})
}

// NewUDPWith creates a UDP header with the given source and destination ports.
func NewUDPWith(sport, dport uint16) *packet.Layer {
	l := NewUDP()
	l.Set("sport", sport)
	l.Set("dport", dport)
	return l
}

// udpBuildHook is called during Packet.Build() for UDP layers.
// It auto-computes the UDP length and checksum using the IPv4 pseudo-header.
func udpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte) ([]byte, error) {
	layer := pkt.Layers()[layerIdx]

	// Compute total length: header (8) + upper payload.
	totalLen := uint16(8 + len(upperBytes))
	layer.Set("len", totalLen)

	// Zero checksum, serialize header.
	layer.Set("chksum", uint16(0))
	hdrBytes, err := layer.SerializeFields()
	if err != nil {
		return nil, err
	}

	// Full datagram = header + upper payload.
	fullDg := make([]byte, 0, len(hdrBytes)+len(upperBytes))
	fullDg = append(fullDg, hdrBytes...)
	fullDg = append(fullDg, upperBytes...)

	// Find IP layer below for src/dst addresses.
	srcIP, dstIP, err := findIPAddresses(pkt, layerIdx)
	if err != nil {
		return nil, err
	}

	csum := UDPChecksum(srcIP, dstIP, fullDg)
	if csum == 0 {
		csum = 0xFFFF // RFC 768: 0 means "no checksum", use 0xFFFF instead
	}
	layer.Set("chksum", csum)

	return layer.SerializeFields()
}
