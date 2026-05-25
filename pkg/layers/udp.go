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
// It auto-computes the UDP length and checksum using the IPv4 or IPv6 pseudo-header.
func udpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte) ([]byte, error) {
	layer := pkt.Layers()[layerIdx]

	// Compute total length: header (8) + upper payload.
	totalLen := uint16(8 + len(upperBytes))
	layer.Set("len", totalLen)

	// Single-pass: serialize with zero checksum.
	layer.Set("chksum", uint16(0))
	buf := make([]byte, 8)
	n, err := layer.SerializeInto(buf)
	if err != nil {
		return nil, err
	}

	// Compute checksum without concatenation.
	addr, err := findIPAddressesAny(pkt, layerIdx)
	if err != nil {
		return nil, err
	}

	var csum uint16
	if addr.isV6 {
		csum = checksumIPv6Pseudo(addr.src, addr.dst, IPv6NextHdrUDP, buf[:n], upperBytes)
	} else {
		csum = checksumIPv4Pseudo(addr.src, addr.dst, 17, buf[:n], upperBytes)
	}
	if csum == 0 {
		csum = 0xFFFF // RFC 768: 0 means "no checksum", use 0xFFFF instead
	}
	layer.Set("chksum", csum)
	// Write checksum at offset 6 (UDP checksum: sport(2)+dport(2)+len(2) = 6).
	buf[6] = byte(csum >> 8)
	buf[7] = byte(csum)
	return buf[:n], nil
}
