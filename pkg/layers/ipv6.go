package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IPv6 extension header (Next Header) numbers.
const (
	IPv6ExtHdrHopByHop uint8 = 0
	IPv6ExtHdrRouting  uint8 = 43
	IPv6ExtHdrFragment uint8 = 44
	IPv6ExtHdrDestOpts uint8 = 60
)

// IPv6 next header values for common upper-layer protocols.
const (
	IPv6NextHdrICMP   uint8 = 58
	IPv6NextHdrTCP    uint8 = 6
	IPv6NextHdrUDP    uint8 = 17
	IPv6NextHdrNoHdr  uint8 = 59
)

// NewIPv6 creates an IPv6 header layer with sensible defaults.
// Defaults: version=6, hop limit=64, zero traffic class and flow label.
func NewIPv6() *packet.Layer {
	return packet.NewLayer("IPv6", []fields.Field{
		fields.NewIntField("ver_tc_fl", 0x60000000), // version=6, tc=0, fl=0
		fields.NewShortField("plen", 0),
		fields.NewByteField("nh", 0),
		fields.NewByteField("hlim", 64),
		fields.NewIPv6Field("src", nil),
		fields.NewIPv6Field("dst", nil),
	})
}

// IPv6Version extracts the version field (upper 4 bits, always 6).
func IPv6Version(verTCFL uint32) uint8 { return uint8(verTCFL >> 28) }

// IPv6TrafficClass extracts the 8-bit traffic class field.
func IPv6TrafficClass(verTCFL uint32) uint8 { return uint8(verTCFL >> 20) & 0xFF }

// IPv6FlowLabel extracts the 20-bit flow label field.
func IPv6FlowLabel(verTCFL uint32) uint32 { return verTCFL & 0x000FFFFF }

// MakeIPv6VerTCFL builds the combined version/traffic-class/flow-label field.
func MakeIPv6VerTCFL(tc uint8, fl uint32) uint32 {
	return 0x60000000 | (uint32(tc&0xFF) << 20) | (fl & 0x000FFFFF)
}

// ipv6BuildHook is called during Packet.Build() for IPv6 layers.
// It auto-computes the payload length from upper layer bytes, writing directly into buf.
func ipv6BuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]
	layer.Set("plen", uint16(len(upperBytes)))
	return layer.SerializeInto(buf)
}

// ---- Extension header layers ----

// newIPv6ExtHdr creates a generic IPv6 extension header layer.
// proto is the protocol name (e.g. "IPv6 Hop-by-Hop").
func newIPv6ExtHdr(proto string) *packet.Layer {
	return packet.NewLayer(proto, []fields.Field{
		fields.NewByteField("nh", 0),
		fields.NewByteField("len", 0),  // Hdr Ext Len in 8-byte units, not counting first 8 bytes
		fields.NewStrField("options", ""), // variable-length options
	})
}

// NewIPv6HopByHop creates an IPv6 Hop-by-Hop Options extension header.
func NewIPv6HopByHop() *packet.Layer { return newIPv6ExtHdr("IPv6 Hop-by-Hop") }

// NewIPv6Routing creates an IPv6 Routing extension header.
func NewIPv6Routing() *packet.Layer { return newIPv6ExtHdr("IPv6 Routing") }

// NewIPv6DestOpts creates an IPv6 Destination Options extension header.
func NewIPv6DestOpts() *packet.Layer { return newIPv6ExtHdr("IPv6 DestOpts") }

// NewIPv6Fragment creates an IPv6 Fragment extension header.
func NewIPv6Fragment() *packet.Layer {
	return packet.NewLayer("IPv6 Fragment", []fields.Field{
		fields.NewByteField("nh", 0),
		fields.NewByteField("res", 0),
		fields.NewShortField("frag", 0), // offset(13) + Res(2) + M(1)
		fields.NewIntField("id", 0),
	})
}

// IPv6FragmentOffset extracts the 13-bit fragment offset.
func IPv6FragmentOffset(frag uint16) uint16 { return frag >> 3 }

// IPv6FragmentMore extracts the M (More Fragments) flag.
func IPv6FragmentMore(frag uint16) bool { return frag&0x01 != 0 }

// extHdrSizeFn computes the actual wire size of an extension header
// from its Hdr Ext Len field: (len + 1) * 8 bytes total.
func extHdrSizeFn(layer *packet.Layer) int {
	hdrLen, err := layer.Get("len")
	if err != nil {
		return 0
	}
	return (int(hdrLen.(uint8)) + 1) * 8
}

// ---- IPv6 pseudo-header checksum ----

// IPv6PseudoHeaderChecksum computes the checksum using the IPv6 pseudo-header
// (RFC 2460). The pseudo-header consists of:
//
//	srcIP (16) + dstIP (16) + upperLen (4) + zeros (3) + nextHeader (1)
//
// This is concatenated with upperData and checksummed.
func IPv6PseudoHeaderChecksum(srcIP, dstIP []byte, nextHeader uint8, upperData []byte) uint16 {
	ph := make([]byte, 40)
	copy(ph[0:16], srcIP)
	copy(ph[16:32], dstIP)
	upperLen := uint32(len(upperData))
	ph[32] = byte(upperLen >> 24)
	ph[33] = byte(upperLen >> 16)
	ph[34] = byte(upperLen >> 8)
	ph[35] = byte(upperLen)
	// bytes 36-38 are zero (already zero from make)
	ph[39] = nextHeader

	buf := make([]byte, 0, len(ph)+len(upperData))
	buf = append(buf, ph...)
	buf = append(buf, upperData...)

	return Checksum(buf)
}