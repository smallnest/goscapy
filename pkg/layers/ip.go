package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IP protocol numbers as assigned by IANA.
const (
	IPProtoICMP uint8 = 1
	IPProtoTCP  uint8 = 6
	IPProtoUDP  uint8 = 17
)

// NewIP creates an IPv4 header layer with sensible defaults.
// Defaults: version/ihl=0x45 (v4, 5 words), ttl=64, checksum=0 (auto-computed during Build).
func NewIP() *packet.Layer {
	return packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45), // version=4, ihl=5
		fields.NewByteField("tos", 0),
		fields.NewShortField("len", 20), // total length, updated during Build
		fields.NewShortField("id", 0),
		fields.NewShortField("frag", 0), // flags (3 bits) + fragment offset (13 bits)
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 0),
		fields.NewShortField("chksum", 0), // auto-computed during Build
		fields.NewIPField("src", nil),
		fields.NewIPField("dst", nil),
	})
}

// IPVersion extracts the version field from the verihl byte.
func IPVersion(verihl uint8) uint8 { return verihl >> 4 }

// IPIHL extracts the IHL field (in 32-bit words) from the verihl byte.
func IPIHL(verihl uint8) uint8 { return verihl & 0x0F }

// IPFlags extracts the 3-bit flags field from the frag short.
func IPFlags(frag uint16) uint8 { return uint8(frag >> 13) }

// IPFragOffset extracts the 13-bit fragment offset from the frag short.
func IPFragOffset(frag uint16) uint16 { return frag & 0x1FFF }

// ipBuildHook is called during Packet.Build() for IP layers.
// It auto-computes the total length and header checksum.
func ipBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte) ([]byte, error) {
	layer := pkt.Layers()[layerIdx]

	// Compute total length: header size + upper layer bytes.
	verihl, _ := layer.Get("verihl")
	headerSize := int(verihl.(uint8)&0x0F) * 4
	totalLen := uint16(headerSize + len(upperBytes))
	layer.Set("len", totalLen)

	// Zero checksum, serialize header, compute checksum, re-serialize.
	layer.Set("chksum", uint16(0))
	hdrBytes, err := layer.SerializeFields()
	if err != nil {
		return nil, err
	}

	csum := IPChecksum(hdrBytes)
	layer.Set("chksum", csum)

	return layer.SerializeFields()
}
