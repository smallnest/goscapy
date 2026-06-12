package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IPProtoVRRP is the IANA-assigned IP protocol number for VRRP.
const IPProtoVRRP uint8 = 112

// VRRP message type (only Advertisement is defined, RFC 3768).
const VRRPTypeAdvertisement uint8 = 1

// VRRP authentication types (RFC 2338; removed in RFC 3768 but still seen).
const (
	VRRPAuthNone       uint8 = 0
	VRRPAuthSimpleText uint8 = 1
	VRRPAuthIPAuthHdr  uint8 = 2
)

// NewVRRP creates a VRRPv2 advertisement message (RFC 3768).
// Wire format:
//
//	ver_type(1) | vrid(1) | priority(1) | ipcount(1) | authtype(1) |
//	adver(1) | checksum(2) | IP address(es) (4*ipcount) | auth data(8, optional)
//
// ver_type packs version (high nibble, =2) and type (low nibble, =1). The
// virtual IP addresses are carried as the "addrs" byte field (4 bytes each);
// set ipcount to match. The checksum is computed over the VRRP message during
// Build.
func NewVRRP() *packet.Layer {
	return packet.NewLayer("VRRP", []fields.Field{
		fields.NewByteField("ver_type", 0x21), // version=2, type=1
		fields.NewByteField("vrid", 1),
		fields.NewByteField("priority", 100),
		fields.NewByteField("ipcount", 1),
		fields.NewByteField("authtype", VRRPAuthNone),
		fields.NewByteField("adver", 1), // advertisement interval (seconds)
		fields.NewShortField("chksum", 0),
		fields.NewStrField("addrs", ""), // virtual IP addresses, 4 bytes each
	})
}

// NewVRRPWith creates a VRRPv2 advertisement for the given router ID and
// priority, advertising a single virtual IP address.
func NewVRRPWith(vrid, priority uint8, virtualIP string) *packet.Layer {
	l := NewVRRP()
	_ = l.Set("vrid", vrid)
	_ = l.Set("priority", priority)
	_ = l.Set("ipcount", uint8(1))
	if virtualIP != "" {
		_ = l.Set("addrs", IPv4Bytes(virtualIP))
	}
	return l
}

// VRRPVersion extracts the 4-bit version from the ver_type byte.
func VRRPVersion(verType uint8) uint8 { return verType >> 4 }

// VRRPType extracts the 4-bit message type from the ver_type byte.
func VRRPType(verType uint8) uint8 { return verType & 0x0F }

// vrrpBuildHook computes the VRRP checksum over the full message
// (header + addresses + any auth data), writing directly into buf.
func vrrpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]

	_ = layer.Set("chksum", uint16(0))
	n, err := layer.SerializeInto(buf)
	if err != nil {
		return 0, err
	}

	sum := checksumSum(buf[:n])
	sum += checksumSum(upperBytes)
	csum := foldChecksum(sum)

	_ = layer.Set("chksum", csum)
	buf[6] = byte(csum >> 8)
	buf[7] = byte(csum)
	return n, nil
}

// IPv4Bytes converts a dotted-quad string to 4 bytes, or nil on error.
func IPv4Bytes(s string) []byte {
	b := ipToBytes(s)
	if len(b) == 4 {
		return b
	}
	return nil
}
