package layers

import (
	"github.com/smallnest/goscapy/pkg/packet"
)

// DefaultFragSize is the default payload size per fragment used by Fragment
// when no explicit size is given. 1480 = 1500 (typical Ethernet MTU) - 20
// (IPv4 header), and is a multiple of 8 as required for fragment offsets.
const DefaultFragSize = 1480

// Fragment splits an IPv4 packet into a list of fragment packets, each
// carrying at most fragSize bytes of the original L4 payload. It mirrors
// Scapy's fragment(pkt, fragsize).
//
// The input packet must contain an IP layer. Everything above the IP header
// (TCP/UDP/ICMP/Raw/...) is treated as the fragmentable payload: it is built
// once, then sliced into fragSize-byte chunks. Each returned packet has its
// own IP header copied from the original with the fragment offset and MF
// (More Fragments) flag set appropriately; lower layers (e.g. Ethernet) are
// preserved on every fragment.
//
// fragSize is rounded down to the nearest multiple of 8 (the fragment-offset
// granularity). If fragSize <= 0, DefaultFragSize is used. If the payload
// already fits in a single fragment, a one-element slice containing a copy of
// the packet is returned.
func Fragment(pkt *packet.Packet, fragSize int) ([]*packet.Packet, error) {
	if fragSize <= 0 {
		fragSize = DefaultFragSize
	}
	// Fragment offsets count in 8-byte units, so each non-final fragment's
	// payload must be a multiple of 8 bytes.
	fragSize -= fragSize % 8
	if fragSize == 0 {
		fragSize = 8
	}

	ipIdx := layerIndex(pkt, "IP")
	if ipIdx < 0 {
		return nil, errNoIP
	}

	// Build the L4 payload: everything above the IP layer.
	payload, err := pkt.BuildFrom(ipIdx + 1)
	if err != nil {
		return nil, err
	}

	// Single fragment: nothing to split.
	if len(payload) <= fragSize {
		return []*packet.Packet{pkt.Copy()}, nil
	}

	origIP := pkt.Layers()[ipIdx]
	origFragVal, _ := origIP.Get("frag")
	origFrag, _ := origFragVal.(uint16)

	var result []*packet.Packet
	for off := 0; off < len(payload); off += fragSize {
		end := off + fragSize
		more := true
		if end >= len(payload) {
			end = len(payload)
			more = false
		}
		chunk := payload[off:end]

		// Clone lower layers (e.g. Ethernet) and the IP header.
		newPkt := packet.New()
		for i := 0; i < ipIdx; i++ {
			newPkt.Push(pkt.Layers()[i].Copy())
		}
		ip := origIP.Copy()

		// Fragment offset is in 8-byte units; MF flag in bit 0 of the high byte.
		fragOff := uint16(off / 8)
		fragField := fragOff & 0x1FFF
		if more {
			fragField |= 0x2000 // MF flag (bit 13)
		}
		// Preserve DF if it was set on the original.
		if origFrag&0x4000 != 0 {
			fragField |= 0x4000
		}
		_ = ip.Set("frag", fragField)

		newPkt.Push(ip)
		newPkt.Push(NewRawWith(chunk))
		result = append(result, newPkt)
	}
	return result, nil
}

// Fragment6 splits an IPv6 packet into fragments using an IPv6 Fragment
// extension header (RFC 8200), mirroring Scapy's fragment6(). It inserts a
// Fragment header between the IPv6 header and the payload, slicing the
// per-fragment payload to at most fragSize bytes (rounded down to a multiple
// of 8). The id field of every fragment is set to fragID so a receiver can
// reassemble the group.
//
// The input packet must contain an IPv6 layer. If fragSize <= 0,
// DefaultFragSize is used. If the payload already fits, a one-element slice
// containing a copy of the packet is returned.
func Fragment6(pkt *packet.Packet, fragSize int, fragID uint32) ([]*packet.Packet, error) {
	if fragSize <= 0 {
		fragSize = DefaultFragSize
	}
	fragSize -= fragSize % 8
	if fragSize == 0 {
		fragSize = 8
	}

	ipIdx := layerIndex(pkt, "IPv6")
	if ipIdx < 0 {
		return nil, errNoIPv6
	}

	payload, err := pkt.BuildFrom(ipIdx + 1)
	if err != nil {
		return nil, err
	}

	origIP := pkt.Layers()[ipIdx]
	// The Next Header value that the fragment header should advertise is the
	// IPv6 header's current nh (the protocol of the first fragmentable header).
	nhVal, _ := origIP.Get("nh")
	innerNH, _ := nhVal.(uint8)

	if len(payload) <= fragSize {
		return []*packet.Packet{pkt.Copy()}, nil
	}

	var result []*packet.Packet
	for off := 0; off < len(payload); off += fragSize {
		end := off + fragSize
		more := true
		if end >= len(payload) {
			end = len(payload)
			more = false
		}
		chunk := payload[off:end]

		newPkt := packet.New()
		for i := 0; i < ipIdx; i++ {
			newPkt.Push(pkt.Layers()[i].Copy())
		}
		ip := origIP.Copy()
		// IPv6 header's next header becomes Fragment (44).
		_ = ip.Set("nh", IPv6ExtHdrFragment)
		newPkt.Push(ip)

		fragHdr := NewIPv6Fragment()
		_ = fragHdr.Set("nh", innerNH)
		_ = fragHdr.Set("res", uint8(0))
		// frag field: offset(13 bits, in 8-byte units) << 3 | M flag (bit 0).
		fragField := (uint16(off/8) << 3) & 0xFFF8
		if more {
			fragField |= 0x0001
		}
		_ = fragHdr.Set("frag", fragField)
		_ = fragHdr.Set("id", fragID)
		newPkt.Push(fragHdr)

		newPkt.Push(NewRawWith(chunk))
		result = append(result, newPkt)
	}
	return result, nil
}

// layerIndex returns the index of the first layer matching proto, or -1.
func layerIndex(pkt *packet.Packet, proto string) int {
	for i, l := range pkt.Layers() {
		if l.Proto() == proto {
			return i
		}
	}
	return -1
}

// errNoIP / errNoIPv6 are returned when the packet lacks the required network layer.
var (
	errNoIP   = &fragError{"Fragment: packet has no IP layer"}
	errNoIPv6 = &fragError{"Fragment6: packet has no IPv6 layer"}
)

type fragError struct{ msg string }

func (e *fragError) Error() string { return "layers: " + e.msg }
