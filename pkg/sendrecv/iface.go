package sendrecv

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/packet"
)

// lookupInterface wraps net.InterfaceByName with a descriptive error.
func lookupInterface(name string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("sendrecv: interface %q not found: %w", name, err)
	}
	return iface, nil
}

// extractDstIP returns the destination IPv4 address from the packet's IP layer
// as a 4-byte array suitable for syscall.Sendto.
func extractDstIP(pkt *packet.Packet) ([4]byte, error) {
	ipLayer := pkt.GetLayer("IP")
	if ipLayer == nil {
		return [4]byte{}, fmt.Errorf("sendrecv: packet has no IP layer")
	}
	dstVal, err := ipLayer.Get("dst")
	if err != nil {
		return [4]byte{}, fmt.Errorf("sendrecv: IP layer has no dst field: %w", err)
	}

	var dstIP net.IP
	switch v := dstVal.(type) {
	case net.IP:
		dstIP = v.To4()
	case string:
		dstIP = net.ParseIP(v).To4()
	default:
		return [4]byte{}, fmt.Errorf("sendrecv: unexpected dst type %T", dstVal)
	}
	if dstIP == nil || len(dstIP) != 4 {
		return [4]byte{}, fmt.Errorf("sendrecv: invalid IPv4 destination")
	}

	var arr [4]byte
	copy(arr[:], dstIP)
	return arr, nil
}

// hasIPv6Layer returns true if the packet contains an IPv6 layer.
func hasIPv6Layer(pkt *packet.Packet) bool {
	return pkt.GetLayer("IPv6") != nil
}

// extractIPv6Info extracts the destination address (16 bytes), next-header protocol,
// and hop limit from the packet's IPv6 layer.
func extractIPv6Info(pkt *packet.Packet) (dst [16]byte, nextHdr uint8, hopLimit uint8, err error) {
	ipLayer := pkt.GetLayer("IPv6")
	if ipLayer == nil {
		err = fmt.Errorf("sendrecv: packet has no IPv6 layer")
		return
	}

	dstVal, e := ipLayer.Get("dst")
	if e != nil {
		err = fmt.Errorf("sendrecv: IPv6 layer has no dst field: %w", e)
		return
	}
	var dstIP net.IP
	switch v := dstVal.(type) {
	case net.IP:
		dstIP = v.To16()
	case string:
		dstIP = net.ParseIP(v).To16()
	default:
		err = fmt.Errorf("sendrecv: unexpected IPv6 dst type %T", dstVal)
		return
	}
	if dstIP == nil || len(dstIP) != 16 {
		err = fmt.Errorf("sendrecv: invalid IPv6 destination")
		return
	}
	copy(dst[:], dstIP)

	nhVal, e := ipLayer.Get("nh")
	if e != nil {
		err = fmt.Errorf("sendrecv: IPv6 layer has no nh field: %w", e)
		return
	}
	nextHdr, _ = nhVal.(uint8)

	hlVal, e := ipLayer.Get("hlim")
	if e == nil {
		hopLimit, _ = hlVal.(uint8)
	} else {
		hopLimit = 64
	}
	return
}

// buildL3v6Payload builds the IPv6 packet bytes and returns the full raw bytes
// and the payload offset (bytes after the 40-byte IPv6 base header).
// On Linux (IPV6_HDRINCL), the full bytes are sent.
// On Darwin, only bytes[40:] are sent (kernel fills IPv6 header).
func buildL3v6Payload(pkt *packet.Packet) (full []byte, err error) {
	return buildL3(pkt)
}

// ethernetStartFn is passed to packet.Dissect when reading from L2 captures.
// It always returns "Ethernet" since raw captures start at the link layer.
func ethernetStartFn(_ []byte) (string, error) {
	return "Ethernet", nil
}

// buildL3 builds the IP-level bytes for L3 sending.
// If the packet starts with an Ethernet layer, it is skipped via BuildFrom(1).
// Otherwise the entire packet is built with Build().
func buildL3(pkt *packet.Packet) ([]byte, error) {
	if len(pkt.Layers()) > 0 && pkt.Layers()[0].Proto() == "Ethernet" {
		return pkt.BuildFrom(1)
	}
	return pkt.Build()
}
