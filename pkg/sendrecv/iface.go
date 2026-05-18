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
