package layers

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/packet"
)

// findIPAddresses searches downward from layerIdx to find the nearest IP layer
// and returns its src and dst IP addresses as 4-byte slices.
func findIPAddresses(pkt *packet.Packet, layerIdx int) (srcIP, dstIP []byte, err error) {
	for i := layerIdx - 1; i >= 0; i-- {
		if pkt.Layers()[i].Proto() == "IP" {
			ipLayer := pkt.Layers()[i]
			src, _ := ipLayer.Get("src")
			dst, _ := ipLayer.Get("dst")

			srcIP = ipToBytes(src)
			dstIP = ipToBytes(dst)

			if len(srcIP) != 4 || len(dstIP) != 4 {
				return nil, nil, fmt.Errorf("layers: IP addresses not set for checksum computation")
			}
			return srcIP, dstIP, nil
		}
	}
	return nil, nil, fmt.Errorf("layers: no IP layer found below layer %d for checksum computation", layerIdx)
}

// ipToBytes converts an IP field value to a 4-byte IPv4 address.
func ipToBytes(v interface{}) []byte {
	switch ip := v.(type) {
	case net.IP:
		return ip.To4()
	case string:
		parsed := net.ParseIP(ip)
		if parsed != nil {
			return parsed.To4()
		}
	case []byte:
		if len(ip) == 4 {
			return ip
		}
	}
	return nil
}
