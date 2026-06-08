package layers

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ipAddr holds resolved IP addresses along with the version.
type ipAddr struct {
	src  []byte
	dst  []byte
	isV6 bool
}

// findIPAddressesAny searches downward from layerIdx to find the nearest IP or
// IPv6 layer (skipping IPv6 extension headers) and returns the resolved addresses.
// It supports both IPv4 and IPv6, which is needed for TCP/UDP checksum computation
// over IPv6 (with or without extension headers).
func findIPAddressesAny(pkt *packet.Packet, layerIdx int) (addr ipAddr, err error) {
	for i := layerIdx - 1; i >= 0; i-- {
		proto := pkt.Layers()[i].Proto()
		if proto == "IP" {
			ipLayer := pkt.Layers()[i]
			src, _ := ipLayer.Get("src")
			dst, _ := ipLayer.Get("dst")
			addr.src = ipToBytes(src)
			addr.dst = ipToBytes(dst)
			if len(addr.src) != 4 || len(addr.dst) != 4 {
				return addr, fmt.Errorf("layers: IP addresses not set for checksum computation")
			}
			addr.isV6 = false
			return addr, nil
		}
		if proto == "IPv6" {
			ipLayer := pkt.Layers()[i]
			src, _ := ipLayer.Get("src")
			dst, _ := ipLayer.Get("dst")
			addr.src = ipv6ToBytes(src)
			addr.dst = ipv6ToBytes(dst)
			if len(addr.src) != 16 || len(addr.dst) != 16 {
				return addr, fmt.Errorf("layers: IPv6 addresses not set for checksum computation")
			}
			addr.isV6 = true
			return addr, nil
		}
		// Skip IPv6 extension headers when searching.
	}
	return addr, fmt.Errorf("layers: no IP/IPv6 layer found below layer %d for checksum computation", layerIdx)
}

// ipToBytes converts an IP field value to a 4-byte IPv4 address.
func ipToBytes(v any) []byte {
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
