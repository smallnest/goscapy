// Package route provides routing table read/write operations.
//
// It reads the OS routing table, resolves next-hops for destinations,
// and allows custom route additions for explicit routing control.
package route

import (
	"fmt"
	"net"
	"strings"
)

// Route represents a single routing table entry.
type Route struct {
	Destination *net.IPNet // destination network (nil for default route)
	Gateway     net.IP     // next-hop gateway (nil for directly connected)
	Interface   string     // output interface name (e.g. "eth0")
	Metric      int        // route metric (lower is preferred)
}

// DefaultRoute returns the system default route (0.0.0.0/0).
func DefaultRoute() (*Route, error) {
	return DefaultRoute4()
}

// Table reads and returns the system IPv4 routing table.
func Table() ([]Route, error) {
	return Table4()
}

// Route4 resolves the gateway and interface for an IPv4 destination.
// It returns the best matching route (longest prefix match).
func Route4(dst net.IP) (*Route, error) {
	routes, err := Table4()
	if err != nil {
		return nil, err
	}
	return bestMatch(dst, routes)
}

// Route6 resolves the gateway and interface for an IPv6 destination.
func Route6(dst net.IP) (*Route, error) {
	routes, err := Table6()
	if err != nil {
		return nil, err
	}
	return bestMatch(dst, routes)
}

// bestMatch finds the longest-prefix-matching route for dst.
func bestMatch(dst net.IP, routes []Route) (*Route, error) {
	dst = dst.To4()
	if dst == nil {
		dst = dst.To16()
	}

	var best *Route
	bestLen := -1

	for i := range routes {
		r := &routes[i]
		if r.Destination == nil {
			// Default route — only if nothing else matches.
			if best == nil {
				best = r
				bestLen = 0
			}
			continue
		}
		if r.Destination.Contains(dst) {
			ones, _ := r.Destination.Mask.Size()
			if ones > bestLen {
				best = r
				bestLen = ones
			}
		}
	}

	if best == nil {
		return nil, fmt.Errorf("route: no route to %s", dst)
	}
	return best, nil
}

// parseIPNet parses a destination IP and mask into a net.IPNet.
// If dst is 0.0.0.0 and mask is 0.0.0.0, returns nil (default route).
func parseIPNet(dst net.IP, mask net.IP) *net.IPNet {
	if dst.IsUnspecified() && mask.IsUnspecified() {
		return nil
	}
	return &net.IPNet{IP: dst, Mask: net.IPMask(mask.To4())}
}

// parseHexIP parses a hex-encoded IPv4 address (little-endian, as in /proc/net/route).
func parseHexIP(s string) (net.IP, error) {
	var ip [4]byte
	_, err := fmt.Sscanf(s, "%2x%2x%2x%2x", &ip[3], &ip[2], &ip[1], &ip[0])
	if err != nil {
		return nil, fmt.Errorf("route: parse hex IP %q: %w", s, err)
	}
	return net.IP(ip[:]), nil
}

// parseHexIPv6 parses a 32-char hex string into an IPv6 address (little-endian groups).
func parseHexIPv6(s string) (net.IP, error) {
	if len(s) != 32 {
		return nil, fmt.Errorf("route: invalid IPv6 hex length %d", len(s))
	}
	ip := make(net.IP, 16)
	// Each 8-char group is a 32-bit value in little-endian.
	for i := 0; i < 4; i++ {
		var v uint32
		_, err := fmt.Sscanf(s[i*8:i*8+8], "%08x", &v)
		if err != nil {
			return nil, err
		}
		ip[i*4+0] = byte(v >> 24)
		ip[i*4+1] = byte(v >> 16)
		ip[i*4+2] = byte(v >> 8)
		ip[i*4+3] = byte(v)
	}
	return ip, nil
}

// parseIPv6Mask creates a net.IPMask from a prefix length.
func parseIPv6Mask(ones int) net.IPMask {
	if ones < 0 || ones > 128 {
		return nil
	}
	m := make(net.IPMask, 16)
	for i := 0; i < 16; i++ {
		if ones >= 8 {
			m[i] = 0xff
			ones -= 8
		} else if ones > 0 {
			m[i] = byte(0xff << (8 - ones))
			ones = 0
		}
	}
	return m
}

// parseIfaceName extracts the interface name from a net.route message,
// trimming null bytes.
func parseIfaceName(raw string) string {
	return strings.TrimRight(raw, "\x00")
}
