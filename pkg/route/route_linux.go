//go:build linux

package route

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Table4 reads the IPv4 routing table from /proc/net/route (Linux).
func Table4() ([]Route, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("route: open /proc/net/route: %w", err)
	}
	defer f.Close()

	var routes []Route
	scanner := bufio.NewScanner(f)

	// Skip header line.
	if !scanner.Scan() {
		return nil, fmt.Errorf("route: empty /proc/net/route")
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		iface := fields[0]
		dstHex := fields[1]
		gwHex := fields[2]
		maskHex := fields[7]

		dst, err := parseHexIP(dstHex)
		if err != nil {
			continue
		}

		gw, err := parseHexIP(gwHex)
		if err != nil {
			continue
		}

		mask, err := parseHexIP(maskHex)
		if err != nil {
			continue
		}

		metric := 0
		if len(fields) > 6 {
			metric, _ = strconv.Atoi(fields[6])
		}

		var gateway net.IP
		if !gw.IsUnspecified() {
			gateway = gw
		}

		routes = append(routes, Route{
			Destination: parseIPNet(dst, mask),
			Gateway:     gateway,
			Interface:   iface,
			Metric:      metric,
		})
	}

	return routes, scanner.Err()
}

// Table6 reads the IPv6 routing table from /proc/net/ipv6_route (Linux).
func Table6() ([]Route, error) {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return nil, fmt.Errorf("route: open /proc/net/ipv6_route: %w", err)
	}
	defer f.Close()

	var routes []Route
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		dstHex := fields[0]
		prefixLen, _ := strconv.Atoi(fields[1])
		iface := fields[9]

		dst, err := parseHexIPv6(dstHex)
		if err != nil {
			continue
		}

		var gateway net.IP
		if len(fields) > 4 {
			gw, err := parseHexIPv6(fields[4])
			if err == nil && !gw.IsUnspecified() {
				gateway = gw
			}
		}

		metric := 0
		if len(fields) > 5 {
			metric, _ = strconv.Atoi(fields[5])
		}

		mask := parseIPv6Mask(prefixLen)
		var ipNet *net.IPNet
		if prefixLen > 0 {
			ipNet = &net.IPNet{IP: dst, Mask: mask}
		}

		routes = append(routes, Route{
			Destination: ipNet,
			Gateway:     gateway,
			Interface:   iface,
			Metric:      metric,
		})
	}

	return routes, scanner.Err()
}

// DefaultRoute4 returns the system default IPv4 route.
func DefaultRoute4() (*Route, error) {
	routes, err := Table4()
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].Destination == nil {
			return &routes[i], nil
		}
	}
	return nil, fmt.Errorf("route: no default IPv4 route found")
}

// DefaultRoute6 returns the system default IPv6 route.
func DefaultRoute6() (*Route, error) {
	routes, err := Table6()
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].Destination == nil {
			return &routes[i], nil
		}
	}
	return nil, fmt.Errorf("route: no default IPv6 route found")
}

// InterfaceInfo holds information about a network interface.
type InterfaceInfo struct {
	Name         string
	Index        int
	MTU          int
	Flags        string
	HardwareAddr string
	Addresses    []string
}

// Interfaces returns all network interfaces with their addresses.
func Interfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:  iface.Name,
			Index: iface.Index,
			MTU:   iface.MTU,
			Flags: iface.Flags.String(),
		}
		if iface.HardwareAddr != nil {
			info.HardwareAddr = iface.HardwareAddr.String()
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}
		result = append(result, info)
	}
	return result, nil
}
