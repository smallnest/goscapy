//go:build darwin

package route

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Table4 reads the IPv4 routing table via netstat (macOS).
func Table4() ([]Route, error) {
	return parseNetstat("-f", "inet")
}

// Table6 reads the IPv6 routing table via netstat (macOS).
func Table6() ([]Route, error) {
	return parseNetstat("-f", "inet6")
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

func parseNetstat(args ...string) ([]Route, error) {
	cmd := exec.Command("netstat", append([]string{"-rn"}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("route: netstat: %w", err)
	}

	var routes []Route
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	isIPv6 := len(args) >= 2 && args[1] == "inet6"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Internet") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip header lines.
		if fields[0] == "Destination" || fields[0] == "Destination/Mask" {
			continue
		}

		dstStr := fields[0]
		gwStr := fields[1]
		// fields[2] = Flags, fields[3] = Netif
		iface := ""
		if len(fields) >= 4 {
			iface = fields[3]
		}

		metric := 0
		// No metric column in macOS netstat.

		var gateway net.IP
		gw := net.ParseIP(gwStr)
		if gw != nil && !gw.IsUnspecified() {
			gateway = gw
		}

		var dest *net.IPNet
		if isIPv6 {
			dest = parseIPv6Destination(dstStr)
		} else {
			dest = parseIPv4Destination(dstStr)
		}

		routes = append(routes, Route{
			Destination: dest,
			Gateway:     gateway,
			Interface:   iface,
			Metric:      metric,
		})
	}

	return routes, scanner.Err()
}

func parseIPv4Destination(s string) *net.IPNet {
	if s == "default" {
		return nil
	}

	// Handle CIDR notation.
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err == nil {
			return ipnet
		}
	}

	// Handle "address/mask" format like "192.168/24" or plain IP.
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err == nil {
			return ipnet
		}
	}

	// Plain IP: treat as /32.
	ip := net.ParseIP(s)
	if ip != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}

	return nil
}

func parseIPv6Destination(s string) *net.IPNet {
	if s == "default" {
		return nil
	}

	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err == nil {
			return ipnet
		}
	}

	ip := net.ParseIP(s)
	if ip != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}

	return nil
}
