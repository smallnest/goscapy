package arping

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Host represents a discovered host from ARP scanning.
type Host struct {
	IP    string
	MAC   string
	RTT   time.Duration
}

// ArpingResult holds the results of an ARP scan.
type ArpingResult struct {
	CIDR      string
	Interface string
	Hosts     []Host
	Duration  time.Duration
}

// Options configures ARP scan behavior.
type Options struct {
	Timeout     time.Duration
	Concurrency int
	Interface   string
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:     1500 * time.Millisecond,
		Concurrency: 50,
	}
}

// Arping performs an ARP scan on the given CIDR network.
// Supports single IP ("192.168.1.1") or CIDR notation ("192.168.1.0/24").
func Arping(target string, opts Options) (*ArpingResult, error) {
	// Determine if target is a single IP or CIDR.
	var ips []string
	var cidr string

	if strings.Contains(target, "/") {
		cidr = target
		var err error
		ips, err = cidrToIPs(target)
		if err != nil {
			return nil, fmt.Errorf("arping: %w", err)
		}
	} else {
		ip := net.ParseIP(target)
		if ip == nil {
			return nil, fmt.Errorf("arping: invalid IP: %s", target)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("arping: IPv6 not supported")
		}
		ips = []string{ip4.String()}
		cidr = ip4.String() + "/32"
	}

	// Determine interface.
	iface := opts.Interface
	if iface == "" {
		iface = defaultIface()
	}

	srcMAC := getSrcMAC(iface)
	srcIP := getSrcIP(iface)

	result := &ArpingResult{
		CIDR:      cidr,
		Interface: iface,
	}

	start := time.Now()

	// Parallel scanning with semaphore.
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			host := arpProbe(iface, srcMAC, srcIP, targetIP, opts.Timeout)
			if host != nil {
				mu.Lock()
				result.Hosts = append(result.Hosts, *host)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	result.Duration = time.Since(start)

	// Sort by IP.
	sort.Slice(result.Hosts, func(i, j int) bool {
		return result.Hosts[i].IP < result.Hosts[j].IP
	})

	return result, nil
}

// ArpingSingle performs a single ARP request to one IP.
// Returns the MAC address or empty string if no response.
func ArpingSingle(ip string, iface string, timeout time.Duration) (string, error) {
	if iface == "" {
		iface = defaultIface()
	}
	srcMAC := getSrcMAC(iface)
	srcIP := getSrcIP(iface)

	host := arpProbe(iface, srcMAC, srcIP, ip, timeout)
	if host == nil {
		return "", nil
	}
	return host.MAC, nil
}

// String returns a formatted table of discovered hosts.
func (r *ArpingResult) String() string {
	var buf strings.Builder
	fmt.Fprintf(&buf, "ARP scan: %s on %s\n", r.CIDR, r.Interface)
	fmt.Fprintf(&buf, "%-16s %-18s %s\n", "IP", "MAC", "RTT")
	buf.WriteString(strings.Repeat("-", 50))
	buf.WriteByte('\n')

	for _, h := range r.Hosts {
		fmt.Fprintf(&buf, "%-16s %-18s %.1fms\n", h.IP, h.MAC, h.RTT.Seconds()*1000)
	}

	buf.WriteString(strings.Repeat("-", 50))
	buf.WriteByte('\n')
	fmt.Fprintf(&buf, "Found %d hosts in %.2fs\n", len(r.Hosts), r.Duration.Seconds())
	return buf.String()
}

// ---- Internal helpers ----

func arpProbe(iface, srcMAC, srcIP, targetIP string, timeout time.Duration) *Host {
	pkt := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").
		SrcMAC(srcMAC).
		Type(layers.EtherTypeARP).
		Over(goscapy.NewARP().
			Op(layers.ARPWhoHas).
			SrcMAC(srcMAC).
			DstMAC("00:00:00:00:00:00").
			SrcIP(srcIP).
			DstIP(targetIP)).
		Packet()

	start := time.Now()
	_, reply, err := sendrecv.Srp1(pkt, iface, timeout, nil)
	rtt := time.Since(start)

	if err != nil || reply == nil {
		return nil
	}

	arpLayer := reply.GetLayer("ARP")
	if arpLayer == nil {
		return nil
	}

	hwSrc, _ := arpLayer.Get("hwsrc")
	if hwSrc == nil {
		return nil
	}

	macVal, ok := hwSrc.(net.HardwareAddr)
	if !ok {
		return nil
	}

	mac := macVal.String()
	if mac == "00:00:00:00:00:00" {
		return nil
	}

	return &Host{
		IP:  targetIP,
		MAC: mac,
		RTT: rtt,
	}
}

func cidrToIPs(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ip4 := ip.To4()
		if ip4 != nil {
			ips = append(ips, ip4.String())
		}
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func getSrcMAC(iface string) string {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return "00:00:00:00:00:00"
	}
	return i.HardwareAddr.String()
}

func getSrcIP(iface string) string {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return "0.0.0.0"
	}
	addrs, err := i.Addrs()
	if err != nil || len(addrs) == 0 {
		return "0.0.0.0"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "0.0.0.0"
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "en0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			return iface.Name
		}
	}
	return "en0"
}
