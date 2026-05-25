package traceroute

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Protocol specifies the traceroute probe type.
type Protocol int

const (
	ProtoICMP Protocol = iota
	ProtoTCP
	ProtoUDP
)

// Hop represents a single traceroute hop result.
type Hop struct {
	TTL    int
	IP     string
	RTT    time.Duration
	ASNum  string
	ASName string
	Err    error
}

// TracerouteResult holds the complete traceroute results.
type TracerouteResult struct {
	Dst      string
	DstIP    string
	Protocol Protocol
	MaxTTL   int
	Hops     []Hop
	Reached  bool
}

// Options configures traceroute behavior.
type Options struct {
	MaxTTL   int
	Timeout  time.Duration
	Probes   int // probes per hop
	Port     uint16
	Protocol Protocol
	Interface string
	ResolveAS bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		MaxTTL:    30,
		Timeout:   2 * time.Second,
		Probes:    3,
		Port:      80,
		Protocol:  ProtoICMP,
		ResolveAS: true,
	}
}

// Traceroute performs a traceroute to the given destination.
func Traceroute(dst string, opts Options) (*TracerouteResult, error) {
	host := dst
	if ip := net.ParseIP(dst); ip == nil {
		addrs, err := net.LookupHost(dst)
		if err != nil {
			return nil, fmt.Errorf("traceroute: resolve %s: %w", dst, err)
		}
		host = addrs[0]
	}

	dstIP := net.ParseIP(host)
	if dstIP == nil {
		return nil, fmt.Errorf("traceroute: invalid IP: %s", host)
	}
	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return nil, fmt.Errorf("traceroute: IPv6 not supported yet")
	}

	nic := opts.Interface
	if nic == "" {
		nic = detectInterface(dstIP4)
	}

	srcIP := getLocalIP(nic)
	if srcIP == nil {
		return nil, fmt.Errorf("traceroute: no local IP on %s", nic)
	}

	pid := uint16(os.Getpid() & 0xFFFF)
	result := &TracerouteResult{
		Dst:      dst,
		DstIP:    host,
		Protocol: opts.Protocol,
		MaxTTL:   opts.MaxTTL,
	}

	match := buildMatcher(dstIP4, pid, opts)

	for ttl := 1; ttl <= opts.MaxTTL; ttl++ {
		hop := Hop{TTL: ttl}
		var rtts []time.Duration
		reached := false

		for probe := 0; probe < opts.Probes; probe++ {
			pkt := buildProbe(srcIP, dstIP4, ttl, pid, probe, opts)
			if pkt == nil {
				continue
			}

			start := time.Now()
			_, resp, err := sendrecv.Sr1(pkt, nic, opts.Timeout, match)
			rtt := time.Since(start)

			if err != nil || resp == nil {
				continue
			}

			ipLayer := resp.GetLayer("IP")
			if ipLayer != nil {
				if srcVal, err := ipLayer.Get("src"); err == nil && srcVal != nil {
					hop.IP = srcVal.(net.IP).String()
				}
			}

			icmpLayer := resp.GetLayer("ICMP")
			if icmpLayer != nil {
				if typeVal, err := icmpLayer.Get("type"); err == nil && typeVal != nil {
					if typeVal.(uint8) == 0 {
						reached = true
					}
				}
			}

			// Also check for TCP RST/SYN-ACK as reachability indicator.
			tcpLayer := resp.GetLayer("TCP")
			if tcpLayer != nil {
				if flagsVal, err := tcpLayer.Get("flags"); err == nil && flagsVal != nil {
					flags := flagsVal.(uint8)
					if flags&layers.TCPSyn != 0 || flags&layers.TCPRst != 0 {
						reached = true
					}
				}
			}

			rtts = append(rtts, rtt)
		}

		if len(rtts) > 0 {
			// Use minimum RTT.
			hop.RTT = minRTT(rtts)
		}

		result.Hops = append(result.Hops, hop)

		if reached {
			result.Reached = true
			break
		}

		if hop.IP == "" && ttl > 1 {
			// Check if last hop also had no IP — possible end.
			allEmpty := true
			for i := len(result.Hops) - 1; i >= 0 && i >= len(result.Hops)-3; i-- {
				if result.Hops[i].IP != "" {
					allEmpty = false
					break
				}
			}
			if allEmpty && ttl >= 5 {
				break
			}
		}
	}

	// Resolve AS numbers in parallel.
	if opts.ResolveAS {
		resolveASNumbers(result.Hops)
	}

	return result, nil
}

// String returns a formatted table of the traceroute result.
func (r *TracerouteResult) String() string {
	var buf strings.Builder
	protoName := "ICMP"
	switch r.Protocol {
	case ProtoTCP:
		protoName = "TCP"
	case ProtoUDP:
		protoName = "UDP"
	}
	fmt.Fprintf(&buf, "traceroute to %s (%s), %d hops max, %s probes\n\n",
		r.Dst, r.DstIP, r.MaxTTL, protoName)

	for _, hop := range r.Hops {
		fmt.Fprintf(&buf, "%2d  ", hop.TTL)
		if hop.IP == "" {
			buf.WriteString("*\n")
			continue
		}

		asInfo := ""
		if hop.ASNum != "" {
			asInfo = fmt.Sprintf(" [AS%s", hop.ASNum)
			if hop.ASName != "" {
				asInfo += " " + hop.ASName
			}
			asInfo += "]"
		}
		fmt.Fprintf(&buf, "%-15s %8.2f ms%s\n", hop.IP, hop.RTT.Seconds()*1000, asInfo)
	}

	if r.Reached {
		buf.WriteString("\nReached destination.\n")
	}
	return buf.String()
}

// Graph returns a DOT format graph for Graphviz visualization.
func (r *TracerouteResult) Graph() string {
	var buf strings.Builder
	buf.WriteString("digraph traceroute {\n")
	buf.WriteString("  rankdir=TB;\n")
	buf.WriteString("  node [shape=box];\n")
	buf.WriteString(fmt.Sprintf("  src [label=\"Source\"];\n"))
	buf.WriteString(fmt.Sprintf("  dst [label=\"%s (%s)\"];\n", r.Dst, r.DstIP))

	prev := "src"
	for _, hop := range r.Hops {
		if hop.IP == "" {
			continue
		}
		nodeName := fmt.Sprintf("h%d", hop.TTL)
		label := hop.IP
		if hop.ASNum != "" {
			label += fmt.Sprintf("\\nAS%s", hop.ASNum)
			if hop.ASName != "" {
				label += " " + hop.ASName
			}
		}
		fmt.Fprintf(&buf, "  %s [label=\"%s\"];\n", nodeName, label)
		fmt.Fprintf(&buf, "  %s -> %s [label=\"%.1fms\"];\n", prev, nodeName, hop.RTT.Seconds()*1000)
		prev = nodeName
	}
	fmt.Fprintf(&buf, "  %s -> dst;\n", prev)
	buf.WriteString("}\n")
	return buf.String()
}

// ---- Internal helpers ----

func buildProbe(srcIP, dstIP net.IP, ttl int, pid uint16, probe int, opts Options) *packet.Packet {
	switch opts.Protocol {
	case ProtoTCP:
		return buildTCPProbe(srcIP, dstIP, ttl, pid, probe, opts)
	case ProtoUDP:
		return buildUDPProbe(srcIP, dstIP, ttl, pid, probe, opts)
	default:
		return buildICMPProbe(srcIP, dstIP, ttl, pid, probe)
	}
}

func buildICMPProbe(srcIP, dstIP net.IP, ttl int, pid uint16, probe int) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", srcIP)
	ip.Set("dst", dstIP)
	ip.Set("ttl", uint8(ttl))
	icmp := layers.NewICMPEcho(pid, uint16(ttl*1000+probe))
	return ip.Over(icmp)
}

func buildTCPProbe(srcIP, dstIP net.IP, ttl int, pid uint16, probe int, opts Options) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", srcIP)
	ip.Set("dst", dstIP)
	ip.Set("ttl", uint8(ttl))
	tcp := layers.NewTCP()
	tcp.Set("sport", pid+uint16(probe))
	tcp.Set("dport", opts.Port)
	tcp.Set("flags", uint8(layers.TCPSyn))
	return ip.Over(tcp)
}

func buildUDPProbe(srcIP, dstIP net.IP, ttl int, pid uint16, probe int, opts Options) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", srcIP)
	ip.Set("dst", dstIP)
	ip.Set("ttl", uint8(ttl))
	udp := layers.NewUDP()
	udp.Set("sport", pid+uint16(probe))
	udp.Set("dport", opts.Port)
	// Add a small payload so the packet isn't empty.
	raw := layers.NewRaw()
	raw.Set("load", []byte{0x00, 0x00, 0x00, 0x00})
	pkt := ip.Over(udp)
	pkt.Push(raw)
	return pkt
}

func buildMatcher(dstIP net.IP, pid uint16, opts Options) sendrecv.MatchFunc {
	return func(sent, received *packet.Packet) bool {
		recvIP := received.GetLayer("IP")
		recvICMP := received.GetLayer("ICMP")
		if recvIP == nil {
			return false
		}

		// TCP response: SYN-ACK or RST
		if opts.Protocol == ProtoTCP {
			recvTCP := received.GetLayer("TCP")
			if recvTCP != nil && recvICMP == nil {
				sentIP := sent.GetLayer("IP")
				if sentIP == nil {
					return false
				}
				sentDst, _ := sentIP.Get("dst")
				recvSrc, _ := recvIP.Get("src")
				if sentDst == nil || recvSrc == nil {
					return false
				}
				return sentDst.(net.IP).Equal(recvSrc.(net.IP))
			}
		}

		if recvICMP == nil {
			return false
		}

		recvTypeVal, err := recvICMP.Get("type")
		if err != nil || recvTypeVal == nil {
			return false
		}
		recvType := recvTypeVal.(uint8)

		sentIP := sent.GetLayer("IP")
		if sentIP == nil {
			return false
		}
		sentDst, _ := sentIP.Get("dst")
		if sentDst == nil {
			return false
		}

		switch recvType {
		case 0: // Echo Reply
			recvSrc, _ := recvIP.Get("src")
			if recvSrc == nil {
				return false
			}
			return recvSrc.(net.IP).Equal(sentDst.(net.IP))

		case 3, 11: // Dest Unreachable, Time Exceeded
			rawLayer := received.GetLayer("Raw")
			if rawLayer == nil {
				return false
			}
			loadVal, err := rawLayer.Get("load")
			if err != nil || loadVal == nil {
				return false
			}
			loadBytes, ok := loadVal.([]byte)
			if !ok || len(loadBytes) < 20 {
				return false
			}

			// The inner IP header starts at the beginning of load.
			// Check inner dst IP matches our target.
			innerDst := net.IP(loadBytes[16:20])
			return innerDst.Equal(sentDst.(net.IP))
		}

		return false
	}
}

// ---- AS Resolution ----

// ASInfo holds autonomous system information for an IP.
type ASInfo struct {
	ASNum  string
	ASName string
}

var asCache sync.Map

// ResolveAS resolves the AS number and name for an IP address using RDAP.
func ResolveAS(ip string) (*ASInfo, error) {
	if cached, ok := asCache.Load(ip); ok {
		return cached.(*ASInfo), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use cymru.com DNS-based AS lookup.
	// Reverse the IP octets and query origin.asn.cymru.com.
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("traceroute: invalid IPv4: %s", ip)
	}
	reversed := fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com", parts[3], parts[2], parts[1], parts[0])

	txtRecords, err := net.DefaultResolver.LookupTXT(ctx, reversed)
	if err != nil || len(txtRecords) == 0 {
		info := &ASInfo{}
		asCache.Store(ip, info)
		return info, nil
	}

	// Format: "ASNumber | IP | ASName | CC | Registry | Created"
	fields := strings.Split(txtRecords[0], " | ")
	info := &ASInfo{}
	if len(fields) >= 1 {
		info.ASNum = strings.TrimSpace(fields[0])
	}
	if len(fields) >= 3 {
		info.ASName = strings.TrimSpace(fields[2])
	}

	asCache.Store(ip, info)
	return info, nil
}

func resolveASNumbers(hops []Hop) {
	var wg sync.WaitGroup
	for i := range hops {
		if hops[i].IP == "" {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			info, err := ResolveAS(hops[idx].IP)
			if err == nil && info != nil {
				hops[idx].ASNum = info.ASNum
				hops[idx].ASName = info.ASName
			}
		}(i)
	}
	wg.Wait()
}

// ---- Utility ----

func detectInterface(dstIP net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "en0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return iface.Name
			}
		}
	}
	return "en0"
}

func getLocalIP(ifaceName string) net.IP {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4
			}
		}
	}
	return nil
}

func minRTT(rtts []time.Duration) time.Duration {
	if len(rtts) == 0 {
		return 0
	}
	m := rtts[0]
	for _, r := range rtts[1:] {
		if r < m {
			m = r
		}
	}
	return m
}
