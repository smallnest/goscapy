package packetlist

import (
	"fmt"
	"net"
	"sort"

	"github.com/smallnest/goscapy/pkg/packet"
)

// SessionKey identifies a conversation. For IP-based traffic it is the
// canonicalized 5-tuple (protocol + unordered endpoint pair) so that both
// directions of a flow map to the same key. For non-IP traffic it falls back
// to a protocol-stack string.
type SessionKey string

// Sessions groups the list's packets into conversations, mirroring Scapy's
// pl.sessions(). Packets belonging to the same bidirectional flow (TCP/UDP
// 5-tuple, ICMP by host pair, or otherwise by stack signature) are collected
// into their own PacketList, preserving capture order within each session.
//
// The returned map is keyed by SessionKey; use SessionKeys for a stable,
// sorted ordering.
func (pl *PacketList) Sessions() map[SessionKey]*PacketList {
	sessions := make(map[SessionKey]*PacketList)
	for _, e := range pl.entries {
		key := sessionKey(e.Packet)
		s, ok := sessions[key]
		if !ok {
			s = &PacketList{name: string(key)}
			sessions[key] = s
		}
		s.entries = append(s.entries, e)
	}
	return sessions
}

// SessionKeys returns the keys of Sessions() in a stable, sorted order.
func (pl *PacketList) SessionKeys() []SessionKey {
	sessions := pl.Sessions()
	keys := make([]SessionKey, 0, len(sessions))
	for k := range sessions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// sessionKey computes the canonical conversation key for a packet.
func sessionKey(pkt *packet.Packet) SessionKey {
	srcIP, dstIP, ok := packetIPs(pkt)
	if !ok {
		// Non-IP: group by full stack signature.
		return SessionKey(pkt.String())
	}

	// Determine transport and ports if present.
	if tcp := pkt.GetLayer("TCP"); tcp != nil {
		sp, dp := ports(tcp)
		return tupleKey("TCP", srcIP, sp, dstIP, dp)
	}
	if udp := pkt.GetLayer("UDP"); udp != nil {
		sp, dp := ports(udp)
		return tupleKey("UDP", srcIP, sp, dstIP, dp)
	}
	if sctp := pkt.GetLayer("SCTP"); sctp != nil {
		sp, dp := ports(sctp)
		return tupleKey("SCTP", srcIP, sp, dstIP, dp)
	}
	// IP without recognized transport (ICMP, etc.): group by host pair.
	return hostPairKey(srcIP, dstIP)
}

// packetIPs extracts the source and destination IPs from the IP/IPv6 layer.
func packetIPs(pkt *packet.Packet) (src, dst net.IP, ok bool) {
	if ip := pkt.GetLayer("IP"); ip != nil {
		s, _ := ip.Get("src")
		d, _ := ip.Get("dst")
		return toIP(s), toIP(d), true
	}
	if ip := pkt.GetLayer("IPv6"); ip != nil {
		s, _ := ip.Get("src")
		d, _ := ip.Get("dst")
		return toIP(s), toIP(d), true
	}
	return nil, nil, false
}

func toIP(v any) net.IP {
	switch t := v.(type) {
	case net.IP:
		return t
	case string:
		return net.ParseIP(t)
	case []byte:
		return net.IP(t)
	}
	return nil
}

func ports(l *packet.Layer) (sport, dport uint16) {
	if v, err := l.Get("sport"); err == nil {
		sport, _ = v.(uint16)
	}
	if v, err := l.Get("dport"); err == nil {
		dport, _ = v.(uint16)
	}
	return sport, dport
}

// tupleKey builds a direction-independent 5-tuple key by ordering the two
// (IP, port) endpoints so that A↔B and B↔A collapse to one session.
func tupleKey(proto string, src net.IP, sport uint16, dst net.IP, dport uint16) SessionKey {
	a := fmt.Sprintf("%s:%d", src.String(), sport)
	b := fmt.Sprintf("%s:%d", dst.String(), dport)
	if a > b {
		a, b = b, a
	}
	return SessionKey(fmt.Sprintf("%s %s <> %s", proto, a, b))
}

// hostPairKey builds a direction-independent key for IP traffic without ports.
func hostPairKey(src, dst net.IP) SessionKey {
	a, b := src.String(), dst.String()
	if a > b {
		a, b = b, a
	}
	return SessionKey(fmt.Sprintf("IP %s <> %s", a, b))
}
