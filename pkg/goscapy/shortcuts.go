package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// EtherIP builds an Ethernet + IPv4 packet with a raw payload.
// srcMAC and dstMAC are MAC addresses; srcIP and dstIP are IPv4 addresses;
// payload is the upper-layer data.
func EtherIP(srcMAC, dstMAC, srcIP, dstIP string, payload []byte) ([]byte, error) {
	return NewEthernet().
		SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Over(&rawBuilder{layers.NewRawWith(payload)}).
		Build()
}

// EtherIPICMP builds a full Ethernet + IPv4 + ICMP Echo Request packet.
// dstMAC is the destination MAC, dstIP is the destination IP.
// icmpType and icmpCode set the ICMP type/code fields.
// Defaults: srcMAC="00:00:00:00:00:00", srcIP="0.0.0.0", id=0, seq=0.
func EtherIPICMP(dstMAC, dstIP string, icmpType, icmpCode uint8) ([]byte, error) {
	return NewEthernet().
		SrcMAC("00:00:00:00:00:00").DstMAC(dstMAC).
		Over(NewIP().SrcIP("0.0.0.0").DstIP(dstIP)).
		Over(NewICMP().Type(icmpType).Code(icmpCode)).
		Build()
}

// EtherIPTCP builds a full Ethernet + IPv4 + TCP packet.
// Defaults: srcMAC="00:00:00:00:00:00", srcIP="0.0.0.0", seq=0, ack=0.
func EtherIPTCP(srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, flags uint8) ([]byte, error) {
	return NewEthernet().
		SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Over(NewTCP().SrcPort(srcPort).DstPort(dstPort).Flags(flags)).
		Build()
}

// EtherIPUDP builds a full Ethernet + IPv4 + UDP packet.
// Defaults: srcMAC="00:00:00:00:00:00", srcIP="0.0.0.0".
func EtherIPUDP(srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16) ([]byte, error) {
	return NewEthernet().
		SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Over(NewUDP().SrcPort(srcPort).DstPort(dstPort)).
		Build()
}

// EtherARP builds a full Ethernet + ARP packet.
// Uses sensible defaults: hwtype=Ethernet, ptype=IPv4, hwlen=6, plen=4.
func EtherARP(srcMAC, dstMAC, psrc, pdst string, op uint16) ([]byte, error) {
	return NewEthernet().
		SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewARP().Op(op).SrcMAC(srcMAC).SrcIP(psrc).DstMAC(dstMAC).DstIP(pdst)).
		Build()
}

// IPICMP builds an IPv4 + ICMP packet (no Ethernet header).
func IPICMP(srcIP, dstIP string, icmpType, icmpCode uint8) ([]byte, error) {
	return NewIP().SrcIP(srcIP).DstIP(dstIP).
		Over(NewICMP().Type(icmpType).Code(icmpCode)).
		Build()
}

// IPTCP builds an IPv4 + TCP packet (no Ethernet header).
func IPTCP(srcIP, dstIP string, srcPort, dstPort uint16, flags uint8) ([]byte, error) {
	return NewIP().SrcIP(srcIP).DstIP(dstIP).
		Over(NewTCP().SrcPort(srcPort).DstPort(dstPort).Flags(flags)).
		Build()
}

// IPUDP builds an IPv4 + UDP packet (no Ethernet header).
func IPUDP(srcIP, dstIP string, srcPort, dstPort uint16) ([]byte, error) {
	return NewIP().SrcIP(srcIP).DstIP(dstIP).
		Over(NewUDP().SrcPort(srcPort).DstPort(dstPort)).
		Build()
}

// rawBuilder is an internal adapter that wraps Raw layers as a LayerBuilder.
type rawBuilder struct {
	layer *packet.Layer
}

func (rb *rawBuilder) Layer() *packet.Layer { return rb.layer }