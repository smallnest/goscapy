package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/layers/erspan"
	"github.com/smallnest/goscapy/pkg/layers/lldp"
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

// IPv6ICMPv6Echo builds an IPv6 + ICMPv6 Echo Request packet.
func IPv6ICMPv6Echo(srcIP, dstIP string, id, seq uint16) ([]byte, error) {
	return NewIPv6().SrcIP(srcIP).DstIP(dstIP).NH(58).
		Over(NewICMPv6().Type(128).Code(0)).
		Over(&rawBuilder{layers.NewICMPv6Echo(id, seq)}).
		Build()
}

// EtherDot1QIP builds an Ethernet + Dot1Q + IPv4 packet with a VLAN tag.
func EtherDot1QIP(srcMAC, dstMAC, srcIP, dstIP string, vid uint16) ([]byte, error) {
	return NewEthernet().SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewDot1Q().VID(vid)).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Build()
}

// EtherIPUDPVXLAN builds an Ethernet + IP + UDP + VXLAN packet with an inner payload.
// Uses UDP port 4789 (standard VXLAN port) for both source and destination.
func EtherIPUDPVXLAN(srcMAC, dstMAC, srcIP, dstIP string, vni uint32, innerPayload []byte) ([]byte, error) {
	return NewEthernet().SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Over(NewUDP().SrcPort(4789).DstPort(4789)).
		Over(NewVXLAN().VNI(vni)).
		Over(&rawBuilder{layers.NewRawWith(innerPayload)}).
		Build()
}

// EtherIPGRE builds an Ethernet + IP + GRE packet with an inner payload.
// protoType sets the GRE Protocol Type (0x0800=IP, 0x6558=Ethernet).
// If key is non-zero, the K flag is set and the key field is included.
func EtherIPGRE(srcMAC, dstMAC, srcIP, dstIP string, protoType uint16, key uint32, innerPayload []byte) ([]byte, error) {
	greBuilder := NewGRE().ProtocolType(protoType)
	if key != 0 {
		greBuilder.Key(key)
	}
	return NewEthernet().SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Over(greBuilder).
		Over(&rawBuilder{layers.NewRawWith(innerPayload)}).
		Build()
}

// EtherIPUDPDNS builds an Ethernet + IP + UDP + DNS query packet.
func EtherIPUDPDNS(srcMAC, dstMAC, srcIP, dstIP string, dnsPort uint16, questions []dns.DNSQuestion) ([]byte, error) {
	return NewEthernet().SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Over(NewUDP().SrcPort(12345).DstPort(dnsPort)).
		Over(NewDNS().Questions(questions)).
		Build()
}

// EtherIPUDPDHCP builds an Ethernet + IP + UDP + DHCP packet.
// Uses broadcast IP (255.255.255.255) and DHCP client/server ports (68/67).
// Default: BOOTREQUEST with specified message type (e.g. dhcp.DHCPDISCOVER).
func EtherIPUDPDHCP(srcMAC, dstMAC string, xid uint32, msgType uint8) ([]byte, error) {
	return NewEthernet().SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP("0.0.0.0").DstIP("255.255.255.255")).
		Over(NewUDP().SrcPort(68).DstPort(67)).
		Over(NewDHCP().XID(xid).MessageType(msgType)).
		Build()
}

// EtherLLDP builds an Ethernet + LLDP frame with default mandatory TLVs.
// LLDP uses destination MAC 01:80:c2:00:00:0e (LLDP multicast) and EtherType 0x88CC.
func EtherLLDP(srcMAC string, du *lldp.LLDPDU) ([]byte, error) {
	tlvData, err := du.Serialize()
	if err != nil {
		return nil, err
	}
	return NewEthernet().SrcMAC(srcMAC).DstMAC("01:80:c2:00:00:0e").Type(0x88CC).
		Over(&rawBuilder{layers.NewRawWith(tlvData)}).
		Build()
}

// EtherIPGREERSPAN builds an Ethernet + IP + GRE + ERSPAN v3 packet.
// GRE protocol type is set to 0x88BE (ERSPAN). The ERSPAN header is serialized
// from the provided ERSPAN struct.
func EtherIPGREERSPAN(srcMAC, dstMAC, srcIP, dstIP string, e *erspan.ERSPAN, innerPayload []byte) ([]byte, error) {
	erspanData, err := e.Serialize()
	if err != nil {
		return nil, err
	}
	payload := append(erspanData, innerPayload...)
	return NewEthernet().SrcMAC(srcMAC).DstMAC(dstMAC).
		Over(NewIP().SrcIP(srcIP).DstIP(dstIP)).
		Over(NewGRE().ProtocolType(0x88BE)).
		Over(&rawBuilder{layers.NewRawWith(payload)}).
		Build()
}

// IPOSPF builds an IPv4 + OSPF packet with specified header fields.
// Default: OSPFv2 Hello message, router_id and area_id set from parameters.
func IPOSPF(srcIP, dstIP, routerID, areaID string, msgType uint8) ([]byte, error) {
	return NewIP().SrcIP(srcIP).DstIP(dstIP).Proto(89).
		Over(NewOSPF().RouterID(routerID).AreaID(areaID).Type(msgType)).
		Build()
}

// IPTCPBGP builds an IPv4 + TCP + BGP packet.
// BGP runs on TCP port 179. The BGP message type is set from the type parameter.
func IPTCPBGP(srcIP, dstIP string, srcPort, dstPort uint16, msgType uint8) ([]byte, error) {
	return NewIP().SrcIP(srcIP).DstIP(dstIP).
		Over(NewTCP().SrcPort(srcPort).DstPort(dstPort)).
		Over(NewBGP().Type(msgType)).
		Build()
}

// IPUDPQUIC builds an IPv4 + UDP + QUIC Long Header packet.
// Default: QUIC v1 with provided connection IDs.
func IPUDPQUIC(srcIP, dstIP string, srcPort, dstPort uint16, dcid, scid []byte) ([]byte, error) {
	return NewIP().SrcIP(srcIP).DstIP(dstIP).
		Over(NewUDP().SrcPort(srcPort).DstPort(dstPort)).
		Over(NewQUIC().DCID(dcid).SCID(scid)).
		Build()
}
