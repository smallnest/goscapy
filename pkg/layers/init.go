package layers

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/packet"
)

func init() {
	// Layer binding rules.
	// IP over Ethernet → Ether.type = 0x0800
	packet.RegisterBinding("IP", "Ethernet", "type", uint16(0x0800))
	// ARP over Ethernet → Ether.type = 0x0806
	packet.RegisterBinding("ARP", "Ethernet", "type", uint16(0x0806))
	// RARP over Ethernet → Ether.type = 0x8035
	packet.RegisterBinding("RARP", "Ethernet", "type", uint16(0x8035))
	// TCP over IP → IP.proto = 6
	packet.RegisterBinding("TCP", "IP", "proto", uint8(6))
	// UDP over IP → IP.proto = 17
	packet.RegisterBinding("UDP", "IP", "proto", uint8(17))
	// ICMP over IP → IP.proto = 1
	packet.RegisterBinding("ICMP", "IP", "proto", uint8(1))

	// Build hooks for derived field auto-computation.
	packet.RegisterBuildHook("IP", ipBuildHook)
	packet.RegisterBuildHook("IPv6", ipv6BuildHook)
	packet.RegisterBuildHook("ICMPv6", icmpv6BuildHook)
	packet.RegisterBuildHook("ICMP", icmpBuildHook)
	packet.RegisterBuildHook("TCP", tcpBuildHook)
	packet.RegisterBuildHook("UDP", udpBuildHook)

	// ---- Dissect (parsing) registrations ----

	// Register layer factories.
	packet.RegisterLayer("Ethernet", NewEthernet)
	packet.RegisterLayer("ARP", NewARP)
	packet.RegisterLayer("IP", NewIP)
	packet.RegisterLayer("IPv6", NewIPv6)
	packet.RegisterLayer("IPv6 Hop-by-Hop", NewIPv6HopByHop)
	packet.RegisterLayer("IPv6 Routing", NewIPv6Routing)
	packet.RegisterLayer("IPv6 Fragment", NewIPv6Fragment)
	packet.RegisterLayer("IPv6 DestOpts", NewIPv6DestOpts)
	packet.RegisterLayer("ICMP", NewICMP)
	packet.RegisterLayer("TCP", NewTCP)
	packet.RegisterLayer("UDP", NewUDP)
	packet.RegisterLayer("ICMPv6", NewICMPv6)
	packet.RegisterLayer("ICMPv6 Echo", newICMPv6EchoLayer)
	packet.RegisterLayer("ICMPv6 Echo Reply", newICMPv6EchoReplyLayer)
	packet.RegisterLayer("NDP Router Solicitation", NewNDPRouterSolicitation)
	packet.RegisterLayer("NDP Router Advertisement", NewNDPRouterAdvertisement)
	packet.RegisterLayer("NDP Neighbor Solicitation", NewNDPNeighborSolicitation)
	packet.RegisterLayer("NDP Neighbor Advertisement", NewNDPNeighborAdvertisement)
	packet.RegisterLayer("NDP Redirect", NewNDPRedirect)
	packet.RegisterLayer("Raw", NewRaw)

	// Register key fields for next-layer resolution.
	// Ethernet uses "type" field to identify the upper layer.
	packet.RegisterKeyField("Ethernet", "type")
	// IP uses "proto" field to identify the upper layer.
	packet.RegisterKeyField("IP", "proto")

	// Register next-layer mappings: Ethernet.type → upper protocol.
	packet.RegisterNextLayer("Ethernet", 0x0800, "IP")
	packet.RegisterNextLayer("Ethernet", 0x0806, "ARP")
	packet.RegisterNextLayer("Ethernet", 0x8035, "RARP")

	// Register next-layer mappings: IP.proto → upper protocol.
	packet.RegisterNextLayer("IP", 1, "ICMP") // ICMP
	packet.RegisterNextLayer("IP", 6, "TCP")  // TCP
	packet.RegisterNextLayer("IP", 17, "UDP") // UDP

	// Register key fields for IPv6 and extension headers.
	packet.RegisterKeyField("IPv6", "nh")
	packet.RegisterKeyField("IPv6 Hop-by-Hop", "nh")
	packet.RegisterKeyField("IPv6 Routing", "nh")
	packet.RegisterKeyField("IPv6 Fragment", "nh")
	packet.RegisterKeyField("IPv6 DestOpts", "nh")

	// ICMPv6 uses "type" for sub-type resolution (Echo, NDP, etc.).
	packet.RegisterKeyField("ICMPv6", "type")

	// Register next-layer mappings: IPv6 nh → extension header or upper protocol.
	packet.RegisterNextLayer("IPv6", 0, "IPv6 Hop-by-Hop")
	packet.RegisterNextLayer("IPv6", 43, "IPv6 Routing")
	packet.RegisterNextLayer("IPv6", 44, "IPv6 Fragment")
	packet.RegisterNextLayer("IPv6", 60, "IPv6 DestOpts")
	packet.RegisterNextLayer("IPv6", 58, "ICMPv6")
	packet.RegisterNextLayer("IPv6", 6, "TCP")
	packet.RegisterNextLayer("IPv6", 17, "UDP")

	// ICMPv6 type → sub-layer (Echo, NDP).
	packet.RegisterNextLayer("ICMPv6", 128, "ICMPv6 Echo")
	packet.RegisterNextLayer("ICMPv6", 129, "ICMPv6 Echo Reply")
	packet.RegisterNextLayer("ICMPv6", 133, "NDP Router Solicitation")
	packet.RegisterNextLayer("ICMPv6", 134, "NDP Router Advertisement")
	packet.RegisterNextLayer("ICMPv6", 135, "NDP Neighbor Solicitation")
	packet.RegisterNextLayer("ICMPv6", 136, "NDP Neighbor Advertisement")
	packet.RegisterNextLayer("ICMPv6", 137, "NDP Redirect")

	// Extension headers can chain to each other or to upper protocols.
	packet.RegisterNextLayer("IPv6 Hop-by-Hop", 44, "IPv6 Fragment")
	packet.RegisterNextLayer("IPv6 Hop-by-Hop", 58, "ICMPv6")
	packet.RegisterNextLayer("IPv6 Hop-by-Hop", 6, "TCP")
	packet.RegisterNextLayer("IPv6 Hop-by-Hop", 17, "UDP")
	packet.RegisterNextLayer("IPv6 Fragment", 58, "ICMPv6")
	packet.RegisterNextLayer("IPv6 Fragment", 6, "TCP")
	packet.RegisterNextLayer("IPv6 Fragment", 17, "UDP")
	packet.RegisterNextLayer("IPv6 DestOpts", 58, "ICMPv6")
	packet.RegisterNextLayer("IPv6 DestOpts", 6, "TCP")
	packet.RegisterNextLayer("IPv6 DestOpts", 17, "UDP")

	// ---- Heuristic registrations (port-based, EtherType-based) ----

	// DNS: UDP port 53.
	packet.RegisterHeuristic("UDP", "dport", uint16(53), "DNS")
	packet.RegisterHeuristic("UDP", "sport", uint16(53), "DNS")
	// DHCP: UDP port 67 (server) or 68 (client).
	packet.RegisterHeuristic("UDP", "dport", uint16(67), "DHCP")
	packet.RegisterHeuristic("UDP", "sport", uint16(67), "DHCP")
	packet.RegisterHeuristic("UDP", "dport", uint16(68), "DHCP")
	packet.RegisterHeuristic("UDP", "sport", uint16(68), "DHCP")
	// VXLAN: UDP port 4789.
	packet.RegisterHeuristic("UDP", "dport", uint16(4789), "VXLAN")
	// GRE: IP protocol 47.
	packet.RegisterHeuristic("IP", "proto", uint8(47), "GRE")
	// IPv6: Ethernet type 0x86DD.
	packet.RegisterHeuristic("Ethernet", "type", uint16(0x86DD), "IPv6")
	// Dot1Q: Ethernet type 0x8100 (single VLAN) and 0x88A8 (QinQ outer).
	packet.RegisterHeuristic("Ethernet", "type", uint16(0x8100), "Dot1Q")

	// ---- Tunnel payload registrations ----

	// VXLAN payload is an inner Ethernet frame.
	packet.RegisterTunnelPayload("VXLAN", "Ethernet")
	// GRE with ProtocolType=0x6558 carries inner Ethernet.
	packet.RegisterTunnelPayload("GRE", "IP")

	// ---- Dissector registrations for DissectByProto ----

	// Ethernet dissector: requires at least 14 bytes.
	packet.RegisterDissector("Ethernet", func(data []byte) (string, int, error) {
		if len(data) < 14 {
			return "", 0, fmt.Errorf("layers: Ethernet needs at least 14 bytes, got %d", len(data))
		}
		return "Ethernet", 0, nil
	})

	// Register variable header size functions.
	// IP: IHL (lower nibble of verihl) * 4 bytes.
	packet.RegisterHeaderSizeFunc("IP", func(layer *packet.Layer) int {
		verihl, _ := layer.Get("verihl")
		return int(verihl.(uint8)&0x0F) * 4
	})

	// TCP: dataofs (upper nibble) * 4 bytes.
	packet.RegisterHeaderSizeFunc("TCP", func(layer *packet.Layer) int {
		dataofs, _ := layer.Get("dataofs")
		return int(dataofs.(uint8)>>4) * 4
	})

	// IPv6 extension headers: (Hdr Ext Len + 1) * 8 bytes.
	packet.RegisterHeaderSizeFunc("IPv6 Hop-by-Hop", extHdrSizeFn)
	packet.RegisterHeaderSizeFunc("IPv6 Routing", extHdrSizeFn)
	packet.RegisterHeaderSizeFunc("IPv6 DestOpts", extHdrSizeFn)
}
