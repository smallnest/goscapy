package layers

import "github.com/smallnest/goscapy/pkg/packet"

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
	packet.RegisterBuildHook("ICMP", icmpBuildHook)
	packet.RegisterBuildHook("TCP", tcpBuildHook)
	packet.RegisterBuildHook("UDP", udpBuildHook)
}
