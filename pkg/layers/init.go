package layers

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	// IP over Ethernet → Ether.type = 0x0800
	packet.RegisterBinding("IP", "Ethernet", "type", uint16(0x0800))
	// ARP over Ethernet → Ether.type = 0x0806
	packet.RegisterBinding("ARP", "Ethernet", "type", uint16(0x0806))
	// RARP over Ethernet → Ether.type = 0x8035
	packet.RegisterBinding("RARP", "Ethernet", "type", uint16(0x8035))
}