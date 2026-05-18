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

	// ---- Dissect (parsing) registrations ----

	// Register layer factories.
	packet.RegisterLayer("Ethernet", NewEthernet)
	packet.RegisterLayer("ARP", NewARP)
	packet.RegisterLayer("IP", NewIP)
	packet.RegisterLayer("ICMP", NewICMP)
	packet.RegisterLayer("TCP", NewTCP)
	packet.RegisterLayer("UDP", NewUDP)
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
	packet.RegisterNextLayer("IP", 1, "ICMP")  // ICMP
	packet.RegisterNextLayer("IP", 6, "TCP")   // TCP
	packet.RegisterNextLayer("IP", 17, "UDP")  // UDP

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
}
