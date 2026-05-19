package dot1q

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("Dot1Q", NewDot1QLayer)

	// Dot1Q uses "type" field to determine the next upper-layer protocol.
	packet.RegisterKeyField("Dot1Q", "type")

	// Dot1Q "type" → upper protocol.
	packet.RegisterNextLayer("Dot1Q", uint64(0x0800), "IP")
	packet.RegisterNextLayer("Dot1Q", uint64(0x0806), "ARP")
	packet.RegisterNextLayer("Dot1Q", uint64(0x86DD), "IPv6")
	// QinQ: inner tag is another Dot1Q.
	packet.RegisterNextLayer("Dot1Q", uint64(0x8100), "Dot1Q")
	packet.RegisterNextLayer("Dot1Q", uint64(0x88A8), "Dot1Q")
}