package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ARP operation codes.
const (
	ARPWhoHas  uint16 = 1 // ARP request
	ARPIsAt    uint16 = 2 // ARP reply
	RARPWhoIs  uint16 = 3
	RARPIsAt   uint16 = 4
)

// ARP hardware type constants.
const (
	ARPHwEthernet uint16 = 1
)

// NewARP creates an ARP message layer with sensible defaults for Ethernet+IPv4.
// Defaults: hwtype=Ethernet(1), ptype=IPv4(0x0800), hwlen=6, plen=4, op=WHO-HAS(1).
func NewARP() *packet.Layer {
	return packet.NewLayer("ARP", []fields.Field{
		fields.NewShortField("hwtype", ARPHwEthernet),
		fields.NewShortField("ptype", EtherTypeIPv4),
		fields.NewByteField("hwlen", 6),
		fields.NewByteField("plen", 4),
		fields.NewShortField("op", ARPWhoHas),
		fields.NewMACField("hwsrc", nil),
		fields.NewIPField("psrc", nil),
		fields.NewMACField("hwdst", nil),
		fields.NewIPField("pdst", nil),
	})
}