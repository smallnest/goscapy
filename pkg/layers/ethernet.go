package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// EtherType constants.
const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeRARP uint16 = 0x8035
	EtherTypeIPv6 uint16 = 0x86DD
)

// NewEthernet creates an Ethernet frame layer with default (zero) values.
// dst and src are 6-byte MAC addresses; type is an EtherType constant.
func NewEthernet() *packet.Layer {
	return packet.NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", nil),
		fields.NewMACField("src", nil),
		fields.NewShortField("type", 0),
	})
}

// NewEthernetWith creates an Ethernet frame with the given values.
func NewEthernetWith(dst, src string, etype uint16) *packet.Layer {
	l := NewEthernet()
	l.Set("dst", dst)
	l.Set("src", src)
	l.Set("type", etype)
	return l
}
