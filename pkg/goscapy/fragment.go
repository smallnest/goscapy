package goscapy

import (
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Fragment splits an IPv4 packet into fragment packets, each carrying at most
// fragSize bytes of the original L4 payload. It mirrors Scapy's fragment().
// If fragSize <= 0, layers.DefaultFragSize (1480) is used. See
// layers.Fragment for full semantics.
func Fragment(pkt *packet.Packet, fragSize int) ([]*packet.Packet, error) {
	return layers.Fragment(pkt, fragSize)
}

// Fragment6 splits an IPv6 packet into fragments using an IPv6 Fragment
// extension header, mirroring Scapy's fragment6(). fragID is the fragment
// identification shared by all fragments. See layers.Fragment6 for full
// semantics.
func Fragment6(pkt *packet.Packet, fragSize int, fragID uint32) ([]*packet.Packet, error) {
	return layers.Fragment6(pkt, fragSize, fragID)
}
