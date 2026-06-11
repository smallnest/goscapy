package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// EtherType values for MPLS unicast and multicast.
const (
	EtherTypeMPLSUnicast   uint16 = 0x8847
	EtherTypeMPLSMulticast uint16 = 0x8848
)

// NewMPLS creates an MPLS label stack entry layer (RFC 3032).
// Each entry is 32 bits packed as a single field "lse":
//
//	label(20) | traffic class / exp(3) | bottom-of-stack(1) | TTL(8)
//
// Use MakeMPLSLSE to construct the packed value, and the MPLSLabel/MPLSExp/
// MPLSBottom/MPLSTTL helpers to extract fields. Multiple MPLS layers may be
// stacked; the bottom-of-stack bit (s=1) marks the last entry.
func NewMPLS() *packet.Layer {
	return packet.NewLayer("MPLS", []fields.Field{
		fields.NewIntField("lse", MakeMPLSLSE(0, 0, true, 64)),
	})
}

// NewMPLSWith creates an MPLS layer with the given label, traffic class,
// bottom-of-stack flag, and TTL.
func NewMPLSWith(label uint32, tc uint8, bottom bool, ttl uint8) *packet.Layer {
	l := NewMPLS()
	_ = l.Set("lse", MakeMPLSLSE(label, tc, bottom, ttl))
	return l
}

// MakeMPLSLSE packs the MPLS label stack entry fields into a single uint32.
// label is 20 bits, tc (traffic class / EXP) is 3 bits, bottom is the
// bottom-of-stack bit, and ttl is 8 bits.
func MakeMPLSLSE(label uint32, tc uint8, bottom bool, ttl uint8) uint32 {
	var s uint32
	if bottom {
		s = 1
	}
	return (label&0xFFFFF)<<12 | uint32(tc&0x7)<<9 | s<<8 | uint32(ttl)
}

// MPLSLabel extracts the 20-bit label from a packed LSE.
func MPLSLabel(lse uint32) uint32 { return (lse >> 12) & 0xFFFFF }

// MPLSExp extracts the 3-bit traffic class (EXP) field from a packed LSE.
func MPLSExp(lse uint32) uint8 { return uint8((lse >> 9) & 0x7) }

// MPLSBottom extracts the bottom-of-stack flag from a packed LSE.
func MPLSBottom(lse uint32) bool { return (lse>>8)&0x1 == 1 }

// MPLSTTL extracts the 8-bit TTL from a packed LSE.
func MPLSTTL(lse uint32) uint8 { return uint8(lse & 0xFF) }
