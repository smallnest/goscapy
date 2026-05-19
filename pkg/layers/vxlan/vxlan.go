package vxlan

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

const (
	// FlagI is the VXLAN I flag bit (bit 3), indicating a valid VNI.
	FlagI uint8 = 0x08
)

// VXLAN wraps a packet.Layer with chainable builder methods for VXLAN encapsulation.
type VXLAN struct {
	*packet.Layer
}

// NewVXLAN creates a VXLAN builder with default flags=0x08 (I flag set).
func NewVXLAN() *VXLAN {
	return &VXLAN{newVXLANLayer()}
}

func newVXLANLayer() *packet.Layer {
	return packet.NewLayer("VXLAN", []fields.Field{
		fields.NewByteField("flags", FlagI),
		fields.NewThreeBytesField("reserved1", 0),
		fields.NewThreeBytesField("vni", 0),
		fields.NewByteField("reserved2", 0),
	})
}

// NewVXLANLayer creates a VXLAN layer for use with the packet registry.
func NewVXLANLayer() *packet.Layer {
	return newVXLANLayer()
}

// VNI sets the VXLAN Network Identifier (24 bits, 0-16777215) and returns the builder.
func (v *VXLAN) VNI(vni uint32) *VXLAN {
	v.Layer.Set("vni", vni&0xFFFFFF)
	return v
}

// Flags sets the VXLAN flags byte and returns the builder.
func (v *VXLAN) Flags(flags uint8) *VXLAN {
	v.Layer.Set("flags", flags)
	return v
}

// GetVNI extracts the VXLAN Network Identifier from a VXLAN layer.
func GetVNI(layer *packet.Layer) uint32 {
	vni, _ := layer.Get("vni")
	return vni.(uint32)
}

// GetFlags extracts the flags byte from a VXLAN layer.
func GetFlags(layer *packet.Layer) uint8 {
	flags, _ := layer.Get("flags")
	return flags.(uint8)
}