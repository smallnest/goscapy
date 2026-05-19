package dot1q

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// TPID constants for 802.1Q and 802.1ad (QinQ).
const (
	TPID8021Q  uint16 = 0x8100
	TPID8021AD uint16 = 0x88A8
)

// Dot1Q wraps a packet.Layer with chainable builder methods for VLAN tagging.
type Dot1Q struct {
	*packet.Layer
}

// NewDot1Q creates a Dot1Q builder with default 802.1Q tag.
// Defaults: tpid=0x8100, pcp=0, dei=0, vid=0, type=0x0800 (IPv4).
func NewDot1Q() *Dot1Q {
	return &Dot1Q{newDot1QLayer()}
}

// newDot1QLayer creates the underlying packet.Layer for a VLAN tag.
// Exported as NewDot1QLayer for use by the dissector registry.
func newDot1QLayer() *packet.Layer {
	return packet.NewLayer("Dot1Q", []fields.Field{
		fields.NewShortField("tpid", TPID8021Q),
		fields.NewShortField("tci", 0),
		fields.NewShortField("type", 0x0800),
	})
}

// NewDot1QLayer creates a Dot1Q layer for use with the packet registry.
func NewDot1QLayer() *packet.Layer {
	return newDot1QLayer()
}

// VID sets the VLAN ID (12 bits, 0-4095) and returns the builder for chaining.
func (d *Dot1Q) VID(vid uint16) *Dot1Q {
	tci, _ := d.Layer.Get("tci")
	val := tci.(uint16)
	val = (val & 0xF000) | (vid & 0x0FFF)
	d.Layer.Set("tci", val)
	return d
}

// PCP sets the Priority Code Point (3 bits, 0-7) and returns the builder for chaining.
func (d *Dot1Q) PCP(pcp uint8) *Dot1Q {
	tci, _ := d.Layer.Get("tci")
	val := tci.(uint16)
	val = (val & 0x1FFF) | (uint16(pcp&0x7) << 13)
	d.Layer.Set("tci", val)
	return d
}

// DEI sets the Drop Eligible Indicator (1 bit) and returns the builder for chaining.
func (d *Dot1Q) DEI(dei bool) *Dot1Q {
	tci, _ := d.Layer.Get("tci")
	val := tci.(uint16)
	if dei {
		val |= 0x1000
	} else {
		val &^= 0x1000
	}
	d.Layer.Set("tci", val)
	return d
}

// Type sets the inner EtherType and returns the builder for chaining.
func (d *Dot1Q) Type(etype uint16) *Dot1Q {
	d.Layer.Set("type", etype)
	return d
}

// TPID sets the Tag Protocol Identifier and returns the builder for chaining.
func (d *Dot1Q) TPID(tpid uint16) *Dot1Q {
	d.Layer.Set("tpid", tpid)
	return d
}

// GetVID extracts the VLAN ID from a Dot1Q layer.
func GetVID(layer *packet.Layer) uint16 {
	tci, _ := layer.Get("tci")
	return tci.(uint16) & 0x0FFF
}

// GetPCP extracts the Priority Code Point from a Dot1Q layer.
func GetPCP(layer *packet.Layer) uint8 {
	tci, _ := layer.Get("tci")
	return uint8((tci.(uint16) >> 13) & 0x7)
}

// GetDEI extracts the Drop Eligible Indicator from a Dot1Q layer.
func GetDEI(layer *packet.Layer) bool {
	tci, _ := layer.Get("tci")
	return (tci.(uint16)>>12)&0x1 == 1
}

// GetType extracts the inner EtherType from a Dot1Q layer.
func GetType(layer *packet.Layer) uint16 {
	t, _ := layer.Get("type")
	return t.(uint16)
}