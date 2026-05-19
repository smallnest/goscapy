package layers

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// NDP message types (ICMPv6 sub-types).
const (
	NDPRouterSolicitation   uint8 = 133
	NDPRouterAdvertisement  uint8 = 134
	NDPNeighborSolicitation uint8 = 135
	NDPNeighborAdvertisement uint8 = 136
	NDPRedirect             uint8 = 137
)

// NDP option type constants.
const (
	NDPOptSourceLinkLayer  uint8 = 1
	NDPOptTargetLinkLayer  uint8 = 2
	NDPOptPrefixInfo       uint8 = 3
	NDPOptMTU              uint8 = 5
)

// Router Advertisement flags.
const (
	NDPRAManaged     uint8 = 0x80
	NDPRAOther       uint8 = 0x40
	NDPRAHomeAgent   uint8 = 0x20
	NDPRAPreference  uint8 = 0x18 // 2 bits, shifted
	NDPRAProxy       uint8 = 0x04
)

// Neighbor Advertisement flags.
const (
	NDPNARouter     uint8 = 0x80
	NDPNASolicited  uint8 = 0x40
	NDPNAOverride   uint8 = 0x20
)

// NDPOption represents a single NDP option.
type NDPOption struct {
	Type   uint8
	Length uint8 // in units of 8 bytes
	Value  []byte
}

// NewNDPRouterSolicitation creates an NDP Router Solicitation body layer.
// Stack: IPv6 → ICMPv6(type=133) → this layer.
func NewNDPRouterSolicitation() *packet.Layer {
	return packet.NewLayer("NDP Router Solicitation", []fields.Field{
		fields.NewIntField("reserved", 0),
		fields.NewStrField("options", ""),
	})
}

// NewNDPRouterAdvertisement creates an NDP Router Advertisement body layer.
func NewNDPRouterAdvertisement() *packet.Layer {
	return packet.NewLayer("NDP Router Advertisement", []fields.Field{
		fields.NewByteField("hoplimit", 64),
		fields.NewByteField("flags", 0),
		fields.NewShortField("lifetime", 1800),
		fields.NewIntField("reachable", 0),
		fields.NewIntField("retrans", 0),
		fields.NewStrField("options", ""),
	})
}

// NewNDPNeighborSolicitation creates an NDP Neighbor Solicitation body layer.
func NewNDPNeighborSolicitation() *packet.Layer {
	return packet.NewLayer("NDP Neighbor Solicitation", []fields.Field{
		fields.NewIntField("reserved", 0),
		fields.NewIPv6Field("target", nil),
		fields.NewStrField("options", ""),
	})
}

// NewNDPNeighborAdvertisement creates an NDP Neighbor Advertisement body layer.
func NewNDPNeighborAdvertisement() *packet.Layer {
	return packet.NewLayer("NDP Neighbor Advertisement", []fields.Field{
		fields.NewByteField("flags", 0),
		fields.NewThreeBytesField("reserved", 0),
		fields.NewIPv6Field("target", nil),
		fields.NewStrField("options", ""),
	})
}

// NewNDPRedirect creates an NDP Redirect body layer.
func NewNDPRedirect() *packet.Layer {
	return packet.NewLayer("NDP Redirect", []fields.Field{
		fields.NewIntField("reserved", 0),
		fields.NewIPv6Field("target", nil),
		fields.NewIPv6Field("dest", nil),
		fields.NewStrField("options", ""),
	})
}

// ParseNDPOptions parses raw bytes into a slice of NDPOption.
// NDP options are TLV-encoded with Length in units of 8 bytes.
func ParseNDPOptions(data []byte) ([]NDPOption, error) {
	var opts []NDPOption
	for i := 0; i < len(data); {
		if data[i] == 0 {
			break // Pad1 or end-of-options
		}
		if i+1 >= len(data) {
			return nil, fmt.Errorf("layers: truncated NDP option at offset %d", i)
		}
		optType := data[i]
		optLen := data[i+1] // in units of 8 bytes
		if optLen == 0 {
			return nil, fmt.Errorf("layers: invalid NDP option length 0 at offset %d", i)
		}
		totalBytes := int(optLen) * 8
		if totalBytes < 2 || i+totalBytes > len(data) {
			return nil, fmt.Errorf("layers: NDP option type %d runs past buffer at offset %d", optType, i)
		}
		valLen := totalBytes - 2
		val := make([]byte, valLen)
		copy(val, data[i+2:i+totalBytes])
		opts = append(opts, NDPOption{Type: optType, Length: optLen, Value: val})
		i += totalBytes
	}
	return opts, nil
}

// BuildNDPOptions serializes NDP options to their wire format.
func BuildNDPOptions(opts []NDPOption) []byte {
	var out []byte
	for _, o := range opts {
		if o.Length == 0 {
			continue
		}
		total := int(o.Length) * 8
		buf := make([]byte, total)
		buf[0] = o.Type
		buf[1] = o.Length
		copy(buf[2:], o.Value)
		out = append(out, buf...)
	}
	return out
}

// BuildSourceLinkLayerOption creates a Source Link-Layer Address option.
func BuildSourceLinkLayerOption(mac net.HardwareAddr) NDPOption {
	val := make([]byte, 6)
	copy(val, mac)
	return NDPOption{Type: NDPOptSourceLinkLayer, Length: 1, Value: val}
}

// BuildTargetLinkLayerOption creates a Target Link-Layer Address option.
func BuildTargetLinkLayerOption(mac net.HardwareAddr) NDPOption {
	val := make([]byte, 6)
	copy(val, mac)
	return NDPOption{Type: NDPOptTargetLinkLayer, Length: 1, Value: val}
}

// BuildMTUOption creates an MTU option.
func BuildMTUOption(mtu uint32) NDPOption {
	val := make([]byte, 6)
	val[0] = 0
	val[1] = 0 // reserved
	val[2] = byte(mtu >> 24)
	val[3] = byte(mtu >> 16)
	val[4] = byte(mtu >> 8)
	val[5] = byte(mtu)
	return NDPOption{Type: NDPOptMTU, Length: 1, Value: val}
}