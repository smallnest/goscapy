package layers

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ICMPv6 type constants.
const (
	ICMPv6DestUnreach  uint8 = 1
	ICMPv6PacketTooBig uint8 = 2
	ICMPv6TimeExceed   uint8 = 3
	ICMPv6ParamProblem uint8 = 4
	ICMPv6EchoRequest  uint8 = 128
	ICMPv6EchoReply    uint8 = 129
)

// NewICMPv6 creates an ICMPv6 message layer. Default: Echo Request (type=128, code=0).
func NewICMPv6() *packet.Layer {
	return packet.NewLayer("ICMPv6", []fields.Field{
		fields.NewByteField("type", ICMPv6EchoRequest),
		fields.NewByteField("code", 0),
		fields.NewShortField("chksum", 0), // auto-computed during Build
		fields.NewShortField("id", 0),
		fields.NewShortField("seq", 0),
		fields.NewStrField("data", ""),
	})
}

// NewICMPv6Echo creates an ICMPv6 Echo Request with the given id and seq.
func NewICMPv6Echo(id, seq uint16) *packet.Layer {
	l := NewICMPv6()
	l.Set("type", ICMPv6EchoRequest)
	l.Set("code", uint8(0))
	l.Set("id", id)
	l.Set("seq", seq)
	return l
}

// icmpv6BuildHook is called during Packet.Build() for ICMPv6 layers.
// It auto-computes the ICMPv6 checksum using the IPv6 pseudo-header.
func icmpv6BuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte) ([]byte, error) {
	layer := pkt.Layers()[layerIdx]

	// Find IPv6 layer below for src/dst addresses.
	srcIP, dstIP, err := findIPv6Addresses(pkt, layerIdx)
	if err != nil {
		return nil, err
	}

	// Zero checksum, serialize header.
	layer.Set("chksum", uint16(0))
	hdrBytes, err := layer.SerializeFields()
	if err != nil {
		return nil, err
	}

	// Full ICMPv6 message = header + upper payload.
	fullMsg := make([]byte, 0, len(hdrBytes)+len(upperBytes))
	fullMsg = append(fullMsg, hdrBytes...)
	fullMsg = append(fullMsg, upperBytes...)

	csum := IPv6PseudoHeaderChecksum(srcIP, dstIP, IPv6NextHdrICMP, fullMsg)
	layer.Set("chksum", csum)

	return layer.SerializeFields()
}

// findIPv6Addresses searches downward from layerIdx to find the nearest IPv6 layer
// and returns its src and dst IP addresses as 16-byte slices.
func findIPv6Addresses(pkt *packet.Packet, layerIdx int) (srcIP, dstIP []byte, err error) {
	for i := layerIdx - 1; i >= 0; i-- {
		if pkt.Layers()[i].Proto() == "IPv6" {
			ipLayer := pkt.Layers()[i]
			src, _ := ipLayer.Get("src")
			dst, _ := ipLayer.Get("dst")

			srcIP = ipv6ToBytes(src)
			dstIP = ipv6ToBytes(dst)

			if len(srcIP) != 16 || len(dstIP) != 16 {
				return nil, nil, fmt.Errorf("layers: IPv6 addresses not set for ICMPv6 checksum")
			}
			return srcIP, dstIP, nil
		}
	}
	return nil, nil, fmt.Errorf("layers: no IPv6 layer found below layer %d for ICMPv6 checksum", layerIdx)
}

// ipv6ToBytes converts an IP field value to a 16-byte IPv6 address.
func ipv6ToBytes(v any) []byte {
	switch ip := v.(type) {
	case net.IP:
		return ip.To16()
	case string:
		parsed := net.ParseIP(ip)
		if parsed != nil {
			return parsed.To16()
		}
	case []byte:
		if len(ip) == 16 {
			return ip
		}
	}
	return nil
}