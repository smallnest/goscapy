package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IPProtoIGMP is the IANA-assigned IP protocol number for IGMP.
const IPProtoIGMP uint8 = 2

// IGMP message type constants (RFC 2236 / RFC 3376).
const (
	IGMPMembershipQuery    uint8 = 0x11 // Membership Query (v1/v2/v3)
	IGMPv1MembershipReport uint8 = 0x12 // Version 1 Membership Report
	IGMPv2MembershipReport uint8 = 0x16 // Version 2 Membership Report
	IGMPv2LeaveGroup       uint8 = 0x17 // Version 2 Leave Group
	IGMPv3MembershipReport uint8 = 0x22 // Version 3 Membership Report
)

// NewIGMP creates an IGMPv2 message layer (RFC 2236).
// Wire format (8 bytes):
//
//	type(1) | max response time(1) | checksum(2) | group address(4)
//
// The checksum is computed over the whole IGMP message during Build.
func NewIGMP() *packet.Layer {
	return packet.NewLayer("IGMP", []fields.Field{
		fields.NewByteField("type", IGMPMembershipQuery),
		fields.NewByteField("mrtime", 0), // max response time, in 1/10 second units
		fields.NewShortField("chksum", 0),
		fields.NewIPField("gaddr", nil), // group address
	})
}

// NewIGMPWith creates an IGMPv2 message with the given type and group address.
func NewIGMPWith(msgType uint8, groupAddr string) *packet.Layer {
	l := NewIGMP()
	_ = l.Set("type", msgType)
	if groupAddr != "" {
		_ = l.Set("gaddr", groupAddr)
	} else {
		_ = l.Set("gaddr", "0.0.0.0")
	}
	return l
}

// igmpBuildHook computes the IGMP checksum over the full message
// (header + any trailing payload), writing directly into buf.
func igmpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]

	// Default group address to 0.0.0.0 if unset.
	if v, _ := layer.Get("gaddr"); v == nil {
		_ = layer.Set("gaddr", "0.0.0.0")
	}

	_ = layer.Set("chksum", uint16(0))
	n, err := layer.SerializeInto(buf)
	if err != nil {
		return 0, err
	}

	sum := checksumSum(buf[:n])
	sum += checksumSum(upperBytes)
	csum := foldChecksum(sum)

	_ = layer.Set("chksum", csum)
	buf[2] = byte(csum >> 8)
	buf[3] = byte(csum)
	return n, nil
}
