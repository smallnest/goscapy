package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ICMP type constants.
const (
	ICMPEchoReply   uint8 = 0
	ICMPDestUnreach uint8 = 3
	ICMPEchoRequest uint8 = 8
	ICMPTimeExceed  uint8 = 11
)

// NewICMP creates an ICMP message layer. Default: Echo Request (type=8, code=0).
func NewICMP() *packet.Layer {
	return packet.NewLayer("ICMP", []fields.Field{
		fields.NewByteField("type", ICMPEchoRequest),
		fields.NewByteField("code", 0),
		fields.NewShortField("chksum", 0), // auto-computed during Build
		fields.NewShortField("id", 0),
		fields.NewShortField("seq", 0),
	})
}

// NewICMPEcho creates an ICMP Echo Request message with the given id and seq.
func NewICMPEcho(id, seq uint16) *packet.Layer {
	l := NewICMP()
	l.Set("type", ICMPEchoRequest)
	l.Set("code", uint8(0))
	l.Set("id", id)
	l.Set("seq", seq)
	return l
}

// icmpBuildHook is called during Packet.Build() for ICMP layers.
// It auto-computes the ICMP checksum over the full message (header + payload),
// writing directly into buf.
func icmpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]

	// Serialize header with zero checksum into buf.
	layer.Set("chksum", uint16(0))
	n, err := layer.SerializeInto(buf)
	if err != nil {
		return 0, err
	}

	// Compute checksum over header + upperBytes without concatenation.
	sum := checksumSum(buf[:n])
	sum += checksumSum(upperBytes)
	csum := foldChecksum(sum)

	layer.Set("chksum", csum)
	buf[2] = byte(csum >> 8)
	buf[3] = byte(csum)
	return n, nil
}
