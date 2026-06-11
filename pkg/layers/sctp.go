package layers

import (
	"hash/crc32"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IPProtoSCTP is the IANA-assigned IP protocol number for SCTP.
const IPProtoSCTP uint8 = 132

// SCTP chunk type constants (RFC 4960).
const (
	SCTPChunkData             uint8 = 0
	SCTPChunkInit             uint8 = 1
	SCTPChunkInitAck          uint8 = 2
	SCTPChunkSack             uint8 = 3
	SCTPChunkHeartbeat        uint8 = 4
	SCTPChunkHeartbeatAck     uint8 = 5
	SCTPChunkAbort            uint8 = 6
	SCTPChunkShutdown         uint8 = 7
	SCTPChunkShutdownAck      uint8 = 8
	SCTPChunkError            uint8 = 9
	SCTPChunkCookieEcho       uint8 = 10
	SCTPChunkCookieAck        uint8 = 11
	SCTPChunkShutdownComplete uint8 = 14
)

// sctpCRC32C is the Castagnoli CRC table used for the SCTP checksum (RFC 3309).
var sctpCRC32C = crc32.MakeTable(crc32.Castagnoli)

// NewSCTP creates an SCTP common header layer (RFC 4960).
// Wire format (12 bytes):
//
//	source port(2) | destination port(2) | verification tag(4) | checksum(4)
//
// The checksum is a CRC32c computed over the whole packet (common header +
// chunks) during Build. Chunks are carried as the upper-layer payload.
func NewSCTP() *packet.Layer {
	return packet.NewLayer("SCTP", []fields.Field{
		fields.NewShortField("sport", 0),
		fields.NewShortField("dport", 0),
		fields.NewIntField("vtag", 0),
		fields.NewIntField("chksum", 0), // CRC32c, auto-computed during Build
	})
}

// NewSCTPWith creates an SCTP common header with the given ports and verification tag.
func NewSCTPWith(sport, dport uint16, vtag uint32) *packet.Layer {
	l := NewSCTP()
	_ = l.Set("sport", sport)
	_ = l.Set("dport", dport)
	_ = l.Set("vtag", vtag)
	return l
}

// sctpBuildHook computes the SCTP CRC32c checksum over the common header and
// all chunk bytes, writing the result little-endian into the checksum field
// (RFC 3309 / gopacket convention).
func sctpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]

	// Serialize header with zero checksum into buf.
	_ = layer.Set("chksum", uint32(0))
	n, err := layer.SerializeInto(buf)
	if err != nil {
		return 0, err
	}

	// CRC32c over header (checksum zeroed) followed by the chunk bytes.
	crc := crc32.Update(0, sctpCRC32C, buf[:n])
	crc = crc32.Update(crc, sctpCRC32C, upperBytes)

	_ = layer.Set("chksum", crc)
	// SCTP stores the CRC32c in the checksum field in little-endian byte order.
	buf[8] = byte(crc)
	buf[9] = byte(crc >> 8)
	buf[10] = byte(crc >> 16)
	buf[11] = byte(crc >> 24)
	return n, nil
}

// NewSCTPChunk creates a generic SCTP chunk layer (RFC 4960 chunk header):
//
//	type(1) | flags(1) | length(2) | value(variable)
//
// The length field is the chunk header (4 bytes) plus the value, not counting
// padding to a 4-byte boundary. Specific chunk types (DATA, INIT, ...) can be
// constructed by setting the type field and supplying the value bytes.
func NewSCTPChunk() *packet.Layer {
	return packet.NewLayer("SCTPChunk", []fields.Field{
		fields.NewByteField("type", 0),
		fields.NewByteField("flags", 0),
		fields.NewShortField("len", 4),
		fields.NewStrField("value", ""),
	})
}
