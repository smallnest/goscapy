// Package quic implements QUIC (RFC 9000) packet layers.
//
// QUIC is a transport protocol built on UDP that provides TLS-encrypted
// connections with multiplexed streams. This package supports:
//   - Long Header packets (Initial, 0-RTT, Handshake, Retry)
//   - Short Header packets (1-RTT)
//   - CRYPTO frames for TLS handshake
//
// Packet-level only; no connection state machine.
package quic

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// QUIC version constants.
const (
	Version1    uint32 = 0x00000001 // QUIC v1 (RFC 9000)
	VersionDraft29 uint32 = 0xff00001d // Draft 29
)

// Long header packet types (encoded in the lower 2 bits of the first byte).
const (
	PacketTypeInitial   uint8 = 0 // Initial packet
	PacketTypeZeroRTT   uint8 = 1 // 0-RTT packet
	PacketTypeHandshake uint8 = 2 // Handshake packet
	PacketTypeRetry     uint8 = 3 // Retry packet
)

// Frame types.
const (
	FrameTypePadding uint64 = 0x00
	FrameTypePing    uint64 = 0x01
	FrameTypeCrypto  uint64 = 0x06
	FrameTypeStream  uint64 = 0x08
)

// NewQUICLongHeader creates a QUIC Long Header layer (for Initial, 0-RTT, Handshake).
// Wire format:
//   Byte 0: 1 (header form) | 1 (fixed bit) | 2 (type) | 2 (reserved) | 2 (PN length)
//   Bytes 1-4: version (4B)
//   Byte 5: DCID length (1B) + DCID (variable)
//   Byte 5+N: SCID length (1B) + SCID (variable)
//   [Initial only] Token length (VLQ) + Token (variable)
//   Length (VLQ) + Packet number (1-4B) + Payload
func NewQUICLongHeader() *packet.Layer {
	return packet.NewLayer("QUIC", []fields.Field{
		fields.NewByteField("first_byte", 0xC0),   // 1100 0000: long header, fixed bit
		fields.NewIntField("version", Version1),     // QUIC version
		fields.NewStrField("dcid", ""),              // Destination Connection ID
		fields.NewStrField("scid", ""),              // Source Connection ID
		fields.NewStrField("token", ""),             // Token (Initial only)
		fields.NewStrField("payload", ""),           // Packet payload (frames)
	})
}

// NewQUICShortHeader creates a QUIC Short Header layer (1-RTT).
// Wire format:
//   Byte 0: 0 (header form) | 1 (fixed bit) | 2 (reserved) | 1 (key phase) | 2 (PN length)
//   DCID (variable, no length prefix)
//   Packet number (1-4B) + Payload
func NewQUICShortHeader() *packet.Layer {
	return packet.NewLayer("QUIC", []fields.Field{
		fields.NewByteField("first_byte", 0x40),    // 0100 0000: short header, fixed bit
		fields.NewStrField("dcid", ""),              // Destination Connection ID
		fields.NewStrField("payload", ""),           // Packet payload (frames)
	})
}

// QUICLongHeader holds a parsed QUIC Long Header packet.
type QUICLongHeader struct {
	FirstByte  byte
	Version    uint32
	DCID       []byte
	SCID       []byte
	Token      []byte
	Payload    []byte
}

// QUICShortHeader holds a parsed QUIC Short Header packet.
type QUICShortHeader struct {
	FirstByte byte
	DCID      []byte
	Payload   []byte
}

// CRYPTOFrame holds a QUIC CRYPTO frame.
type CRYPTOFrame struct {
	Offset uint64
	Data   []byte
}

// SerializeCryptoFrame serializes a CRYPTO frame to wire format.
func SerializeCryptoFrame(f *CRYPTOFrame) []byte {
	var buf []byte
	buf = append(buf, EncodeVLQ(FrameTypeCrypto)...)
	buf = append(buf, EncodeVLQ(f.Offset)...)
	buf = append(buf, EncodeVLQ(uint64(len(f.Data)))...)
	buf = append(buf, f.Data...)
	return buf
}

// ParseCryptoFrame parses a CRYPTO frame from wire format.
func ParseCryptoFrame(data []byte) (*CRYPTOFrame, int, error) {
	offset := 0

	// Frame type
	ft, n := DecodeVLQ(data[offset:])
	offset += n
	if ft != FrameTypeCrypto {
		return nil, offset, fmt.Errorf("quic: expected CRYPTO frame type %d, got %d", FrameTypeCrypto, ft)
	}

	// Offset
	off, n := DecodeVLQ(data[offset:])
	offset += n

	// Length
	length, n := DecodeVLQ(data[offset:])
	offset += n

	if offset+int(length) > len(data) {
		return nil, offset, fmt.Errorf("quic: CRYPTO frame data truncated: need %d, have %d", length, len(data)-offset)
	}

	frameData := make([]byte, length)
	copy(frameData, data[offset:offset+int(length)])
	offset += int(length)

	return &CRYPTOFrame{Offset: off, Data: frameData}, offset, nil
}

// SerializeLongHeader serializes a QUIC Long Header packet.
func SerializeLongHeader(h *QUICLongHeader) ([]byte, error) {
	var buf []byte

	// First byte
	buf = append(buf, h.FirstByte)

	// Version (4 bytes big-endian)
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, h.Version)
	buf = append(buf, ver...)

	// DCID length + DCID
	buf = append(buf, byte(len(h.DCID)))
	buf = append(buf, h.DCID...)

	// SCID length + SCID
	buf = append(buf, byte(len(h.SCID)))
	buf = append(buf, h.SCID...)

	// Token (only for Initial packets)
	pktType := (h.FirstByte >> 4) & 0x03
	if pktType == PacketTypeInitial {
		buf = append(buf, EncodeVLQ(uint64(len(h.Token)))...)
		buf = append(buf, h.Token...)
	}

	// Length (VLQ) + payload
	payloadLen := len(h.Payload) + 1 // +1 for minimum packet number
	buf = append(buf, EncodeVLQ(uint64(payloadLen))...)
	buf = append(buf, h.Payload...)

	return buf, nil
}

// ParseLongHeader parses a QUIC Long Header from raw bytes.
func ParseLongHeader(data []byte) (*QUICLongHeader, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("quic: long header needs at least 6 bytes, got %d", len(data))
	}

	offset := 0
	h := &QUICLongHeader{}

	// First byte
	h.FirstByte = data[offset]
	offset++

	// Check it's a long header (bit 7 = 1)
	if h.FirstByte&0x80 == 0 {
		return nil, fmt.Errorf("quic: not a long header (first byte = 0x%02x)", h.FirstByte)
	}

	// Version
	h.Version = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// DCID
	dcidLen := int(data[offset])
	offset++
	if offset+dcidLen > len(data) {
		return nil, fmt.Errorf("quic: DCID truncated")
	}
	h.DCID = make([]byte, dcidLen)
	copy(h.DCID, data[offset:offset+dcidLen])
	offset += dcidLen

	// SCID
	scidLen := int(data[offset])
	offset++
	if offset+scidLen > len(data) {
		return nil, fmt.Errorf("quic: SCID truncated")
	}
	h.SCID = make([]byte, scidLen)
	copy(h.SCID, data[offset:offset+scidLen])
	offset += scidLen

	// Token (Initial only)
	pktType := (h.FirstByte >> 4) & 0x03
	if pktType == PacketTypeInitial {
		tokenLen, n := DecodeVLQ(data[offset:])
		offset += n
		if offset+int(tokenLen) > len(data) {
			return nil, fmt.Errorf("quic: token truncated")
		}
		h.Token = make([]byte, tokenLen)
		copy(h.Token, data[offset:offset+int(tokenLen)])
		offset += int(tokenLen)
	}

	// Length + remaining payload
	_, n := DecodeVLQ(data[offset:])
	offset += n

	h.Payload = make([]byte, len(data[offset:]))
	copy(h.Payload, data[offset:])

	return h, nil
}

// EncodeVLQ encodes a variable-length integer (RFC 9000 Section 16).
func EncodeVLQ(v uint64) []byte {
	if v <= 0x3F {
		return []byte{byte(v)}
	}
	if v <= 0x3FFF {
		return []byte{byte(v>>8) | 0x40, byte(v)}
	}
	if v <= 0x3FFFFFFF {
		return []byte{byte(v>>24) | 0x80, byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{byte(v>>56) | 0xC0, byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// DecodeVLQ decodes a variable-length integer.
func DecodeVLQ(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	prefix := data[0] >> 6
	switch prefix {
	case 0: // 1 byte (6-bit value)
		return uint64(data[0] & 0x3F), 1
	case 1: // 2 bytes (14-bit value)
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(data[0]&0x3F)<<8 | uint64(data[1]), 2
	case 2: // 4 bytes (30-bit value)
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(data[0]&0x3F)<<24 | uint64(data[1])<<16 | uint64(data[2])<<8 | uint64(data[3]), 4
	case 3: // 8 bytes (62-bit value)
		if len(data) < 8 {
			return 0, 0
		}
		return uint64(data[0]&0x3F)<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7]), 8
	}
	return 0, 0
}
