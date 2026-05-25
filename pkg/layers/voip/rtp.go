package voip

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

const (
	RTPVersion = 2

	RTPHeaderLen = 12 // fixed part (without CSRC or extension)
)

// Payload type assignments (RFC 3551).
const (
	RTPPayloadPCMU   uint8 = 0  // G.711 PCM
	RTPPayloadPCMA   uint8 = 8  // G.711 A-law
	RTPPayloadG722   uint8 = 9
	RTPPayloadG728   uint8 = 15
	RTPPayloadG729   uint8 = 18
	RTPPayloadDynMin uint8 = 96 // dynamic range start
	RTPPayloadDynMax uint8 = 127
)

// NewRTP creates an RTP header layer.
func NewRTP() *packet.Layer {
	return packet.NewLayer("RTP", []fields.Field{
		fields.NewByteField("byte0", 0x80), // V=2, P=0, X=0, CC=0
		fields.NewByteField("byte1", 0),     // M=0, PT=0
		fields.NewShortField("seq", 0),
		fields.NewIntField("timestamp", 0),
		fields.NewIntField("ssrc", 0),
	})
}

// RTPHeader represents the parsed RTP header.
type RTPHeader struct {
	Version      uint8
	Padding      bool
	Extension    bool
	CSRCCount    uint8
	Marker       bool
	PayloadType  uint8
	Sequence     uint16
	Timestamp    uint32
	SSRC         uint32
	CSRC         []uint32
	ExtProfile   uint16
	ExtLength    uint16
	ExtData      []byte
	Payload      []byte
}

// ParseRTP parses an RTP packet from raw bytes.
func ParseRTP(data []byte) (RTPHeader, error) {
	if len(data) < RTPHeaderLen {
		return RTPHeader{}, fmt.Errorf("rtp: need at least %d bytes, got %d", RTPHeaderLen, len(data))
	}

	byte0 := data[0]
	byte1 := data[1]

	h := RTPHeader{
		Version:     (byte0 >> 6) & 0x03,
		Padding:     (byte0>>5)&0x01 != 0,
		Extension:   (byte0>>4)&0x01 != 0,
		CSRCCount:   byte0 & 0x0F,
		Marker:      (byte1>>7)&0x01 != 0,
		PayloadType: byte1 & 0x7F,
		Sequence:    binary.BigEndian.Uint16(data[2:4]),
		Timestamp:   binary.BigEndian.Uint32(data[4:8]),
		SSRC:        binary.BigEndian.Uint32(data[8:12]),
	}

	if h.Version != RTPVersion {
		return h, fmt.Errorf("rtp: unexpected version %d", h.Version)
	}

	off := 12

	// CSRC list.
	if h.CSRCCount > 0 {
		csrcEnd := off + int(h.CSRCCount)*4
		if csrcEnd > len(data) {
			return h, fmt.Errorf("rtp: truncated CSRC list (need %d bytes, have %d)", csrcEnd, len(data))
		}
		h.CSRC = make([]uint32, h.CSRCCount)
		for i := range h.CSRCCount {
			h.CSRC[i] = binary.BigEndian.Uint32(data[off:])
			off += 4
		}
	}

	// Header extension.
	if h.Extension {
		if off+4 > len(data) {
			return h, fmt.Errorf("rtp: truncated extension header at offset %d", off)
		}
		h.ExtProfile = binary.BigEndian.Uint16(data[off:])
		h.ExtLength = binary.BigEndian.Uint16(data[off+2:])
		off += 4
		extBytes := int(h.ExtLength) * 4
		if off+extBytes > len(data) {
			return h, fmt.Errorf("rtp: truncated extension data (need %d bytes, have %d)", extBytes, len(data)-off)
		}
		h.ExtData = make([]byte, extBytes)
		copy(h.ExtData, data[off:])
		off += extBytes
	}

	h.Payload = data[off:]
	if h.Padding && len(h.Payload) > 0 {
		padCount := int(h.Payload[len(h.Payload)-1])
		if padCount <= len(h.Payload) {
			h.Payload = h.Payload[:len(h.Payload)-padCount]
		}
	}
	return h, nil
}

// PackRTP serializes an RTP header + payload.
// CC is derived from len(h.CSRC). ExtLength is derived from len(h.ExtData)/4.
func PackRTP(h RTPHeader) []byte {
	csrcLen := len(h.CSRC) * 4
	extLen := 0
	if h.Extension {
		extLen = 4 + len(h.ExtData)
	}

	total := RTPHeaderLen + csrcLen + extLen + len(h.Payload)
	buf := make([]byte, total)

	cc := len(h.CSRC)
	if cc > 15 {
		cc = 15
	}

	byte0 := (h.Version << 6)
	if h.Padding {
		byte0 |= 0x20
	}
	if h.Extension {
		byte0 |= 0x10
	}
	byte0 |= uint8(cc)

	byte1 := h.PayloadType & 0x7F
	if h.Marker {
		byte1 |= 0x80
	}

	buf[0] = byte0
	buf[1] = byte1
	binary.BigEndian.PutUint16(buf[2:], h.Sequence)
	binary.BigEndian.PutUint32(buf[4:], h.Timestamp)
	binary.BigEndian.PutUint32(buf[8:], h.SSRC)

	off := 12
	for _, csrc := range h.CSRC {
		binary.BigEndian.PutUint32(buf[off:], csrc)
		off += 4
	}

	if h.Extension {
		extWords := uint16(len(h.ExtData) / 4)
		binary.BigEndian.PutUint16(buf[off:], h.ExtProfile)
		binary.BigEndian.PutUint16(buf[off+2:], extWords)
		off += 4
		copy(buf[off:], h.ExtData)
		off += len(h.ExtData)
	}

	copy(buf[off:], h.Payload)
	return buf
}
