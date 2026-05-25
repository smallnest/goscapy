package voip

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// RTCP packet types (RFC 3550).
const (
	RTCPSR      uint8 = 200 // Sender Report
	RTCPRR      uint8 = 201 // Receiver Report
	RTCPSDES    uint8 = 202 // Source Description
	RTCPBYE     uint8 = 203
	RTCPAPP     uint8 = 204
	RTCPRTPFB   uint8 = 205 // Transport-wide FB
	RTCPTCCFB   uint8 = 206 // Payload-specific FB
)

const RTCPHeaderLen = 4 // common header: V/P/RC/PT/Length

// RTCPPacket is the common header for all RTCP packets.
type RTCPPacket struct {
	Version    uint8  // 2 bits
	Padding    bool   // 1 bit
	RC         uint8  // 5 bits (report count or subtype)
	Type       uint8  // 8 bits
	Length     uint16 // 16 bits (in 32-bit words minus 1)
	RawPayload []byte
}

// RTCPSenderReport is an RTCP Sender Report.
type RTCPSenderReport struct {
	RTCPPacket
	SSRC        uint32
	NTPMSW      uint32
	NTPLSW      uint32
	RTPTime     uint32
	PacketCount uint32
	OctetCount  uint32
	Reports     []RTCPReceiverBlock
}

// RTCPReceiverReport is an RTCP Receiver Report.
type RTCPReceiverReport struct {
	RTCPPacket
	SSRC     uint32
	Reports  []RTCPReceiverBlock
}

// RTCPReceiverBlock is a reception report block.
type RTCPReceiverBlock struct {
	SSRC         uint32
	FractionLost uint8
	PacketsLost  uint32 // 24 bits
	LastSeq      uint32
	Jitter       uint32
	LSR          uint32
	DLSR         uint32
}

// RTCPBYEPacket is an RTCP BYE packet.
type RTCPBYEPacket struct {
	RTCPPacket
	Sources []uint32
	Reason  string
}

// RTCPSDESPacket is an RTCP SDES packet.
type RTCPSDESPacket struct {
	RTCPPacket
	Chunks []RTCPSDESChunk
}

// RTCPSDESChunk is a single SDES chunk (one SSRC + items).
type RTCPSDESChunk struct {
	SSRC  uint32
	Items []RTCPSDESItem
}

// RTCPSDESItem is a single SDES item.
type RTCPSDESItem struct {
	Type uint8
	Data string
}

// SDES item types.
const (
	SDESEnd      uint8 = 0
	SDESCNAME    uint8 = 1
	SDESName     uint8 = 2
	SDESEmail    uint8 = 3
	SDESPhone    uint8 = 4
	SDESLocation uint8 = 5
	SDESTool     uint8 = 6
	SDESNote     uint8 = 7
	SDESPriv     uint8 = 8
)

// NewRTCP creates a generic RTCP layer.
func NewRTCP() *packet.Layer {
	return packet.NewLayer("RTCP", []fields.Field{
		fields.NewByteField("byte0", 0x80), // V=2
		fields.NewByteField("type", 0),
		fields.NewShortField("length", 0),
	})
}

// ParseRTCPPackets parses one or more compound RTCP packets.
func ParseRTCPPackets(data []byte) ([]RTCPPacket, error) {
	var packets []RTCPPacket
	off := 0
	for off < len(data) {
		if off+4 > len(data) {
			return nil, fmt.Errorf("rtcp: truncated header at offset %d", off)
		}
		byte0 := data[off]
		pktType := data[off+1]
		length := binary.BigEndian.Uint16(data[off+2:])
		payloadLen := int(length) * 4
		if off+4+payloadLen > len(data) {
			return nil, fmt.Errorf("rtcp: packet overruns buffer at offset %d", off)
		}
		ver := (byte0 >> 6) & 0x03
		if ver != 2 {
			return nil, fmt.Errorf("rtcp: unexpected version %d at offset %d", ver, off)
		}
		pad := (byte0>>5)&0x01 != 0
		payload := data[off+4 : off+4+payloadLen]
		if pad && len(payload) > 0 {
			padCount := int(payload[len(payload)-1])
			if padCount <= len(payload) {
				payload = payload[:len(payload)-padCount]
			}
		}
		packets = append(packets, RTCPPacket{
			Version:    ver,
			Padding:    pad,
			RC:         byte0 & 0x1F,
			Type:       pktType,
			Length:     length,
			RawPayload: payload,
		})
		off += 4 + payloadLen
	}
	return packets, nil
}

// ParseSenderReport parses a Sender Report from raw payload.
func ParseSenderReport(data []byte) (RTCPSenderReport, error) {
	if len(data) < 24 {
		return RTCPSenderReport{}, fmt.Errorf("rtcp: SR needs at least 24 bytes, got %d", len(data))
	}
	sr := RTCPSenderReport{
		SSRC:        binary.BigEndian.Uint32(data[0:4]),
		NTPMSW:      binary.BigEndian.Uint32(data[4:8]),
		NTPLSW:      binary.BigEndian.Uint32(data[8:12]),
		RTPTime:     binary.BigEndian.Uint32(data[12:16]),
		PacketCount: binary.BigEndian.Uint32(data[16:20]),
		OctetCount:  binary.BigEndian.Uint32(data[20:24]),
	}
	off := 24
	for off+24 <= len(data) {
		sr.Reports = append(sr.Reports, parseReceiverBlock(data[off:]))
		off += 24
	}
	return sr, nil
}

// ParseReceiverReport parses a Receiver Report from raw payload.
func ParseReceiverReport(data []byte) (RTCPReceiverReport, error) {
	if len(data) < 4 {
		return RTCPReceiverReport{}, fmt.Errorf("rtcp: RR needs at least 4 bytes, got %d", len(data))
	}
	rr := RTCPReceiverReport{
		SSRC: binary.BigEndian.Uint32(data[0:4]),
	}
	off := 4
	for off+24 <= len(data) {
		rr.Reports = append(rr.Reports, parseReceiverBlock(data[off:]))
		off += 24
	}
	return rr, nil
}

// ParseSDESPacket parses an SDES packet from raw payload.
func ParseSDESPacket(rc uint8, data []byte) (RTCPSDESPacket, error) {
	sdes := RTCPSDESPacket{}
	off := 0
	for i := 0; i < int(rc) && off < len(data); i++ {
		if off+4 > len(data) {
			break
		}
		chunk := RTCPSDESChunk{
			SSRC: binary.BigEndian.Uint32(data[off:]),
		}
		off += 4
		for off < len(data) {
			if off+2 > len(data) {
				break
			}
			itemType := data[off]
			if itemType == SDESEnd {
				off++
				// Skip padding to next 32-bit boundary.
				for off%4 != 0 && off < len(data) {
					off++
				}
				break
			}
			itemLen := int(data[off+1])
			if off+2+itemLen > len(data) {
				break
			}
			chunk.Items = append(chunk.Items, RTCPSDESItem{
				Type: itemType,
				Data: string(data[off+2 : off+2+itemLen]),
			})
			off += 2 + itemLen
		}
		sdes.Chunks = append(sdes.Chunks, chunk)
	}
	return sdes, nil
}

// ParseBYEPacket parses a BYE packet from raw payload.
func ParseBYEPacket(rc uint8, data []byte) (RTCPBYEPacket, error) {
	bye := RTCPBYEPacket{}
	off := 0
	for i := 0; i < int(rc) && off+4 <= len(data); i++ {
		bye.Sources = append(bye.Sources, binary.BigEndian.Uint32(data[off:]))
		off += 4
	}
	if off < len(data) {
		reasonLen := int(data[off])
		off++
		if off+reasonLen <= len(data) {
			bye.Reason = string(data[off : off+reasonLen])
		}
	}
	return bye, nil
}

func parseReceiverBlock(data []byte) RTCPReceiverBlock {
	return RTCPReceiverBlock{
		SSRC:         binary.BigEndian.Uint32(data[0:4]),
		FractionLost: data[4],
		PacketsLost:  uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		LastSeq:      binary.BigEndian.Uint32(data[8:12]),
		Jitter:       binary.BigEndian.Uint32(data[12:16]),
		LSR:          binary.BigEndian.Uint32(data[16:20]),
		DLSR:         binary.BigEndian.Uint32(data[20:24]),
	}
}

// PackRTCPPacket serializes a generic RTCP packet.
// Payload is padded to 4-byte boundary as required by RFC 3550.
func PackRTCPPacket(rc uint8, pktType uint8, payload []byte) []byte {
	// Pad payload to 4-byte boundary.
	padLen := (4 - len(payload)%4) % 4
	paddedLen := len(payload) + padLen
	payloadWords := uint16(paddedLen / 4)
	totalLen := 4 + paddedLen
	buf := make([]byte, totalLen)
	buf[0] = 0x80 | (rc & 0x1F) // V=2
	buf[1] = pktType
	binary.BigEndian.PutUint16(buf[2:], payloadWords)
	copy(buf[4:], payload)
	return buf
}

// PackSenderReport serializes a Sender Report.
func PackSenderReport(sr RTCPSenderReport) []byte {
	payloadLen := 24 + len(sr.Reports)*24
	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint32(payload[0:], sr.SSRC)
	binary.BigEndian.PutUint32(payload[4:], sr.NTPMSW)
	binary.BigEndian.PutUint32(payload[8:], sr.NTPLSW)
	binary.BigEndian.PutUint32(payload[12:], sr.RTPTime)
	binary.BigEndian.PutUint32(payload[16:], sr.PacketCount)
	binary.BigEndian.PutUint32(payload[20:], sr.OctetCount)
	off := 24
	for _, rb := range sr.Reports {
		packReceiverBlock(payload[off:], rb)
		off += 24
	}
	rc := uint8(len(sr.Reports))
	if rc > 31 {
		rc = 31
	}
	return PackRTCPPacket(rc, RTCPSR, payload)
}

// PackReceiverReport serializes a Receiver Report.
func PackReceiverReport(rr RTCPReceiverReport) []byte {
	payloadLen := 4 + len(rr.Reports)*24
	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint32(payload[0:], rr.SSRC)
	off := 4
	for _, rb := range rr.Reports {
		packReceiverBlock(payload[off:], rb)
		off += 24
	}
	rc := uint8(len(rr.Reports))
	if rc > 31 {
		rc = 31
	}
	return PackRTCPPacket(rc, RTCPRR, payload)
}

// PackBYEPacket serializes a BYE packet.
func PackBYEPacket(bye RTCPBYEPacket) []byte {
	payloadLen := len(bye.Sources)*4 + 1 + len(bye.Reason)
	payload := make([]byte, payloadLen)
	off := 0
	for _, src := range bye.Sources {
		binary.BigEndian.PutUint32(payload[off:], src)
		off += 4
	}
	payload[off] = uint8(len(bye.Reason))
	off++
	copy(payload[off:], bye.Reason)
	rc := uint8(len(bye.Sources))
	if rc > 31 {
		rc = 31
	}
	return PackRTCPPacket(rc, RTCPBYE, payload)
}

func packReceiverBlock(buf []byte, rb RTCPReceiverBlock) {
	binary.BigEndian.PutUint32(buf[0:], rb.SSRC)
	buf[4] = rb.FractionLost
	buf[5] = uint8((rb.PacketsLost >> 16) & 0xFF)
	buf[6] = uint8((rb.PacketsLost >> 8) & 0xFF)
	buf[7] = uint8(rb.PacketsLost & 0xFF)
	binary.BigEndian.PutUint32(buf[8:], rb.LastSeq)
	binary.BigEndian.PutUint32(buf[12:], rb.Jitter)
	binary.BigEndian.PutUint32(buf[16:], rb.LSR)
	binary.BigEndian.PutUint32(buf[20:], rb.DLSR)
}
