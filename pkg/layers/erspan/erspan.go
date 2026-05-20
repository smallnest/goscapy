// Package erspan implements the Encapsulated Remote SPAN (ERSPAN) v3 protocol.
//
// ERSPAN v3 is a GRE-based tunneling protocol (GRE protocol type 0x88BE) used
// for mirroring network traffic to a remote monitoring station. It provides
// metadata about the mirrored packet including session ID, VLAN, timestamp, etc.
//
// Wire format (ERSPAN v3 header, 12 bytes minimum):
//
//	Bytes 0-3: ver(4b) | vlan(12b) | cos(3b) | bso(2b) | en(2b) | t(1b) | session_id(6b) | reserved(1B)
//	Bytes 4-7: timestamp (4 bytes)
//	Bytes 8-11: sgt(16b) | p(1b) | ft(2b) | offset(5b) | hwd_id(6b) | dir(1b) | gra(2b) | oa(1b) | reserved(5b)
package erspan

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ERSPAN version constants.
const (
	VersionII  uint8 = 2 // ERSPAN Version II (Type II)
	VersionIII uint8 = 3 // ERSPAN Version III (Type III)
)

// ERSPAN v3 header sizes.
const (
	HeaderSizeV3 = 12 // 12 bytes for ERSPAN v3 header
)

// Direction constants.
const (
	DirIngress  uint8 = 0 // Ingress (received)
	DirEgress   uint8 = 1 // Egress (transmitted)
)

// NewERSPAN creates an ERSPAN v3 layer with default values.
func NewERSPAN() *packet.Layer {
	return packet.NewLayer("ERSPAN", []fields.Field{
		fields.NewByteField("ver_vlan_hi", 0x30), // ver=3 (upper 4 bits), vlan bits [11:8]=0
		fields.NewShortField("vlan_lo_cos_bso_en", 0), // vlan[7:0], cos, bso, en, t
		fields.NewByteField("session_id_flags", 0),     // session_id (6b) | reserved
		fields.NewByteField("reserved", 0),
		fields.NewIntField("timestamp", 0),   // 4-byte timestamp
		fields.NewShortField("sgt_p_ft", 0),  // sgt(16b) | p(1b) | ft(2b) | offset_high
		fields.NewShortField("offset_hw", 0), // offset(5b) | hwd_id(6b) | dir(1b) | gra(2b) | oa(1b) | reserved(1b)
	})
}

// ERSPAN holds a parsed/generatable ERSPAN header.
// This provides a more ergonomic API than raw field manipulation.
type ERSPAN struct {
	Version    uint8  // ERSPAN version (should be 3)
	VLAN       uint16 // Original VLAN ID
	COS        uint8  // Class of Service
	BSO        uint8  // Bandwidth Span Object
	En         uint8  // Encapsulation type
	T          uint8  // Truncated flag
	SessionID  uint16 // Session ID (10 bits)
	Timestamp  uint32 // Timestamp
	SGT        uint16 // Security Group Tag
	P          uint8  // Priority
	FT         uint8  // Frame Type (2 bits)
	Offset     uint8  // Offset (5 bits)
	HardwareID uint8  // Hardware ID (6 bits)
	Direction  uint8  // Direction (0=ingress, 1=egress)
	GRA        uint8  // Graceful Rate Adjustment (2 bits)
	OA         uint8  // Original Adjustable
}

// NewERSPANHeader creates a default ERSPAN v3 header.
func NewERSPANHeader() *ERSPAN {
	return &ERSPAN{
		Version:    VersionIII,
		VLAN:       0,
		COS:        0,
		BSO:        0,
		En:         0,
		T:          0,
		SessionID:  0,
		Timestamp:  0,
		SGT:        0,
		P:          0,
		FT:         0,
		Offset:     0,
		HardwareID: 0,
		Direction:  DirIngress,
		GRA:        0,
		OA:         0,
	}
}

// Serialize converts the ERSPAN header to wire-format bytes (12 bytes).
func (e *ERSPAN) Serialize() ([]byte, error) {
	buf := make([]byte, HeaderSizeV3)

	// Byte 0: ver(4b) | vlan[11:8](4b)
	buf[0] = (e.Version & 0x0F) << 4
	buf[0] |= uint8((e.VLAN >> 8) & 0x0F)

	// Byte 1: vlan[7:0]
	buf[1] = uint8(e.VLAN & 0xFF)

	// Byte 2: cos(3b) | bso(2b) | en(2b) | t(1b)
	buf[2] = (e.COS & 0x07) << 5
	buf[2] |= (e.BSO & 0x03) << 3
	buf[2] |= (e.En & 0x03) << 1
	buf[2] |= e.T & 0x01

	// Byte 3: session_id[9:4](6b) | reserved(2b)
	buf[3] = uint8(e.SessionID>>4) & 0x3F << 2

	// Byte 4: session_id[3:0](4b) | reserved(4b)
	buf[4] = uint8(e.SessionID&0x0F) << 4

	// Bytes 5: reserved
	buf[5] = 0

	// Bytes 6-9: timestamp
	binary.BigEndian.PutUint32(buf[6:10], e.Timestamp)

	// Bytes 10-11: sgt(16b)
	binary.BigEndian.PutUint16(buf[10:12], e.SGT)

	return buf, nil
}

// ParseERSPAN parses raw bytes into an ERSPAN header.
func ParseERSPAN(data []byte) (*ERSPAN, error) {
	if len(data) < HeaderSizeV3 {
		return nil, fmt.Errorf("erspan: need at least %d bytes, got %d", HeaderSizeV3, len(data))
	}

	e := &ERSPAN{}
	e.Version = (data[0] >> 4) & 0x0F
	e.VLAN = uint16(data[0]&0x0F)<<8 | uint16(data[1])
	e.COS = (data[2] >> 5) & 0x07
	e.BSO = (data[2] >> 3) & 0x03
	e.En = (data[2] >> 1) & 0x03
	e.T = data[2] & 0x01
	e.SessionID = uint16(data[3]&0xFC)<<2 | uint16(data[4]>>4)
	e.Timestamp = binary.BigEndian.Uint32(data[6:10])
	e.SGT = binary.BigEndian.Uint16(data[10:12])

	return e, nil
}
