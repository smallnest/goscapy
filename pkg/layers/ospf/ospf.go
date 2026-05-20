// Package ospf implements the OSPF (Open Shortest Path First, RFC 2328) protocol.
//
// OSPF is a link-state interior gateway protocol (IGP) used for routing within
// an autonomous system. It uses IP protocol number 89.
//
// This package implements:
//   - OSPFv2 common header
//   - Hello message
//   - Database Description (DBD) message
//   - Link State Request (LSR) message
//   - Link State Update (LSU) message
//   - Link State Acknowledgement (LSAck) message
//   - LSA Header struct
//
// Packet-level only, no adjacency state machine.
package ospf

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// OSPF message type constants.
const (
	TypeHello uint8 = 1 // Hello
	TypeDBD   uint8 = 2 // Database Description
	TypeLSR   uint8 = 3 // Link State Request
	TypeLSU   uint8 = 4 // Link State Update
	TypeLSAck uint8 = 5 // Link State Acknowledgement
)

// OSPF authentication type constants.
const (
	AuthNone   uint16 = 0 // No authentication
	AuthSimple uint16 = 1 // Simple password
	AuthCrypto uint16 = 2 // Cryptographic (MD5/HMAC)
)

// OSPF options flag bits.
const (
	OptMT uint8 = 0x80 // Multi-Topology
	OptE  uint8 = 0x40 // External routing capability
	OptMC uint8 = 0x20 // Multicast
	OptNP uint8 = 0x10 // NSSA capability
	OptL  uint8 = 0x08 // LLS data block present
	OptDC uint8 = 0x04 // Demand circuits
	OptO  uint8 = 0x02 // Opaque LSA
	OptDN uint8 = 0x01 // Downstream bit
)

// OSPF DBD flags.
const (
	DBDFlagMS uint8 = 0x80 // Master/Slave
	DBDFlagM  uint8 = 0x40 // More bits to follow
	DBDFlagI  uint8 = 0x20 // Initialize
)

// OSPF Header size.
const HeaderSize = 24

// NewOSPF creates an OSPFv2 common header layer.
// Wire format (24 bytes):
//
//	version(1) | type(1) | length(2) | router_id(4) | area_id(4) |
//	checksum(2) | auth_type(2) | auth_data(8)
func NewOSPF() *packet.Layer {
	return packet.NewLayer("OSPF", []fields.Field{
		fields.NewByteField("version", 2),                   // OSPF version 2
		fields.NewByteField("type", TypeHello),               // Message type
		fields.NewShortField("len", HeaderSize),              // Total OSPF packet length
		fields.NewIPField("router_id", nil),                  // Router ID
		fields.NewIPField("area_id", nil),                    // Area ID
		fields.NewShortField("chksum", 0),                    // Checksum
		fields.NewShortField("auth_type", AuthNone),          // Authentication type
		fields.NewLongField("auth_data", 0),                  // Authentication data (8 bytes)
	})
}

// NewOSPFHello creates an OSPF Hello message body.
// Wire format (20+ bytes):
//
//	mask(4) | hello_interval(2) | options(1) | priority(1) |
//	dead_interval(4) | dr(4) | bdr(4) | neighbors[](4 each)
func NewOSPFHello() *packet.Layer {
	return packet.NewLayer("OSPF Hello", []fields.Field{
		fields.NewIPField("mask", nil),                       // Network mask
		fields.NewShortField("hello_interval", 10),           // Hello interval (seconds)
		fields.NewByteField("options", OptE),                  // Options
		fields.NewByteField("prio", 1),                        // Router priority
		fields.NewIntField("dead_interval", 40),               // Dead interval (seconds)
		fields.NewIPField("dr", nil),                          // Designated Router
		fields.NewIPField("bdr", nil),                         // Backup Designated Router
		fields.NewStrField("neighbors", ""),                   // Neighbor list (4 bytes each)
	})
}

// NewOSPFDBD creates an OSPF Database Description message body.
// Wire format (8 bytes + LSA headers):
//
//	mtu(2) | options(1) | flags(1) | dd_seq(4) | lsa_headers[]
func NewOSPFDBD() *packet.Layer {
	return packet.NewLayer("OSPF DBD", []fields.Field{
		fields.NewShortField("mtu", 1500),                    // Interface MTU
		fields.NewByteField("options", OptE),                  // Options
		fields.NewByteField("flags", DBDFlagMS|DBDFlagM|DBDFlagI), // DBD flags
		fields.NewIntField("dd_seq", 1),                       // DD sequence number
		fields.NewStrField("lsa_headers", ""),                 // LSA headers
	})
}

// NewOSPFLSR creates an OSPF Link State Request message body.
// Wire format (12 bytes per entry):
//
//	ls_type(4) | ls_id(4) | adv_router(4)
func NewOSPFLSR() *packet.Layer {
	return packet.NewLayer("OSPF LSR", []fields.Field{
		fields.NewStrField("requests", ""),                    // Raw request entries
	})
}

// NewOSPFLSU creates an OSPF Link State Update message body.
// Wire format (4 bytes + LSAs):
//
//	count(4) | lsas[]
func NewOSPFLSU() *packet.Layer {
	return packet.NewLayer("OSPF LSU", []fields.Field{
		fields.NewIntField("count", 0),                        // Number of LSAs
		fields.NewStrField("lsas", ""),                        // Raw LSA data
	})
}

// NewOSPFLSAck creates an OSPF Link State Acknowledgement message body.
// Contains a list of LSA headers.
func NewOSPFLSAck() *packet.Layer {
	return packet.NewLayer("OSPF LSAck", []fields.Field{
		fields.NewStrField("lsa_headers", ""),                 // LSA headers
	})
}

// LSAHeader represents a 20-byte OSPF LSA header.
type LSAHeader struct {
	Age       uint16 // Time since origination (seconds)
	Options   uint8  // Options
	Type      uint8  // LSA type (1=Router, 2=Network, etc.)
	ID        uint32 // Link State ID
	AdvRouter uint32 // Advertising Router
	Seq       uint32 // Sequence number
	Checksum  uint16 // Fletcher checksum
	Length    uint16 // Total LSA length including header
}

// Serialize converts an LSAHeader to wire-format bytes (20 bytes).
func (h *LSAHeader) Serialize() []byte {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], h.Age)
	buf[2] = h.Options
	buf[3] = h.Type
	binary.BigEndian.PutUint32(buf[4:8], h.ID)
	binary.BigEndian.PutUint32(buf[8:12], h.AdvRouter)
	binary.BigEndian.PutUint32(buf[12:16], h.Seq)
	binary.BigEndian.PutUint16(buf[16:18], h.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], h.Length)
	return buf
}

// ParseLSAHeader parses a 20-byte LSA header from raw bytes.
func ParseLSAHeader(data []byte) (*LSAHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("ospf: LSA header needs 20 bytes, got %d", len(data))
	}
	h := &LSAHeader{
		Age:       binary.BigEndian.Uint16(data[0:2]),
		Options:   data[2],
		Type:      data[3],
		ID:        binary.BigEndian.Uint32(data[4:8]),
		AdvRouter: binary.BigEndian.Uint32(data[8:12]),
		Seq:       binary.BigEndian.Uint32(data[12:16]),
		Checksum:  binary.BigEndian.Uint16(data[16:18]),
		Length:    binary.BigEndian.Uint16(data[18:20]),
	}
	return h, nil
}

// OSPFChecksum computes the OSPF checksum (same algorithm as IP checksum).
// The checksum covers the entire OSPF packet with the checksum field set to 0.
func OSPFChecksum(data []byte) uint16 {
	return ipChecksum(data)
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
