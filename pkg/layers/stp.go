package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// STP BPDU types (IEEE 802.1D).
const (
	STPBPDUConfig         uint8 = 0x00 // Configuration BPDU
	STPBPDUTopologyChange uint8 = 0x80 // Topology Change Notification BPDU
)

// STP protocol identifier and version.
const (
	STPProtocolID uint16 = 0x0000
	STPVersionSTP uint8  = 0x00
	STPVersionRST uint8  = 0x02 // Rapid Spanning Tree
)

// NewSTP creates a Spanning Tree Protocol Configuration BPDU (IEEE 802.1D).
// Wire format (35 bytes):
//
//	protocol id(2) | version(1) | bpdu type(1) | flags(1) |
//	root id(8) | root path cost(4) | bridge id(8) | port id(2) |
//	message age(2) | max age(2) | hello time(2) | forward delay(2)
//
// Bridge/root IDs are 8 bytes (2-byte priority + 6-byte MAC). Times are in
// units of 1/256 second per 802.1D. STP is typically carried in an 802.3 LLC
// frame (DSAP/SSAP 0x42); goscapy models the BPDU itself.
func NewSTP() *packet.Layer {
	return packet.NewLayer("STP", []fields.Field{
		fields.NewShortField("proto", STPProtocolID),
		fields.NewByteField("version", STPVersionSTP),
		fields.NewByteField("bpdutype", STPBPDUConfig),
		fields.NewXByteField("flags", 0),
		fields.NewStrFixedField("rootid", 8, nil),
		fields.NewIntField("rootcost", 0),
		fields.NewStrFixedField("bridgeid", 8, nil),
		fields.NewShortField("portid", 0x8001),
		fields.NewShortField("age", 0),
		fields.NewShortField("maxage", 20*256),
		fields.NewShortField("hello", 2*256),
		fields.NewShortField("fwddelay", 15*256),
	})
}

// NewSTPConfig creates an STP Configuration BPDU with the given bridge priority
// and bridge MAC, using it for both the root and bridge identifiers.
func NewSTPConfig(priority uint16, bridgeMAC string) *packet.Layer {
	l := NewSTP()
	id := bridgeID(priority, bridgeMAC)
	_ = l.Set("rootid", id)
	_ = l.Set("bridgeid", id)
	return l
}

// bridgeID builds an 8-byte STP bridge identifier (2-byte priority + 6-byte MAC).
func bridgeID(priority uint16, mac string) []byte {
	id := make([]byte, 8)
	id[0] = byte(priority >> 8)
	id[1] = byte(priority)
	if m := macBytes(mac); len(m) == 6 {
		copy(id[2:], m)
	}
	return id
}

// macBytes parses a MAC string into 6 bytes, or nil on error.
func macBytes(s string) []byte {
	l := NewEthernet()
	if err := l.Set("src", s); err != nil {
		return nil
	}
	f := l.FindField("src")
	v, _ := l.Get("src")
	b, err := f.Pack(v)
	if err != nil {
		return nil
	}
	return b
}
