package gre

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// GRE flag bits (RFC 2784) within the flagsver uint16 (big-endian).
const (
	FlagC uint16 = 0x8000 // Checksum Present (bit 15)
	FlagR uint16 = 0x4000 // Reserved0 (bit 14, must be 0)
	FlagK uint16 = 0x2000 // Key Present (bit 13)
	FlagS uint16 = 0x1000 // Sequence Number Present (bit 12)
)

// GRE ProtocolType values.
const (
	ProtoIP       uint16 = 0x0800
	ProtoEthernet uint16 = 0x6558
)

// condition helpers for ConditionalField.
func cFlagSet(vals map[string]any) bool {
	fv, ok := vals["flagsver"]
	return ok && fv.(uint16)&FlagC != 0
}

func kFlagSet(vals map[string]any) bool {
	fv, ok := vals["flagsver"]
	return ok && fv.(uint16)&FlagK != 0
}

func sFlagSet(vals map[string]any) bool {
	fv, ok := vals["flagsver"]
	return ok && fv.(uint16)&FlagS != 0
}

// GRE wraps a packet.Layer with chainable builder methods.
type GRE struct {
	*packet.Layer
}

// NewGRE creates a GRE builder with default ProtocolType=0x0800 (IP).
func NewGRE() *GRE {
	return &GRE{newGRELayer()}
}

func newGRELayer() *packet.Layer {
	return packet.NewLayer("GRE", []fields.Field{
		// Base: flagsver (2B) + proto (2B) = 4 bytes
		fields.NewShortField("flagsver", 0),
		fields.NewShortField("proto", ProtoIP),
		// Optional: Checksum (4B, C=1)
		fields.NewConditionalField(fields.NewShortField("chksum", 0), cFlagSet),
		fields.NewConditionalField(fields.NewShortField("reserved1", 0), cFlagSet),
		// Optional: Key (4B, K=1)
		fields.NewConditionalField(fields.NewIntField("key", 0), kFlagSet),
		// Optional: Sequence Number (4B, S=1)
		fields.NewConditionalField(fields.NewIntField("seq", 0), sFlagSet),
	})
}

// NewGRELayer creates a GRE layer for use with the packet registry.
func NewGRELayer() *packet.Layer {
	return newGRELayer()
}

// ProtocolType sets the ProtocolType and returns the builder.
func (g *GRE) ProtocolType(pt uint16) *GRE {
	g.Layer.Set("proto", pt)
	return g
}

// Key sets the Key field and enables the K flag, returning the builder.
func (g *GRE) Key(k uint32) *GRE {
	g.Layer.Set("key", k)
	flags, _ := g.Layer.Get("flagsver")
	g.Layer.Set("flagsver", flags.(uint16)|FlagK)
	return g
}

// Seq sets the Sequence Number and enables the S flag, returning the builder.
func (g *GRE) Seq(s uint32) *GRE {
	g.Layer.Set("seq", s)
	flags, _ := g.Layer.Get("flagsver")
	g.Layer.Set("flagsver", flags.(uint16)|FlagS)
	return g
}

// SetChecksum sets the Checksum and enables the C flag, returning the builder.
func (g *GRE) SetChecksum(csum uint16) *GRE {
	g.Layer.Set("chksum", csum)
	g.Layer.Set("reserved1", uint16(0))
	flags, _ := g.Layer.Get("flagsver")
	g.Layer.Set("flagsver", flags.(uint16)|FlagC)
	return g
}

// ---- Getters ----

// GetProtocolType extracts the ProtocolType from a GRE layer.
func GetProtocolType(layer *packet.Layer) uint16 {
	p, _ := layer.Get("proto")
	return p.(uint16)
}

// GetKey extracts the Key field. Returns 0 if K flag is not set.
func GetKey(layer *packet.Layer) uint32 {
	k, err := layer.Get("key")
	if err != nil {
		return 0
	}
	return k.(uint32)
}

// GetSeq extracts the Sequence Number. Returns 0 if S flag is not set.
func GetSeq(layer *packet.Layer) uint32 {
	s, err := layer.Get("seq")
	if err != nil {
		return 0
	}
	return s.(uint32)
}

// HasKey reports whether the K flag is set.
func HasKey(layer *packet.Layer) bool {
	fv, _ := layer.Get("flagsver")
	return fv.(uint16)&FlagK != 0
}

// HasSeq reports whether the S flag is set.
func HasSeq(layer *packet.Layer) bool {
	fv, _ := layer.Get("flagsver")
	return fv.(uint16)&FlagS != 0
}