package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// IP protocol numbers for the IPsec protocols (IANA-assigned).
const (
	IPProtoESP uint8 = 50 // Encapsulating Security Payload
	IPProtoAH  uint8 = 51 // Authentication Header
)

// NewESP creates an IPsec Encapsulating Security Payload header (RFC 4303).
// Wire format:
//
//	SPI(4) | sequence(4) | encrypted payload + trailer (variable)
//
// goscapy treats ESP as an opaque container: the SPI and sequence number are
// parsed, and the remaining ciphertext (including pad/next-header trailer and
// any ICV) is carried as the "data" field. Decryption is out of scope.
func NewESP() *packet.Layer {
	return packet.NewLayer("ESP", []fields.Field{
		fields.NewIntField("spi", 0),
		fields.NewIntField("seq", 0),
		fields.NewStrField("data", ""), // encrypted payload + ESP trailer + ICV
	})
}

// NewESPWith creates an ESP header with the given SPI and sequence number.
func NewESPWith(spi, seq uint32) *packet.Layer {
	l := NewESP()
	_ = l.Set("spi", spi)
	_ = l.Set("seq", seq)
	return l
}

// NewAH creates an IPsec Authentication Header (RFC 4302).
// Wire format:
//
//	next header(1) | payload len(1) | reserved(2) | SPI(4) | sequence(4) |
//	ICV (variable, integrity check value)
//
// payload len is the AH length in 32-bit words minus 2 (RFC 4302 §2.2). It is
// auto-computed from the ICV length during Build. The next-header field names
// the protocol of the data that AH protects (e.g. IPProtoTCP); during
// dissection it selects the next layer.
func NewAH() *packet.Layer {
	return packet.NewLayer("AH", []fields.Field{
		fields.NewByteField("nh", 0),
		fields.NewByteField("len", 0), // (AH length in 32-bit words) - 2, auto-computed
		fields.NewShortField("reserved", 0),
		fields.NewIntField("spi", 0),
		fields.NewIntField("seq", 0),
		newDeferredBytesField("icv"), // integrity check value (filled by ahPostParse)
	})
}

// NewAHWith creates an AH header with the given next-header, SPI, and sequence.
func NewAHWith(nextHeader uint8, spi, seq uint32) *packet.Layer {
	l := NewAH()
	_ = l.Set("nh", nextHeader)
	_ = l.Set("spi", spi)
	_ = l.Set("seq", seq)
	return l
}

// ahBuildHook auto-computes the AH payload-length field from the ICV size.
// The AH header (RFC 4302) is: fixed 12 bytes + ICV. The "len" field holds the
// total AH length in 32-bit words minus 2, so:
//
//	len = (12 + len(icv)) / 4 - 2
func ahBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]

	icvLen := 0
	if v, err := layer.Get("icv"); err == nil {
		switch t := v.(type) {
		case []byte:
			icvLen = len(t)
		case string:
			icvLen = len(t)
		}
	}
	totalWords := (12 + icvLen) / 4
	if totalWords >= 2 {
		_ = layer.Set("len", uint8(totalWords-2))
	}
	return layer.SerializeInto(buf)
}

// ahHeaderSize returns the full AH header size in bytes from the "len" field:
// (len + 2) * 4 (RFC 4302 §2.2). Used during dissection to bound the header.
func ahHeaderSize(layer *packet.Layer) int {
	v, err := layer.Get("len")
	if err != nil {
		return 0
	}
	l, _ := v.(uint8)
	return (int(l) + 2) * 4
}

// ahPostParse trims the ICV field to the bytes between the fixed 12-byte header
// and the full AH header boundary. The fixed StrField otherwise consumes all
// remaining bytes.
func ahPostParse(layer *packet.Layer, extra []byte) error {
	icv := make([]byte, len(extra))
	copy(icv, extra)
	_ = layer.Set("icv", string(icv))
	return nil
}
