package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// TCP flag bits (can be ORed together).
const (
	TCPSyn uint8 = 0x02
	TCPAck uint8 = 0x10
	TCPFin uint8 = 0x01
	TCPRst uint8 = 0x04
	TCPPsh uint8 = 0x08
	TCPUrg uint8 = 0x20
	TCPEce uint8 = 0x40
	TCPCwr uint8 = 0x80
)

// NewTCP creates a TCP header layer with sensible defaults.
// Defaults: dataofs=0x50 (5 words = 20 bytes, no options), flags=0, window=8192,
// checksum=0 (auto-computed during Build).
// The dataofs field stores the raw wire byte (upper nibble = data offset in 32-bit words).
func NewTCP() *packet.Layer {
	return packet.NewLayer("TCP", []fields.Field{
		fields.NewShortField("sport", 0),     // source port
		fields.NewShortField("dport", 0),     // destination port
		fields.NewIntField("seq", 0),         // sequence number
		fields.NewIntField("ack", 0),         // acknowledgment number
		fields.NewByteField("dataofs", 0x50), // data offset in upper nibble (5 << 4 = 0x50 = 20 bytes)
		fields.NewByteField("flags", 0),      // flags byte (CWR|ECE|URG|ACK|PSH|RST|SYN|FIN)
		fields.NewShortField("window", 8192),
		fields.NewShortField("chksum", 0), // auto-computed during Build
		fields.NewShortField("urgptr", 0),
		newTCPOptionsField(), // variable-length TCP options
	})
}

// NewTCPWith creates a TCP header with the given source port, destination port, and flags.
func NewTCPWith(sport, dport uint16, flags uint8) *packet.Layer {
	l := NewTCP()
	l.Set("sport", sport)
	l.Set("dport", dport)
	l.Set("flags", flags)
	return l
}

// TCPDataOffset extracts the TCP header size in bytes from the dataofs wire byte.
func TCPDataOffset(dataofs uint8) int {
	return int(dataofs>>4) * 4
}

// tcpBuildHook is called during Packet.Build() for TCP layers.
// It auto-computes dataofs (based on options length) and the TCP checksum
// using the IPv4 or IPv6 pseudo-header, writing directly into buf.
func tcpBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte, buf []byte) (int, error) {
	layer := pkt.Layers()[layerIdx]

	// Compute dataofs from serialized options.
	optsVal, _ := layer.Get("options")
	var optsBytes []byte
	if opts, ok := optsVal.([]TCPOption); ok && len(opts) > 0 {
		optsBytes = SerializeTCPOptions(opts)
	}
	hdrLen := 20 + len(optsBytes)
	layer.Set("dataofs", uint8((hdrLen/4)<<4))

	// Serialize with zero checksum into buf.
	layer.Set("chksum", uint16(0))
	n, err := layer.SerializeInto(buf)
	if err != nil {
		return 0, err
	}

	// Compute checksum without concatenation.
	addr, err := findIPAddressesAny(pkt, layerIdx)
	if err != nil {
		return 0, err
	}

	var csum uint16
	if addr.isV6 {
		csum = checksumIPv6Pseudo(addr.src, addr.dst, IPv6NextHdrTCP, buf[:n], upperBytes)
	} else {
		csum = checksumIPv4Pseudo(addr.src, addr.dst, 6, buf[:n], upperBytes)
	}
	layer.Set("chksum", csum)
	buf[16] = byte(csum >> 8)
	buf[17] = byte(csum)
	return n, nil
}
