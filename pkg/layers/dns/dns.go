package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// DNS type (QTYPE) constants.
const (
	QtypeA     uint16 = 1
	QtypeNS    uint16 = 2
	QtypeCNAME uint16 = 5
	QtypeSOA   uint16 = 6
	QtypePTR   uint16 = 12
	QtypeMX    uint16 = 15
	QtypeTXT   uint16 = 16
	QtypeAAAA  uint16 = 28
	QtypeOPT   uint16 = 41
)

// DNS class (QCLASS) constants.
const (
	QclassIN uint16 = 1
)

// Max compression pointer hops to prevent loops.
const maxCompressionHops = 16

// DNSQuestion represents a single question section entry.
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNSRR represents a single Resource Record.
type DNSRR struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// NewDNS creates a DNS message layer with a standard query header.
// Default: ID=0, flags=0x0100 (RD=1), QDCount=0, ANCount=0, NSCount=0, ARCount=0.
func NewDNS() *packet.Layer {
	return packet.NewLayer("DNS", []fields.Field{
		fields.NewShortField("id", 0),
		fields.NewShortField("flags", 0x0100),
		fields.NewShortField("qdcount", 0),
		fields.NewShortField("ancount", 0),
		fields.NewShortField("nscount", 0),
		fields.NewShortField("arcount", 0),
		fields.NewStrField("data", ""),
	})
}

// EncodeName converts a dot-separated domain name to wire-format labels
// (e.g., "www.example.com" → [3]www[7]example[3]com[0]).
func EncodeName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	var out []byte
	parts := strings.Split(name, ".")
	for _, p := range parts {
		if len(p) > 63 {
			p = p[:63]
		}
		out = append(out, byte(len(p)))
		out = append(out, []byte(p)...)
	}
	out = append(out, 0)
	return out
}

// DecodeName decodes wire-format labels at offset within msg.
// msgStart is the beginning of the full DNS message (for compression offset resolution).
// Returns the decoded name, the number of bytes consumed, and any error.
func DecodeName(msg []byte, offset int, msgStart int) (string, int, error) {
	var labels []string
	pos := offset
	consumed := 0
	hops := 0
	counting := true

	for hops <= maxCompressionHops {
		if pos >= len(msg) {
			return "", consumed, fmt.Errorf("dns: name truncated at offset %d", pos)
		}
		b := msg[pos]
		if b == 0 {
			if counting {
				consumed++
			}
			break
		}
		// Compression pointer: upper 2 bits set (0xC0).
		if b&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				return "", consumed, fmt.Errorf("dns: truncated compression pointer at %d", pos)
			}
			ptr := int(b&0x3F)<<8 | int(msg[pos+1])
			if ptr >= len(msg) {
				return "", consumed, fmt.Errorf("dns: compression pointer out of range: %d", ptr)
			}
			if counting {
				consumed += 2
				counting = false
			}
			pos = msgStart + ptr
			hops++
			continue
		}
		// Standard label.
		length := int(b)
		pos++
		if counting {
			consumed++
		}
		if pos+length > len(msg) {
			return "", consumed, fmt.Errorf("dns: label length %d exceeds buffer at %d", length, pos-1)
		}
		labels = append(labels, string(msg[pos:pos+length]))
		pos += length
		if counting {
			consumed += length
		}
	}
	if hops > maxCompressionHops {
		return "", consumed, fmt.Errorf("dns: max compression hops exceeded")
	}
	if len(labels) == 0 {
		return ".", consumed, nil
	}
	return strings.Join(labels, "."), consumed, nil
}

// ParseQuestions parses n DNS questions from data at offset.
// msgStart is the beginning of the full DNS message for compression resolution.
func ParseQuestions(data []byte, offset int, n int, msgStart int) ([]DNSQuestion, int, error) {
	pos := offset
	var out []DNSQuestion
	for i := 0; i < n; i++ {
		name, c, err := DecodeName(data, pos, msgStart)
		if err != nil {
			return nil, 0, err
		}
		pos += c
		if pos+4 > len(data) {
			return nil, 0, fmt.Errorf("dns: truncated question at %d", pos)
		}
		qtype := binary.BigEndian.Uint16(data[pos : pos+2])
		qclass := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4
		out = append(out, DNSQuestion{Name: name, Type: qtype, Class: qclass})
	}
	return out, pos - offset, nil
}

// ParseRRs parses n resource records from data at offset.
func ParseRRs(data []byte, offset int, n int, msgStart int) ([]DNSRR, int, error) {
	pos := offset
	var out []DNSRR
	for i := 0; i < n; i++ {
		name, c, err := DecodeName(data, pos, msgStart)
		if err != nil {
			return nil, 0, err
		}
		pos += c
		if pos+10 > len(data) {
			return nil, 0, fmt.Errorf("dns: truncated RR at %d", pos)
		}
		rrtype := binary.BigEndian.Uint16(data[pos : pos+2])
		rrclass := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		ttl := binary.BigEndian.Uint32(data[pos+4 : pos+8])
		rdlen := binary.BigEndian.Uint16(data[pos+8 : pos+10])
		pos += 10
		if pos+int(rdlen) > len(data) {
			return nil, 0, fmt.Errorf("dns: RR RDATA truncated at %d", pos)
		}
		rdata := make([]byte, rdlen)
		copy(rdata, data[pos:pos+int(rdlen)])
		pos += int(rdlen)
		out = append(out, DNSRR{Name: name, Type: rrtype, Class: rrclass, TTL: ttl, RDLength: rdlen, RData: rdata})
	}
	return out, pos - offset, nil
}

// BuildQuestion encodes a question into wire format.
func BuildQuestion(q DNSQuestion) []byte {
	name := EncodeName(q.Name)
	buf := make([]byte, len(name)+4)
	copy(buf, name)
	binary.BigEndian.PutUint16(buf[len(name):], q.Type)
	binary.BigEndian.PutUint16(buf[len(name)+2:], q.Class)
	return buf
}

// BuildRR encodes a resource record into wire format.
func BuildRR(rr DNSRR) []byte {
	name := EncodeName(rr.Name)
	size := len(name) + 10 + len(rr.RData)
	buf := make([]byte, size)
	copy(buf, name)
	off := len(name)
	binary.BigEndian.PutUint16(buf[off:], rr.Type)
	binary.BigEndian.PutUint16(buf[off+2:], rr.Class)
	binary.BigEndian.PutUint32(buf[off+4:], rr.TTL)
	binary.BigEndian.PutUint16(buf[off+8:], rr.RDLength)
	copy(buf[off+10:], rr.RData)
	return buf
}

// GetQuestions extracts parsed DNSQuestion entries from a DNS layer.
func GetQuestions(layer *packet.Layer) ([]DNSQuestion, error) {
	data, _ := layer.Get("data")
	qdcount, _ := layer.Get("qdcount")
	b := data.([]byte)
	qs, _, err := ParseQuestions(b, 0, int(qdcount.(uint16)), -12)
	return qs, err
}

// GetAnswers extracts parsed DNSRR entries (answer section) from a DNS layer.
func GetAnswers(layer *packet.Layer) ([]DNSRR, error) {
	data, _ := layer.Get("data")
	qdcount, _ := layer.Get("qdcount")
	ancount, _ := layer.Get("ancount")
	b := data.([]byte)
	// Skip questions first.
	_, qConsumed, err := ParseQuestions(b, 0, int(qdcount.(uint16)), -12)
	if err != nil {
		return nil, err
	}
	rr, _, err := ParseRRs(b, qConsumed, int(ancount.(uint16)), -12)
	return rr, err
}

// BuildDNSMessage builds the DNS data field from questions and RR sections.
func BuildDNSMessage(questions []DNSQuestion, answers, authorities, additionals []DNSRR) []byte {
	var out []byte
	for _, q := range questions {
		out = append(out, BuildQuestion(q)...)
	}
	for _, rr := range answers {
		out = append(out, BuildRR(rr)...)
	}
	for _, rr := range authorities {
		out = append(out, BuildRR(rr)...)
	}
	for _, rr := range additionals {
		out = append(out, BuildRR(rr)...)
	}
	return out
}

// BuildARData builds an A record RDATA from an IPv4 string.
func BuildARData(ip string) []byte {
	b := make([]byte, 4)
	_, _ = fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	return b
}

// BuildAAAARData builds an AAAA record RDATA from an IPv6 string.
func BuildAAAARData(ip string) []byte {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return make([]byte, 16)
	}
	return parsed.To16()
}

// ParseARData parses an A record RDATA to a string.
func ParseARData(rdata []byte) string {
	if len(rdata) < 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
}

// ParseAAAARData parses an AAAA record RDATA to a string.
func ParseAAAARData(rdata []byte) string {
	if len(rdata) < 16 {
		return ""
	}
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(rdata[i*2:]))
	}
	return strings.Join(parts, ":")
}

// ParseCNAMERData parses a CNAME RDATA from within the full message.
func ParseCNAMERData(rdata []byte, msgStart int) (string, error) {
	name, _, err := DecodeName(rdata, 0, msgStart-len(rdata))
	return name, err
}

// BuildSOARData builds an SOA RDATA.
func BuildSOARData(mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	mn := EncodeName(mname)
	rn := EncodeName(rname)
	buf := make([]byte, len(mn)+len(rn)+20)
	off := 0
	copy(buf[off:], mn)
	off += len(mn)
	copy(buf[off:], rn)
	off += len(rn)
	binary.BigEndian.PutUint32(buf[off:], serial)
	binary.BigEndian.PutUint32(buf[off+4:], refresh)
	binary.BigEndian.PutUint32(buf[off+8:], retry)
	binary.BigEndian.PutUint32(buf[off+12:], expire)
	binary.BigEndian.PutUint32(buf[off+16:], minimum)
	return buf
}

// BuildMXData builds an MX RDATA.
func BuildMXData(preference uint16, exchange string) []byte {
	ex := EncodeName(exchange)
	buf := make([]byte, 2+len(ex))
	binary.BigEndian.PutUint16(buf, preference)
	copy(buf[2:], ex)
	return buf
}

// BuildEDNS0 builds an EDNS(0) OPT pseudo-RR.
func BuildEDNS0(udpSize uint16, d0 uint8, extRCode uint8, version uint8, options []byte) *DNSRR {
	ttl := uint32(extRCode)<<24 | uint32(version)<<16 | uint32(d0)<<8
	return &DNSRR{
		Name:     ".",
		Type:     QtypeOPT,
		Class:    udpSize,
		TTL:      ttl,
		RDLength: uint16(len(options)),
		RData:    options,
	}
}