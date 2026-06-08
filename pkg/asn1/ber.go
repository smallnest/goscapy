// Package asn1 provides BER (Basic Encoding Rules) encoding and decoding
// for ASN.1 data structures. It supports the primitive and constructed types
// commonly found in SNMP, LDAP, Kerberos, and other ASN.1-based protocols.
package asn1

import (
	"fmt"
	"net"
	"strings"
)

// BER tag constants for common ASN.1 types.
const (
	TagBoolean          byte = 0x01
	TagInteger          byte = 0x02
	TagBitString        byte = 0x03
	TagOctetString      byte = 0x04
	TagNull             byte = 0x05
	TagOID              byte = 0x06
	TagEnumerated       byte = 0x0A
	TagSequence         byte = 0x30
	TagSet              byte = 0x31
	TagGeneralizedTime  byte = 0x18
	TagUTCTime          byte = 0x17

	// SNMP application tags.
	TagIPAddress  byte = 0x40
	TagCounter32  byte = 0x41
	TagGauge32    byte = 0x42
	TagTimeTicks  byte = 0x43
	TagOpaque     byte = 0x44
	TagCounter64  byte = 0x46

	// SNMP exception tags.
	TagNoSuchObject   byte = 0x80
	TagNoSuchInstance byte = 0x81
	TagEndOfMibView   byte = 0x82
)

// ---- BER Length ----

// BERLength encodes a length in BER format.
func BERLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var buf []byte
	for l := length; l > 0; l >>= 8 {
		buf = append([]byte{byte(l & 0xff)}, buf...)
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

// BERDecodeLength decodes a BER length. Returns (length, bytesConsumed, error).
func BERDecodeLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("asn1: empty length")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("asn1: invalid BER length")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

// ---- BER TLV ----

// BERTLV encodes a tag-length-value triple.
func BERTLV(tag byte, value []byte) []byte {
	var buf []byte
	buf = append(buf, tag)
	buf = append(buf, BERLength(len(value))...)
	buf = append(buf, value...)
	return buf
}

// BERDecodeTLV decodes a TLV. Returns (tag, value, bytesConsumed, error).
func BERDecodeTLV(data []byte) (byte, []byte, int, error) {
	if len(data) == 0 {
		return 0, nil, 0, fmt.Errorf("asn1: empty TLV")
	}
	tag := data[0]
	length, lenConsumed, err := BERDecodeLength(data[1:])
	if err != nil {
		return 0, nil, 0, err
	}
	totalConsumed := 1 + lenConsumed + length
	if len(data) < totalConsumed {
		return 0, nil, 0, fmt.Errorf("asn1: TLV truncated: need %d, have %d", totalConsumed, len(data))
	}
	value := data[1+lenConsumed : totalConsumed]
	return tag, value, totalConsumed, nil
}

// ---- Integer ----

// BEREncodeInteger encodes an integer.
func BEREncodeInteger(val int) []byte {
	return BERTLV(TagInteger, berEncodeIntBytes(val))
}

// BERDecodeInteger decodes an integer value from BER bytes.
func BERDecodeInteger(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("asn1: empty integer")
	}
	result := int(data[0])
	if result&0x80 != 0 {
		result = int(int8(data[0]))
	}
	for i := 1; i < len(data); i++ {
		result = (result << 8) | int(data[i])
	}
	return result, nil
}

// ---- Enumerated ----

// BEREncodeEnumerated encodes an enumerated value (tag 0x0A).
func BEREncodeEnumerated(val int) []byte {
	encoded := berEncodeIntBytes(val)
	return BERTLV(TagEnumerated, encoded)
}

// BERDecodeEnumerated decodes an enumerated value from BER bytes.
func BERDecodeEnumerated(data []byte) (int, error) {
	return BERDecodeInteger(data) // same encoding as integer, different tag
}

// ---- Boolean ----

// BEREncodeBoolean encodes a boolean value.
func BEREncodeBoolean(val bool) []byte {
	b := byte(0x00)
	if val {
		b = 0xFF
	}
	return BERTLV(TagBoolean, []byte{b})
}

// BERDecodeBoolean decodes a boolean value from BER bytes.
func BERDecodeBoolean(data []byte) (bool, error) {
	if len(data) == 0 {
		return false, fmt.Errorf("asn1: empty boolean")
	}
	return data[0] != 0, nil
}

// ---- Octet String ----

// BEREncodeOctetString encodes an octet string.
func BEREncodeOctetString(val []byte) []byte {
	return BERTLV(TagOctetString, val)
}

// ---- Null ----

// BEREncodeNull encodes a null value.
func BEREncodeNull() []byte {
	return []byte{TagNull, 0x00}
}

// ---- Bit String ----

// BEREncodeBitString encodes a bit string. unusedBits specifies the number of
// unused bits in the last byte (0-7).
func BEREncodeBitString(data []byte, unusedBits uint8) []byte {
	content := make([]byte, 0, 1+len(data))
	content = append(content, unusedBits)
	content = append(content, data...)
	return BERTLV(TagBitString, content)
}

// BERDecodeBitString decodes a bit string. Returns the data bytes and the
// number of unused bits in the last byte.
func BERDecodeBitString(data []byte) ([]byte, uint8, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("asn1: empty bit string")
	}
	unusedBits := data[0]
	if unusedBits > 7 {
		return nil, 0, fmt.Errorf("asn1: invalid unused bits %d", unusedBits)
	}
	return data[1:], unusedBits, nil
}

// ---- OID ----

// BEREncodeOID encodes an OID.
func BEREncodeOID(oid string) []byte {
	parts := parseOID(oid)
	if len(parts) < 2 {
		return BERTLV(TagOID, []byte{})
	}

	var buf []byte
	buf = append(buf, byte(parts[0]*40+parts[1]))

	for _, v := range parts[2:] {
		buf = append(buf, encodeOIDSubID(uint32(v))...)
	}
	return BERTLV(TagOID, buf)
}

// BERDecodeOID decodes an OID from BER bytes.
func BERDecodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	first := int(data[0])
	x := first / 40
	y := first % 40
	parts := []int{x, y}

	pos := 1
	for pos < len(data) {
		val, consumed := decodeOIDSubID(data[pos:])
		parts = append(parts, int(val))
		pos += consumed
	}

	return formatOID(parts)
}

func encodeOIDSubID(v uint32) []byte {
	if v < 0x80 {
		return []byte{byte(v)}
	}
	var buf []byte
	buf = append(buf, byte(v&0x7f))
	v >>= 7
	for v > 0 {
		buf = append([]byte{0x80 | byte(v&0x7f)}, buf...)
		v >>= 7
	}
	return buf
}

func decodeOIDSubID(data []byte) (uint32, int) {
	var val uint32
	for i := 0; i < len(data); i++ {
		val = (val << 7) | uint32(data[i]&0x7f)
		if data[i]&0x80 == 0 {
			return val, i + 1
		}
	}
	return val, len(data)
}

func parseOID(s string) []int {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ".")
	parts := strings.Split(s, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v := 0
		_, _ = fmt.Sscanf(p, "%d", &v)
		result = append(result, v)
	}
	return result
}

func formatOID(parts []int) string {
	s := "."
	for i, p := range parts {
		if i > 0 {
			s += "."
		}
		s += fmt.Sprintf("%d", p)
	}
	return s
}

// ---- GeneralizedTime ----

// BEREncodeGeneralizedTime encodes a GeneralizedTime value.
// The format is YYYYMMDDHHMMSSZ (UTC, RFC 4120 section 5.2.3).
func BEREncodeGeneralizedTime(data []byte) []byte {
	return BERTLV(TagGeneralizedTime, data)
}

// BERDecodeGeneralizedTime decodes a GeneralizedTime value.
// Returns the raw time string bytes (caller interprets format).
func BERDecodeGeneralizedTime(data []byte) []byte {
	return data
}

// ---- IP Address (SNMP application tag) ----

// BEREncodeIP encodes an IP address.
func BEREncodeIP(ip net.IP) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return BERTLV(TagIPAddress, make([]byte, 4))
	}
	return BERTLV(TagIPAddress, ip4)
}

// BERDecodeIP decodes an IP address.
func BERDecodeIP(data []byte) net.IP {
	if len(data) < 4 {
		return nil
	}
	return net.IP(data[:4])
}

// ---- SNMP application types ----

// BEREncodeCounter32 encodes a Counter32 value.
func BEREncodeCounter32(val uint32) []byte {
	return BERTLV(TagCounter32, encodeUint32(val))
}

// BEREncodeGauge32 encodes a Gauge32 value.
func BEREncodeGauge32(val uint32) []byte {
	return BERTLV(TagGauge32, encodeUint32(val))
}

// BEREncodeTimeTicks encodes a TimeTicks value.
func BEREncodeTimeTicks(val uint32) []byte {
	return BERTLV(TagTimeTicks, encodeUint32(val))
}

func encodeUint32(val uint32) []byte {
	if val == 0 {
		return []byte{0}
	}
	var buf []byte
	for v := val; v > 0; v >>= 8 {
		buf = append([]byte{byte(v & 0xff)}, buf...)
	}
	return buf
}

// ---- Internal helpers ----

// berEncodeIntBytes encodes an integer value as minimal BER content bytes
// (without tag/length wrapper), used by Integer and Enumerated.
func berEncodeIntBytes(val int) []byte {
	if val >= 0 && val <= 127 {
		return []byte{byte(val)}
	}
	if val < 0 && val >= -128 {
		return []byte{byte(val)}
	}

	// Build big-endian bytes with minimal representation.
	// For positive: strip leading 0x00 bytes (but keep one if high bit set).
	// For negative: strip leading 0xFF bytes (but keep one if high bit clear).
	var buf [8]byte
	n := 0
	for i := 7; i >= 0; i-- {
		buf[i] = byte(val & 0xff)
		val >>= 8
		n++
		if val == 0 || val == -1 {
			// Remaining bytes are all 0x00 (positive) or 0xFF (negative).
			// Write the sign byte and stop.
			if i > 0 {
				buf[i-1] = byte(val & 0xff)
				n++
			}
			break
		}
	}

	result := buf[8-n:]
	// Strip redundant leading bytes.
	for len(result) > 1 {
		if result[0] == 0x00 && result[1]&0x80 == 0 {
			result = result[1:]
		} else if result[0] == 0xff && result[1]&0x80 != 0 {
			result = result[1:]
		} else {
			break
		}
	}
	return result
}
