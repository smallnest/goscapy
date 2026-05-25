package snmp

import (
	"fmt"
	"net"
	"strings"
)

// BER tag constants.
const (
	TagInteger       = 0x02
	TagOctetString   = 0x04
	TagNull          = 0x05
	TagOID           = 0x06
	TagSequence      = 0x30
	TagIPAddress     = 0x40
	TagCounter32     = 0x41
	TagGauge32       = 0x42
	TagTimeTicks     = 0x43
	TagOpaque        = 0x44
	TagCounter64     = 0x46
	TagNoSuchObject  = 0x80
	TagNoSuchInstance = 0x81
	TagEndOfMibView  = 0x82
)

// SNMP PDU type tags.
const (
	PDUGetRequest     byte = 0xa0
	PDUGetNextRequest byte = 0xa1
	PDUGetResponse    byte = 0xa2
	PDUSetRequest     byte = 0xa3
	PDUTrap           byte = 0xa4
	PDUGetBulk        byte = 0xa5
	PDUInform         byte = 0xa6
	PDUTrapV2         byte = 0xa7
	PDUReport         byte = 0xa8
)

// SNMP version constants.
const (
	Version1   int = 0
	Version2c  int = 1
	Version3   int = 3
)

// ---- BER Encoding ----

// BERLength encodes a length in BER format.
func BERLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Long form.
	var buf []byte
	for l := length; l > 0; l >>= 8 {
		buf = append([]byte{byte(l & 0xff)}, buf...)
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

// BERDecodeLength decodes a BER length. Returns (length, bytesConsumed, error).
func BERDecodeLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("snmp: empty length")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("snmp: invalid BER length")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

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
		return 0, nil, 0, fmt.Errorf("snmp: empty TLV")
	}
	tag := data[0]
	length, lenConsumed, err := BERDecodeLength(data[1:])
	if err != nil {
		return 0, nil, 0, err
	}
	totalConsumed := 1 + lenConsumed + length
	if len(data) < totalConsumed {
		return 0, nil, 0, fmt.Errorf("snmp: TLV truncated: need %d, have %d", totalConsumed, len(data))
	}
	value := data[1+lenConsumed : totalConsumed]
	return tag, value, totalConsumed, nil
}

// BEREncodeInteger encodes an integer.
func BEREncodeInteger(val int) []byte {
	// Determine minimum bytes needed.
	if val >= 0 && val <= 127 {
		return BERTLV(TagInteger, []byte{byte(val)})
	}
	if val < 0 && val >= -128 {
		return BERTLV(TagInteger, []byte{byte(val)})
	}

	var buf []byte
	v := val
	if val < 0 {
		// Two's complement for negative.
		uv := uint64(val) & 0xFFFFFFFFFFFFFFFF
		for uv != 0 {
			buf = append([]byte{byte(uv & 0xff)}, buf...)
			uv >>= 8
		}
		// Ensure sign bit.
		if len(buf) > 0 && buf[0]&0x80 == 0 {
			buf = append([]byte{0xff}, buf...)
		}
	} else {
		for v > 0 {
			buf = append([]byte{byte(v & 0xff)}, buf...)
			v >>= 8
		}
		if buf[0]&0x80 != 0 {
			buf = append([]byte{0x00}, buf...)
		}
	}
	return BERTLV(TagInteger, buf)
}

// BERDecodeInteger decodes an integer value from BER bytes.
func BERDecodeInteger(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("snmp: empty integer")
	}
	// Sign extend.
	result := int(data[0])
	if result&0x80 != 0 {
		result = int(int8(data[0]))
	}
	for i := 1; i < len(data); i++ {
		result = (result << 8) | int(data[i])
	}
	return result, nil
}

// BEREncodeOctetString encodes an octet string.
func BEREncodeOctetString(val []byte) []byte {
	return BERTLV(TagOctetString, val)
}

// BEREncodeNull encodes a null value.
func BEREncodeNull() []byte {
	return []byte{TagNull, 0x00}
}

// BEREncodeOID encodes an OID.
func BEREncodeOID(oid string) []byte {
	parts := parseOID(oid)
	if len(parts) < 2 {
		return BERTLV(TagOID, []byte{})
	}

	var buf []byte
	// First two components encoded as one byte.
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
	if strings.HasPrefix(s, ".") {
		s = s[1:]
	}
	parts := strings.Split(s, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v := 0
		fmt.Sscanf(p, "%d", &v)
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

// ---- SNMP Types ----

// VarBind represents an SNMP variable binding.
type VarBind struct {
	OID   string
	Value []byte // Raw BER-encoded value
}

// SNMPMessage represents a parsed SNMP message.
type SNMPMessage struct {
	Version   int
	Community string
	PDUType   byte
	RequestID int
	ErrorStatus int
	ErrorIndex  int
	VarBinds  []VarBind
	// Trap-v1 specific fields
	Enterprise   string
	AgentAddr    net.IP
	GenericTrap  int
	SpecificTrap int
	Timestamp    uint32
}

// ---- SNMP Build ----

// BuildSNMP builds a complete SNMP message.
func BuildSNMP(msg *SNMPMessage) []byte {
	// Encode version and community.
	version := BEREncodeInteger(msg.Version)
	community := BEREncodeOctetString([]byte(msg.Community))

	var pdu []byte
	if msg.PDUType == PDUTrap {
		pdu = buildTrapPDU(msg)
	} else {
		pdu = buildPDUNormal(msg)
	}

	inner := append(version, community...)
	inner = append(inner, pdu...)

	return BERTLV(TagSequence, inner)
}

func buildPDUNormal(msg *SNMPMessage) []byte {
	reqID := BEREncodeInteger(msg.RequestID)
	errStatus := BEREncodeInteger(msg.ErrorStatus)
	errIndex := BEREncodeInteger(msg.ErrorIndex)
	varBinds := buildVarBinds(msg.VarBinds)

	inner := append(reqID, errStatus...)
	inner = append(inner, errIndex...)
	inner = append(inner, varBinds...)

	return BERTLV(msg.PDUType, inner)
}

func buildTrapPDU(msg *SNMPMessage) []byte {
	enterprise := BEREncodeOID(msg.Enterprise)
	agentAddr := BEREncodeIP(msg.AgentAddr)
	genericTrap := BEREncodeInteger(msg.GenericTrap)
	specificTrap := BEREncodeInteger(msg.SpecificTrap)
	timestamp := BEREncodeTimeTicks(msg.Timestamp)
	varBinds := buildVarBinds(msg.VarBinds)

	inner := append(enterprise, agentAddr...)
	inner = append(inner, genericTrap...)
	inner = append(inner, specificTrap...)
	inner = append(inner, timestamp...)
	inner = append(inner, varBinds...)

	return BERTLV(PDUTrap, inner)
}

func buildVarBinds(vbs []VarBind) []byte {
	var inner []byte
	for _, vb := range vbs {
		oid := BEREncodeOID(vb.OID)
		val := vb.Value
		if val == nil {
			val = BEREncodeNull()
		}
		vbInner := append(oid, val...)
		inner = append(inner, BERTLV(TagSequence, vbInner)...)
	}
	return BERTLV(TagSequence, inner)
}

// ---- SNMP Parse ----

// ParseSNMP parses a raw SNMP message.
func ParseSNMP(data []byte) (*SNMPMessage, error) {
	tag, value, consumed, err := BERDecodeTLV(data)
	if err != nil {
		return nil, fmt.Errorf("snmp: parse outer: %w", err)
	}
	if tag != TagSequence {
		return nil, fmt.Errorf("snmp: expected SEQUENCE, got 0x%02x", tag)
	}
	_ = consumed

	pos := 0

	// Version.
	vTag, vVal, vConsumed, err := BERDecodeTLV(value[pos:])
	if err != nil {
		return nil, fmt.Errorf("snmp: parse version: %w", err)
	}
	if vTag != TagInteger {
		return nil, fmt.Errorf("snmp: version tag = 0x%02x", vTag)
	}
	version, _ := BERDecodeInteger(vVal)
	pos += vConsumed

	// Community.
	cTag, cVal, cConsumed, err := BERDecodeTLV(value[pos:])
	if err != nil {
		return nil, fmt.Errorf("snmp: parse community: %w", err)
	}
	if cTag != TagOctetString {
		return nil, fmt.Errorf("snmp: community tag = 0x%02x", cTag)
	}
	community := string(cVal)
	pos += cConsumed

	msg := &SNMPMessage{
		Version:   version,
		Community: community,
	}

	// PDU.
	pduTag, pduVal, _, err := BERDecodeTLV(value[pos:])
	if err != nil {
		return nil, fmt.Errorf("snmp: parse PDU: %w", err)
	}
	msg.PDUType = pduTag

	if pduTag == PDUTrap {
		err = parseTrapPDU(pduVal, msg)
	} else {
		err = parseNormalPDU(pduVal, msg)
	}
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func parseNormalPDU(data []byte, msg *SNMPMessage) error {
	pos := 0

	// Request ID.
	tag, val, consumed, err := BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.RequestID, _ = BERDecodeInteger(val)
	pos += consumed

	// Error status.
	tag, val, consumed, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.ErrorStatus, _ = BERDecodeInteger(val)
	pos += consumed

	// Error index.
	tag, val, consumed, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.ErrorIndex, _ = BERDecodeInteger(val)
	pos += consumed
	_ = tag

	// VarBinds.
	tag, val, _, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	if tag == TagSequence {
		msg.VarBinds, err = parseVarBinds(val)
	}

	return err
}

func parseTrapPDU(data []byte, msg *SNMPMessage) error {
	pos := 0

	// Enterprise OID.
	_, val, consumed, err := BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.Enterprise = BERDecodeOID(val)
	pos += consumed

	// Agent address.
	_, val, consumed, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.AgentAddr = BERDecodeIP(val)
	pos += consumed

	// Generic trap.
	_, val, consumed, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.GenericTrap, _ = BERDecodeInteger(val)
	pos += consumed

	// Specific trap.
	_, val, consumed, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.SpecificTrap, _ = BERDecodeInteger(val)
	pos += consumed

	// Timestamp.
	_, val, consumed, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	ts, _ := BERDecodeInteger(val)
	msg.Timestamp = uint32(ts)
	pos += consumed

	// VarBinds.
	_, val, _, err = BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.VarBinds, err = parseVarBinds(val)
	return err
}

func parseVarBinds(data []byte) ([]VarBind, error) {
	var vbs []VarBind
	pos := 0
	for pos < len(data) {
		tag, val, consumed, err := BERDecodeTLV(data[pos:])
		if err != nil {
			break
		}
		if tag != TagSequence {
			break
		}

		vb, err := parseVarBind(val)
		if err != nil {
			break
		}
		vbs = append(vbs, vb)
		pos += consumed
	}
	return vbs, nil
}

func parseVarBind(data []byte) (VarBind, error) {
	pos := 0

	// OID.
	_, val, consumed, err := BERDecodeTLV(data[pos:])
	if err != nil {
		return VarBind{}, err
	}
	oid := BERDecodeOID(val)
	pos += consumed

	// Value — store raw bytes (tag + length + value).
	if pos >= len(data) {
		return VarBind{OID: oid, Value: BEREncodeNull()}, nil
	}
	value := data[pos:]

	return VarBind{OID: oid, Value: value}, nil
}

// ---- Helpers ----

// PDUTypeName returns the name of a PDU type.
func PDUTypeName(pduType byte) string {
	switch pduType {
	case PDUGetRequest:
		return "GetRequest"
	case PDUGetNextRequest:
		return "GetNextRequest"
	case PDUGetResponse:
		return "GetResponse"
	case PDUSetRequest:
		return "SetRequest"
	case PDUTrap:
		return "Trap"
	case PDUGetBulk:
		return "GetBulk"
	case PDUInform:
		return "Inform"
	case PDUTrapV2:
		return "TrapV2"
	case PDUReport:
		return "Report"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", pduType)
	}
}

// NewVarBind creates a VarBind with a null value.
func NewVarBind(oid string) VarBind {
	return VarBind{OID: oid, Value: BEREncodeNull()}
}

// NewVarBindInteger creates a VarBind with an integer value.
func NewVarBindInteger(oid string, val int) VarBind {
	return VarBind{OID: oid, Value: BEREncodeInteger(val)}
}

// NewVarBindString creates a VarBind with a string value.
func NewVarBindString(oid string, val string) VarBind {
	return VarBind{OID: oid, Value: BEREncodeOctetString([]byte(val))}
}

// NewVarBindOID creates a VarBind with an OID value.
func NewVarBindOID(oid, val string) VarBind {
	return VarBind{OID: oid, Value: BEREncodeOID(val)}
}

// NewVarBindIP creates a VarBind with an IP address value.
func NewVarBindIP(oid string, ip net.IP) VarBind {
	return VarBind{OID: oid, Value: BEREncodeIP(ip)}
}

// NewVarBindCounter32 creates a VarBind with a Counter32 value.
func NewVarBindCounter32(oid string, val uint32) VarBind {
	return VarBind{OID: oid, Value: BEREncodeCounter32(val)}
}

// NewVarBindTimeTicks creates a VarBind with a TimeTicks value.
func NewVarBindTimeTicks(oid string, val uint32) VarBind {
	return VarBind{OID: oid, Value: BEREncodeTimeTicks(val)}
}

// VarBindValueAsInt tries to decode a VarBind value as an integer.
func VarBindValueAsInt(vb VarBind) (int, bool) {
	if len(vb.Value) == 0 {
		return 0, false
	}
	tag := vb.Value[0]
	if tag == TagNull || tag == TagNoSuchObject || tag == TagNoSuchInstance || tag == TagEndOfMibView {
		return 0, false
	}
	_, val, _, err := BERDecodeTLV(vb.Value)
	if err != nil {
		return 0, false
	}
	n, err := BERDecodeInteger(val)
	return n, err == nil
}

// VarBindValueAsString tries to decode a VarBind value as a string.
func VarBindValueAsString(vb VarBind) (string, bool) {
	if len(vb.Value) == 0 || vb.Value[0] != TagOctetString {
		return "", false
	}
	_, val, _, err := BERDecodeTLV(vb.Value)
	if err != nil {
		return "", false
	}
	return string(val), true
}
