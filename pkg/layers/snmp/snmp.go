package snmp

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/asn1"
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
	Version1  int = 0
	Version2c int = 1
	Version3  int = 3
)

// ---- SNMP Types ----

// VarBind represents an SNMP variable binding.
type VarBind struct {
	OID   string
	Value []byte // Raw BER-encoded value
}

// SNMPMessage represents a parsed SNMP message.
type SNMPMessage struct {
	Version     int
	Community   string
	PDUType     byte
	RequestID   int
	ErrorStatus int
	ErrorIndex  int
	VarBinds    []VarBind
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
	version := asn1.BEREncodeInteger(msg.Version)
	community := asn1.BEREncodeOctetString([]byte(msg.Community))

	var pdu []byte
	if msg.PDUType == PDUTrap {
		pdu = buildTrapPDU(msg)
	} else {
		pdu = buildPDUNormal(msg)
	}

	inner := append(version, community...)
	inner = append(inner, pdu...)

	return asn1.BERTLV(asn1.TagSequence, inner)
}

func buildPDUNormal(msg *SNMPMessage) []byte {
	reqID := asn1.BEREncodeInteger(msg.RequestID)
	errStatus := asn1.BEREncodeInteger(msg.ErrorStatus)
	errIndex := asn1.BEREncodeInteger(msg.ErrorIndex)
	varBinds := buildVarBinds(msg.VarBinds)

	inner := append(reqID, errStatus...)
	inner = append(inner, errIndex...)
	inner = append(inner, varBinds...)

	return asn1.BERTLV(msg.PDUType, inner)
}

func buildTrapPDU(msg *SNMPMessage) []byte {
	enterprise := asn1.BEREncodeOID(msg.Enterprise)
	agentAddr := asn1.BEREncodeIP(msg.AgentAddr)
	genericTrap := asn1.BEREncodeInteger(msg.GenericTrap)
	specificTrap := asn1.BEREncodeInteger(msg.SpecificTrap)
	timestamp := asn1.BEREncodeTimeTicks(msg.Timestamp)
	varBinds := buildVarBinds(msg.VarBinds)

	inner := append(enterprise, agentAddr...)
	inner = append(inner, genericTrap...)
	inner = append(inner, specificTrap...)
	inner = append(inner, timestamp...)
	inner = append(inner, varBinds...)

	return asn1.BERTLV(PDUTrap, inner)
}

func buildVarBinds(vbs []VarBind) []byte {
	var inner []byte
	for _, vb := range vbs {
		oid := asn1.BEREncodeOID(vb.OID)
		val := vb.Value
		if val == nil {
			val = asn1.BEREncodeNull()
		}
		vbInner := append(oid, val...)
		inner = append(inner, asn1.BERTLV(asn1.TagSequence, vbInner)...)
	}
	return asn1.BERTLV(asn1.TagSequence, inner)
}

// ---- SNMP Parse ----

// ParseSNMP parses a raw SNMP message.
func ParseSNMP(data []byte) (*SNMPMessage, error) {
	tag, value, consumed, err := asn1.BERDecodeTLV(data)
	if err != nil {
		return nil, fmt.Errorf("snmp: parse outer: %w", err)
	}
	if tag != asn1.TagSequence {
		return nil, fmt.Errorf("snmp: expected SEQUENCE, got 0x%02x", tag)
	}
	_ = consumed

	pos := 0

	// Version.
	vTag, vVal, vConsumed, err := asn1.BERDecodeTLV(value[pos:])
	if err != nil {
		return nil, fmt.Errorf("snmp: parse version: %w", err)
	}
	if vTag != asn1.TagInteger {
		return nil, fmt.Errorf("snmp: version tag = 0x%02x", vTag)
	}
	version, _ := asn1.BERDecodeInteger(vVal)
	pos += vConsumed

	// Community.
	cTag, cVal, cConsumed, err := asn1.BERDecodeTLV(value[pos:])
	if err != nil {
		return nil, fmt.Errorf("snmp: parse community: %w", err)
	}
	if cTag != asn1.TagOctetString {
		return nil, fmt.Errorf("snmp: community tag = 0x%02x", cTag)
	}
	community := string(cVal)
	pos += cConsumed

	msg := &SNMPMessage{
		Version:   version,
		Community: community,
	}

	// PDU.
	pduTag, pduVal, _, err := asn1.BERDecodeTLV(value[pos:])
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
	_, val, consumed, err := asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.RequestID, _ = asn1.BERDecodeInteger(val)
	pos += consumed

	// Error status.
	_, val, consumed, err = asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.ErrorStatus, _ = asn1.BERDecodeInteger(val)
	pos += consumed

	// Error index.
	_, val, consumed, err = asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.ErrorIndex, _ = asn1.BERDecodeInteger(val)
	pos += consumed

	// VarBinds.
	var tag byte
	tag, val, _, err = asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	if tag == asn1.TagSequence {
		msg.VarBinds, err = parseVarBinds(val)
	}

	return err
}

func parseTrapPDU(data []byte, msg *SNMPMessage) error {
	pos := 0

	// Enterprise OID.
	_, val, consumed, err := asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.Enterprise = asn1.BERDecodeOID(val)
	pos += consumed

	// Agent address.
	_, val, consumed, err = asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.AgentAddr = asn1.BERDecodeIP(val)
	pos += consumed

	// Generic trap.
	_, val, consumed, err = asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.GenericTrap, _ = asn1.BERDecodeInteger(val)
	pos += consumed

	// Specific trap.
	_, val, consumed, err = asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	msg.SpecificTrap, _ = asn1.BERDecodeInteger(val)
	pos += consumed

	// Timestamp.
	_, val, consumed, err = asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return err
	}
	ts, _ := asn1.BERDecodeInteger(val)
	msg.Timestamp = uint32(ts)
	pos += consumed

	// VarBinds.
	_, val, _, err = asn1.BERDecodeTLV(data[pos:])
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
		tag, val, consumed, err := asn1.BERDecodeTLV(data[pos:])
		if err != nil {
			break
		}
		if tag != asn1.TagSequence {
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
	_, val, consumed, err := asn1.BERDecodeTLV(data[pos:])
	if err != nil {
		return VarBind{}, err
	}
	oid := asn1.BERDecodeOID(val)
	pos += consumed

	// Value — store raw bytes (tag + length + value).
	if pos >= len(data) {
		return VarBind{OID: oid, Value: asn1.BEREncodeNull()}, nil
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
	return VarBind{OID: oid, Value: asn1.BEREncodeNull()}
}

// NewVarBindInteger creates a VarBind with an integer value.
func NewVarBindInteger(oid string, val int) VarBind {
	return VarBind{OID: oid, Value: asn1.BEREncodeInteger(val)}
}

// NewVarBindString creates a VarBind with a string value.
func NewVarBindString(oid string, val string) VarBind {
	return VarBind{OID: oid, Value: asn1.BEREncodeOctetString([]byte(val))}
}

// NewVarBindOID creates a VarBind with an OID value.
func NewVarBindOID(oid, val string) VarBind {
	return VarBind{OID: oid, Value: asn1.BEREncodeOID(val)}
}

// NewVarBindIP creates a VarBind with an IP address value.
func NewVarBindIP(oid string, ip net.IP) VarBind {
	return VarBind{OID: oid, Value: asn1.BEREncodeIP(ip)}
}

// NewVarBindCounter32 creates a VarBind with a Counter32 value.
func NewVarBindCounter32(oid string, val uint32) VarBind {
	return VarBind{OID: oid, Value: asn1.BEREncodeCounter32(val)}
}

// NewVarBindTimeTicks creates a VarBind with a TimeTicks value.
func NewVarBindTimeTicks(oid string, val uint32) VarBind {
	return VarBind{OID: oid, Value: asn1.BEREncodeTimeTicks(val)}
}

// VarBindValueAsInt tries to decode a VarBind value as an integer.
func VarBindValueAsInt(vb VarBind) (int, bool) {
	if len(vb.Value) == 0 {
		return 0, false
	}
	tag := vb.Value[0]
	if tag == asn1.TagNull || tag == asn1.TagNoSuchObject || tag == asn1.TagNoSuchInstance || tag == asn1.TagEndOfMibView {
		return 0, false
	}
	_, val, _, err := asn1.BERDecodeTLV(vb.Value)
	if err != nil {
		return 0, false
	}
	n, err := asn1.BERDecodeInteger(val)
	return n, err == nil
}

// VarBindValueAsString tries to decode a VarBind value as a string.
func VarBindValueAsString(vb VarBind) (string, bool) {
	if len(vb.Value) == 0 || vb.Value[0] != asn1.TagOctetString {
		return "", false
	}
	_, val, _, err := asn1.BERDecodeTLV(vb.Value)
	if err != nil {
		return "", false
	}
	return string(val), true
}
