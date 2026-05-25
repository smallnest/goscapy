package snmp

import (
	"net"
	"testing"
)

func TestBERLength(t *testing.T) {
	tests := []struct {
		length int
		want   []byte
	}{
		{0, []byte{0x00}},
		{5, []byte{0x05}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{256, []byte{0x82, 0x01, 0x00}},
	}
	for _, tt := range tests {
		got := BERLength(tt.length)
		if !equalBytes(got, tt.want) {
			t.Errorf("BERLength(%d) = %v, want %v", tt.length, got, tt.want)
		}
	}
}

func TestBERDecodeLength(t *testing.T) {
	tests := []struct {
		data     []byte
		wantLen  int
		wantCons int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0x81, 0x80}, 128, 2},
		{[]byte{0x82, 0x01, 0x00}, 256, 3},
	}
	for _, tt := range tests {
		l, c, err := BERDecodeLength(tt.data)
		if err != nil {
			t.Fatalf("BERDecodeLength(%v): %v", tt.data, err)
		}
		if l != tt.wantLen || c != tt.wantCons {
			t.Errorf("got (%d, %d), want (%d, %d)", l, c, tt.wantLen, tt.wantCons)
		}
	}
}

func TestBERInteger(t *testing.T) {
	tests := []int{0, 1, 127, 128, -1, -128, 256, 65535}
	for _, val := range tests {
		encoded := BEREncodeInteger(val)
		tag, data, _, err := BERDecodeTLV(encoded)
		if err != nil {
			t.Fatalf("decode %d: %v", val, err)
		}
		if tag != TagInteger {
			t.Errorf("tag = 0x%02x", tag)
		}
		decoded, err := BERDecodeInteger(data)
		if err != nil {
			t.Fatalf("parse %d: %v", val, err)
		}
		if decoded != val {
			t.Errorf("round-trip: got %d, want %d", decoded, val)
		}
	}
}

func TestBEROctetString(t *testing.T) {
	val := []byte("hello")
	encoded := BEREncodeOctetString(val)
	tag, data, _, err := BERDecodeTLV(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagOctetString || string(data) != "hello" {
		t.Errorf("got tag=0x%02x data=%q", tag, data)
	}
}

func TestBEROID(t *testing.T) {
	tests := []string{
		".1.3.6.1.2.1.1.1.0",  // sysDescr
		".1.3.6.1.2.1.1.3.0",  // sysUpTime
		".1.3.6.1.2.1.1.5.0",  // sysName
		".1.3.6.1.6.3.1.1.4.1.0", // snmpTrapOID
	}
	for _, oid := range tests {
		encoded := BEREncodeOID(oid)
		tag, data, _, err := BERDecodeTLV(encoded)
		if err != nil {
			t.Fatalf("decode %s: %v", oid, err)
		}
		if tag != TagOID {
			t.Errorf("tag = 0x%02x", tag)
		}
		decoded := BERDecodeOID(data)
		if decoded != oid {
			t.Errorf("round-trip: got %q, want %q", decoded, oid)
		}
	}
}

func TestSNMPGetRequest(t *testing.T) {
	msg := &SNMPMessage{
		Version:   Version2c,
		Community: "public",
		PDUType:   PDUGetRequest,
		RequestID: 1,
		VarBinds: []VarBind{
			NewVarBind(".1.3.6.1.2.1.1.1.0"),
		},
	}

	raw := BuildSNMP(msg)
	parsed, err := ParseSNMP(raw)
	if err != nil {
		t.Fatalf("ParseSNMP: %v", err)
	}

	if parsed.Version != Version2c {
		t.Errorf("version = %d, want %d", parsed.Version, Version2c)
	}
	if parsed.Community != "public" {
		t.Errorf("community = %q", parsed.Community)
	}
	if parsed.PDUType != PDUGetRequest {
		t.Errorf("PDU type = 0x%02x", parsed.PDUType)
	}
	if parsed.RequestID != 1 {
		t.Errorf("request ID = %d", parsed.RequestID)
	}
	if len(parsed.VarBinds) != 1 {
		t.Fatalf("varbinds = %d, want 1", len(parsed.VarBinds))
	}
	if parsed.VarBinds[0].OID != ".1.3.6.1.2.1.1.1.0" {
		t.Errorf("OID = %q", parsed.VarBinds[0].OID)
	}
}

func TestSNMPGetResponse(t *testing.T) {
	msg := &SNMPMessage{
		Version:     Version2c,
		Community:   "public",
		PDUType:     PDUGetResponse,
		RequestID:   42,
		ErrorStatus: 0,
		ErrorIndex:  0,
		VarBinds: []VarBind{
			NewVarBindString(".1.3.6.1.2.1.1.1.0", "Linux test 5.4.0"),
			NewVarBindTimeTicks(".1.3.6.1.2.1.1.3.0", 123456),
		},
	}

	raw := BuildSNMP(msg)
	parsed, err := ParseSNMP(raw)
	if err != nil {
		t.Fatalf("ParseSNMP: %v", err)
	}

	if parsed.RequestID != 42 {
		t.Errorf("request ID = %d", parsed.RequestID)
	}
	if len(parsed.VarBinds) != 2 {
		t.Fatalf("varbinds = %d", len(parsed.VarBinds))
	}

	desc, ok := VarBindValueAsString(parsed.VarBinds[0])
	if !ok || desc != "Linux test 5.4.0" {
		t.Errorf("sysDescr = %q, ok=%v", desc, ok)
	}

	uptime, ok := VarBindValueAsInt(parsed.VarBinds[1])
	if !ok || uptime != 123456 {
		t.Errorf("sysUpTime = %d, ok=%v", uptime, ok)
	}
}

func TestSNMPSetRequest(t *testing.T) {
	msg := &SNMPMessage{
		Version:   Version1,
		Community: "private",
		PDUType:   PDUSetRequest,
		RequestID: 7,
		VarBinds: []VarBind{
			NewVarBindString(".1.3.6.1.2.1.1.4.0", "admin@test.com"),
		},
	}

	raw := BuildSNMP(msg)
	parsed, err := ParseSNMP(raw)
	if err != nil {
		t.Fatalf("ParseSNMP: %v", err)
	}

	if parsed.Community != "private" {
		t.Errorf("community = %q", parsed.Community)
	}
	if parsed.PDUType != PDUSetRequest {
		t.Errorf("PDU = 0x%02x", parsed.PDUType)
	}
}

func TestSNMPTrap(t *testing.T) {
	msg := &SNMPMessage{
		Version:      Version1,
		Community:    "public",
		PDUType:      PDUTrap,
		Enterprise:   ".1.3.6.1.4.1.311",
		AgentAddr:    net.ParseIP("192.168.1.1"),
		GenericTrap:  6, // enterpriseSpecific
		SpecificTrap: 1,
		Timestamp:    5000,
		VarBinds: []VarBind{
			NewVarBindString(".1.3.6.1.4.1.311.1.1", "linkDown"),
		},
	}

	raw := BuildSNMP(msg)
	parsed, err := ParseSNMP(raw)
	if err != nil {
		t.Fatalf("ParseSNMP: %v", err)
	}

	if parsed.PDUType != PDUTrap {
		t.Errorf("PDU = 0x%02x", parsed.PDUType)
	}
	if parsed.Enterprise != ".1.3.6.1.4.1.311" {
		t.Errorf("enterprise = %q", parsed.Enterprise)
	}
	if !parsed.AgentAddr.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("agent = %v", parsed.AgentAddr)
	}
	if parsed.GenericTrap != 6 {
		t.Errorf("genericTrap = %d", parsed.GenericTrap)
	}
	if parsed.SpecificTrap != 1 {
		t.Errorf("specificTrap = %d", parsed.SpecificTrap)
	}
	if parsed.Timestamp != 5000 {
		t.Errorf("timestamp = %d", parsed.Timestamp)
	}
}

func TestSNMPGetBulk(t *testing.T) {
	msg := &SNMPMessage{
		Version:   Version2c,
		Community: "public",
		PDUType:   PDUGetBulk,
		RequestID: 100,
		// ErrorStatus = non-repeaters, ErrorIndex = max-repetitions
		ErrorStatus: 0,
		ErrorIndex:  10,
		VarBinds: []VarBind{
			NewVarBind(".1.3.6.1.2.1.2.2.1.2"),
		},
	}

	raw := BuildSNMP(msg)
	parsed, err := ParseSNMP(raw)
	if err != nil {
		t.Fatalf("ParseSNMP: %v", err)
	}
	if parsed.PDUType != PDUGetBulk {
		t.Errorf("PDU = 0x%02x", parsed.PDUType)
	}
	if parsed.ErrorIndex != 10 {
		t.Errorf("max-repetitions = %d", parsed.ErrorIndex)
	}
}

func TestSNMPInform(t *testing.T) {
	msg := &SNMPMessage{
		Version:   Version2c,
		Community: "public",
		PDUType:   PDUInform,
		RequestID: 55,
		VarBinds: []VarBind{
			NewVarBindOID(".1.3.6.1.6.3.1.1.4.1.0", ".1.3.6.1.4.1.311.0.1"),
		},
	}

	raw := BuildSNMP(msg)
	parsed, err := ParseSNMP(raw)
	if err != nil {
		t.Fatalf("ParseSNMP: %v", err)
	}
	if parsed.PDUType != PDUInform {
		t.Errorf("PDU = 0x%02x", parsed.PDUType)
	}
}

func TestPDUTypeName(t *testing.T) {
	if PDUTypeName(PDUGetRequest) != "GetRequest" {
		t.Errorf("wrong name")
	}
	if PDUTypeName(0xff) != "Unknown(0xff)" {
		t.Errorf("wrong unknown name")
	}
}

func TestBERNull(t *testing.T) {
	null := BEREncodeNull()
	if len(null) != 2 || null[0] != TagNull || null[1] != 0 {
		t.Errorf("null = %v", null)
	}
}

func TestBERIP(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	encoded := BEREncodeIP(ip)
	tag, val, _, err := BERDecodeTLV(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagIPAddress {
		t.Errorf("tag = 0x%02x", tag)
	}
	parsed := BERDecodeIP(val)
	if !parsed.Equal(ip) {
		t.Errorf("IP = %v, want %v", parsed, ip)
	}
}

func TestBERCounter32(t *testing.T) {
	encoded := BEREncodeCounter32(12345)
	tag, val, _, err := BERDecodeTLV(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagCounter32 {
		t.Errorf("tag = 0x%02x", tag)
	}
	n, err := BERDecodeInteger(val)
	if err != nil || n != 12345 {
		t.Errorf("value = %d, err = %v", n, err)
	}
}

func TestVarBindHelpers(t *testing.T) {
	vb := NewVarBindInteger(".1.3.6.1.2.1.1.3.0", 999)
	n, ok := VarBindValueAsInt(vb)
	if !ok || n != 999 {
		t.Errorf("int varbind: %d, ok=%v", n, ok)
	}

	vb2 := NewVarBindString(".1.3.6.1.2.1.1.1.0", "test")
	s, ok := VarBindValueAsString(vb2)
	if !ok || s != "test" {
		t.Errorf("string varbind: %q, ok=%v", s, ok)
	}

	vb3 := NewVarBind(".1.3.6.1.2.1.1.1.0")
	_, ok = VarBindValueAsInt(vb3)
	if ok {
		t.Error("null varbind should not return int")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
