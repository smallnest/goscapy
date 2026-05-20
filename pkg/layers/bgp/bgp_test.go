package bgp

import (
	"testing"
)

func TestNewBGPLayer(t *testing.T) {
	layer := NewBGP()
	if layer.Proto() != "BGP" {
		t.Errorf("Proto = %q, want %q", layer.Proto(), "BGP")
	}

	typ, _ := layer.Get("type")
	if typ != uint8(TypeOpen) {
		t.Errorf("type = %v, want %d", typ, TypeOpen)
	}
}

func TestBGPOpenLayer(t *testing.T) {
	layer := NewBGPOpen()
	if layer.Proto() != "BGP Open" {
		t.Errorf("Proto = %q, want %q", layer.Proto(), "BGP Open")
	}

	ver, _ := layer.Get("version")
	if ver != uint8(4) {
		t.Errorf("version = %v, want 4", ver)
	}
}

func TestBGPKeepaliveLayer(t *testing.T) {
	layer := NewBGPKeepalive()
	if layer.Proto() != "BGP Keepalive" {
		t.Errorf("Proto = %q, want %q", layer.Proto(), "BGP Keepalive")
	}
}

func TestBGPNotificationLayer(t *testing.T) {
	layer := NewBGPNotification()
	code, _ := layer.Get("error_code")
	if code != uint8(0) {
		t.Errorf("error_code = %v, want 0", code)
	}
}

func TestPathAttrRoundTrip(t *testing.T) {
	attr := PathAttr{
		Flags:    FlagTransitive,
		TypeCode: AttrOrigin,
		Value:    []byte{OriginIGP},
	}

	data := attr.Serialize()

	// Should be: flags(1) + type(1) + length(1) + value(1) = 4 bytes
	if len(data) != 4 {
		t.Fatalf("Serialize len = %d, want 4", len(data))
	}

	parsed, consumed, err := ParsePathAttr(data)
	if err != nil {
		t.Fatalf("ParsePathAttr failed: %v", err)
	}

	if consumed != 4 {
		t.Errorf("consumed = %d, want 4", consumed)
	}
	if parsed.Flags != attr.Flags {
		t.Errorf("Flags = 0x%02x, want 0x%02x", parsed.Flags, attr.Flags)
	}
	if parsed.TypeCode != attr.TypeCode {
		t.Errorf("TypeCode = %d, want %d", parsed.TypeCode, attr.TypeCode)
	}
	if len(parsed.Value) != 1 || parsed.Value[0] != OriginIGP {
		t.Errorf("Value = %v, want [0]", parsed.Value)
	}
}

func TestPathAttrExtendedLength(t *testing.T) {
	// Create a large value to trigger extended length
	largeValue := make([]byte, 256)
	for i := range largeValue {
		largeValue[i] = byte(i)
	}

	attr := PathAttr{
		Flags:    FlagOptional | FlagTransitive | FlagExtLength,
		TypeCode: AttrCommunity,
		Value:    largeValue,
	}

	data := attr.Serialize()

	parsed, consumed, err := ParsePathAttr(data)
	if err != nil {
		t.Fatalf("ParsePathAttr failed: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("consumed = %d, want %d", consumed, len(data))
	}
	if len(parsed.Value) != len(largeValue) {
		t.Errorf("Value len = %d, want %d", len(parsed.Value), len(largeValue))
	}
}

func TestParseMultiplePathAttrs(t *testing.T) {
	attrs := []PathAttr{
		{Flags: FlagTransitive, TypeCode: AttrOrigin, Value: []byte{OriginIGP}},
		{Flags: FlagTransitive, TypeCode: AttrNextHop, Value: []byte{192, 168, 1, 1}},
	}

	data := SerializePathAttrs(attrs)

	parsed, err := ParsePathAttrs(data)
	if err != nil {
		t.Fatalf("ParsePathAttrs failed: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("parsed count = %d, want 2", len(parsed))
	}

	if parsed[0].TypeCode != AttrOrigin {
		t.Errorf("parsed[0] TypeCode = %d, want %d", parsed[0].TypeCode, AttrOrigin)
	}
	if parsed[1].TypeCode != AttrNextHop {
		t.Errorf("parsed[1] TypeCode = %d, want %d", parsed[1].TypeCode, AttrNextHop)
	}
}

func TestNLRIPrefixRoundTrip(t *testing.T) {
	prefix := &NLRIPrefix{
		PrefixLen: 24,
		Prefix:    []byte{192, 168, 1},
	}

	data := prefix.Serialize()
	if len(data) != 4 {
		t.Fatalf("Serialize len = %d, want 4", len(data))
	}

	parsed, consumed, err := ParseNLRIPrefix(data)
	if err != nil {
		t.Fatalf("ParseNLRIPrefix failed: %v", err)
	}

	if consumed != 4 {
		t.Errorf("consumed = %d, want 4", consumed)
	}
	if parsed.PrefixLen != 24 {
		t.Errorf("PrefixLen = %d, want 24", parsed.PrefixLen)
	}
}

func TestBuildOpenOptParams(t *testing.T) {
	caps := []BGPCapability{
		{Code: 1, Data: []byte{0x00, 0x01, 0x00, 0x01}}, // MP_BGP: IPv4 unicast
		{Code: 65, Data: []byte{0x00, 0x00, 0x00, 0x64}}, // 4-byte ASN: 100
	}

	params := BuildOpenOptParams(caps)

	// param_type(1) + param_length(1) + capabilities
	// Each cap: code(1) + len(1) + data(4) = 6 bytes, 2 caps = 12 bytes
	// Total: 1 + 1 + 12 = 14 bytes
	if len(params) != 14 {
		t.Errorf("params len = %d, want 14", len(params))
	}

	if params[0] != 2 {
		t.Errorf("param_type = %d, want 2 (Capabilities)", params[0])
	}
}

func TestParsePathAttrTruncated(t *testing.T) {
	_, _, err := ParsePathAttr([]byte{0x40, 0x01})
	if err == nil {
		t.Error("expected error for truncated path attribute")
	}
}
