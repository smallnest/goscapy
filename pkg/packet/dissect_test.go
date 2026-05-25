package packet

import (
	"fmt"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
)

func TestParseFieldsEthernet(t *testing.T) {
	// Ethernet frame: dst=ff:ff:ff:ff:ff:ff, src=00:11:22:33:44:55, type=0x0800
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
	}

	l := NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", nil),
		fields.NewMACField("src", nil),
		fields.NewShortField("type", 0),
	})

	consumed, err := l.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 14 {
		t.Fatalf("consumed = %d, want 14", consumed)
	}

	dst, _ := l.Get("dst")
	mac := dst.(net.HardwareAddr)
	if mac.String() != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("dst = %v, want ff:ff:ff:ff:ff:ff", mac)
	}

	src, _ := l.Get("src")
	mac = src.(net.HardwareAddr)
	if mac.String() != "00:11:22:33:44:55" {
		t.Errorf("src = %v, want 00:11:22:33:44:55", mac)
	}

	etype, _ := l.Get("type")
	if etype.(uint16) != 0x0800 {
		t.Errorf("type = %#x, want 0x0800", etype)
	}
}

func TestParseFieldsEmptyInput(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("a", 0),
	})

	consumed, err := l.ParseFields([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 0 {
		t.Errorf("consumed = %d, want 0 for empty input", consumed)
	}
}

func TestParseFieldsInsufficientData(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewShortField("a", 0), // needs 2 bytes
	})

	_, err := l.ParseFields([]byte{0x01}) // only 1 byte
	if err == nil {
		t.Fatal("expected error for insufficient data")
	}
}

func TestParseFieldsMultipleFields(t *testing.T) {
	// Byte + Short + Int + MAC + IP = 1 + 2 + 4 + 6 + 4 = 17 bytes
	raw := []byte{
		0x42,       // byte
		0x12, 0x34, // short
		0x00, 0x00, 0x03, 0xe8, // int (1000)
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC
		0xc0, 0xa8, 0x01, 0x01, // IP (192.168.1.1)
	}

	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("a", 0),
		fields.NewShortField("b", 0),
		fields.NewIntField("c", 0),
		fields.NewMACField("d", nil),
		fields.NewIPField("e", nil),
	})

	consumed, err := l.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 17 {
		t.Fatalf("consumed = %d, want 17", consumed)
	}

	a, _ := l.Get("a")
	if a.(uint8) != 0x42 {
		t.Errorf("a = %#x, want 0x42", a)
	}

	b, _ := l.Get("b")
	if b.(uint16) != 0x1234 {
		t.Errorf("b = %#x, want 0x1234", b)
	}

	c, _ := l.Get("c")
	if c.(uint32) != 1000 {
		t.Errorf("c = %d, want 1000", c)
	}

	d, _ := l.Get("d")
	mac := d.(net.HardwareAddr)
	if mac.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("d = %v, want aa:bb:cc:dd:ee:ff", mac)
	}

	e, _ := l.Get("e")
	ip := e.(net.IP)
	if !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("e = %v, want 192.168.1.1", ip)
	}
}

func TestParseFieldsExtraData(t *testing.T) {
	// Parse should consume only the defined fields, leaving extra bytes.
	raw := []byte{
		0x42,       // byte field
		0xFF, 0xFF, // extra bytes
	}

	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("a", 0),
	})

	consumed, err := l.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 1 {
		t.Errorf("consumed = %d, want 1", consumed)
	}
}

func TestRegisterHeuristic(t *testing.T) {
	// Register a heuristic for a test protocol.
	RegisterHeuristic("TestLower", "type", uint16(0x9999), "TestUpper")

	// Verify key field was registered.
	if dissectRegistry.keyField["TestLower"] != "type" {
		t.Errorf("keyField not registered: got %q", dissectRegistry.keyField["TestLower"])
	}

	// Verify next layer mapping.
	next, ok := dissectRegistry.nextLayer["TestLower"][0x9999]
	if !ok || next != "TestUpper" {
		t.Errorf("nextLayer mapping: ok=%v, next=%q, want ok=true, next=TestUpper", ok, next)
	}

	// Clean up.
	delete(dissectRegistry.keyField, "TestLower")
	delete(dissectRegistry.nextLayer, "TestLower")
}

func TestRegisterHeuristicMultipleValues(t *testing.T) {
	RegisterHeuristic("MultiProto", "port", uint16(80), "HTTP")
	RegisterHeuristic("MultiProto", "port", uint16(443), "HTTPS")

	if dissectRegistry.nextLayer["MultiProto"][80] != "HTTP" {
		t.Error("nextLayer[80] != HTTP")
	}
	if dissectRegistry.nextLayer["MultiProto"][443] != "HTTPS" {
		t.Error("nextLayer[443] != HTTPS")
	}

	delete(dissectRegistry.keyField, "MultiProto")
	delete(dissectRegistry.nextLayer, "MultiProto")
}

func TestRegisterTunnelPayload(t *testing.T) {
	RegisterTunnelPayload("TunnelProto", "InnerProto")

	inner, ok := dissectRegistry.tunnelPayload["TunnelProto"]
	if !ok || inner != "InnerProto" {
		t.Errorf("tunnelPayload: ok=%v, inner=%q", ok, inner)
	}

	delete(dissectRegistry.tunnelPayload, "TunnelProto")
}

func TestRegisterDissector(t *testing.T) {
	called := false
	fn := func(data []byte) (string, int, error) {
		called = true
		return "TestProto", 0, nil
	}
	RegisterDissector("TestProto", fn)

	d, ok := dissectRegistry.dissectors["TestProto"]
	if !ok {
		t.Errorf("%s.dissectors[%q]: expected true", "dissectRegistry", "TestProto")
	}
	proto, skip, err := d([]byte{1, 2, 3})
	if err != nil || proto != "TestProto" || skip != 0 {
		t.Errorf("dissector: proto=%q, skip=%d, err=%v", proto, skip, err)
	}
	if !called {
		t.Error("DissectorFunc: not called")
	}

	delete(dissectRegistry.dissectors, "TestProto")
}

func TestDissectByProto(t *testing.T) {
	// Register a simple layer and its dissector.
	RegisterLayer("StartLayer", func() *Layer {
		return NewLayer("StartLayer", []fields.Field{
			fields.NewByteField("x", 0),
		})
	})
	RegisterDissector("StartLayer", func(data []byte) (string, int, error) {
		if len(data) < 1 {
			return "", 0, fmt.Errorf("too short")
		}
		return "StartLayer", 0, nil
	})

	raw := []byte{0x42, 0xFF, 0xFF} // 1 byte for StartLayer + 2 extra → Raw
	pkt, err := DissectByProto(raw, "StartLayer")
	if err != nil {
		t.Fatal(err)
	}

	if pkt.Len() != 2 {
		t.Fatalf("got %d layers, want 2 (StartLayer + Raw)", pkt.Len())
	}
	if !pkt.HasLayer("StartLayer") {
		t.Error("missing StartLayer")
	}
	if !pkt.HasLayer("Raw") {
		t.Error("missing Raw layer for extra bytes")
	}

	// Clean up.
	delete(dissectRegistry.factories, "StartLayer")
	delete(dissectRegistry.dissectors, "StartLayer")
}

func TestDissectByProtoUnknownProtocol(t *testing.T) {
	_, err := DissectByProto([]byte{1}, "NoSuchProto")
	if err == nil {
		t.Fatal("expected error for unknown protocol")
	}
}

func TestDissectByProtoEmptyInput(t *testing.T) {
	_, err := DissectByProto([]byte{}, "Ethernet")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestMaxTunnelDepth(t *testing.T) {
	// Register two layers that reference each other in a tunnel loop.
	RegisterLayer("LoopA", func() *Layer {
		return NewLayer("LoopA", []fields.Field{
			fields.NewByteField("x", 0),
		})
	})
	RegisterLayer("LoopB", func() *Layer {
		return NewLayer("LoopB", []fields.Field{
			fields.NewByteField("y", 0),
		})
	})
	RegisterTunnelPayload("LoopA", "LoopB")
	RegisterTunnelPayload("LoopB", "LoopA")

	RegisterDissector("LoopA", func(data []byte) (string, int, error) {
		return "LoopA", 0, nil
	})

	// This should fail with max tunnel depth exceeded.
	_, err := DissectByProto([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "LoopA")
	if err == nil {
		t.Fatal("expected error for max tunnel depth exceeded")
	}

	// Clean up.
	delete(dissectRegistry.factories, "LoopA")
	delete(dissectRegistry.factories, "LoopB")
	delete(dissectRegistry.tunnelPayload, "LoopA")
	delete(dissectRegistry.tunnelPayload, "LoopB")
	delete(dissectRegistry.dissectors, "LoopA")
}

func TestToUint64(t *testing.T) {
	tests := []struct {
		input any
		want  uint64
	}{
		{uint8(42), 42},
		{uint16(1000), 1000},
		{uint32(100000), 100000},
		{uint64(9999999999), 9999999999},
		{int(7), 7},
		{int32(-1), 18446744073709551615},
	}

	for _, tt := range tests {
		got := toUint64(tt.input)
		if got != tt.want {
			t.Errorf("toUint64(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}

	// Non-integer types should return 0.
	if got := toUint64("hello"); got != 0 {
		t.Errorf("toUint64(string) = %d, want 0", got)
	}
	if got := toUint64(nil); got != 0 {
		t.Errorf("toUint64(nil) = %d, want 0", got)
	}
}

func TestParseFieldsConditional(t *testing.T) {
	inner := fields.NewByteField("opt", 0)
	cond := func(vals map[string]any) bool {
		return vals["hasOpt"] == uint8(1)
	}
	cf := fields.NewConditionalField(inner, cond)

	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("hasOpt", 0),
		cf,
	})

	// With hasOpt=1, should parse both fields.
	raw := []byte{0x01, 0x42}
	consumed, err := l.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 2 {
		t.Fatalf("consumed = %d, want 2 (with conditional active)", consumed)
	}

	opt, err := l.Get("opt")
	if err != nil {
		t.Fatal(err)
	}
	if opt.(uint8) != 0x42 {
		t.Errorf("opt = %#x, want 0x42", opt)
	}

	// With hasOpt=0, should skip the conditional field.
	l2 := NewLayer("Test", []fields.Field{
		fields.NewByteField("hasOpt", 0),
		cf,
	})
	raw2 := []byte{0x00}
	consumed2, err := l2.ParseFields(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if consumed2 != 1 {
		t.Errorf("consumed = %d, want 1 (with conditional inactive)", consumed2)
	}
}
