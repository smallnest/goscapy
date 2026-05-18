package packet

import (
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
		0x42,                         // byte
		0x12, 0x34,                   // short
		0x00, 0x00, 0x03, 0xe8,       // int (1000)
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
		0x42,        // byte field
		0xFF, 0xFF,  // extra bytes
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

func TestParseFieldsConditional(t *testing.T) {
	inner := fields.NewByteField("opt", 0)
	cond := func(vals map[string]interface{}) bool {
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
