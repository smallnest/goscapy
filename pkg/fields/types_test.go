package fields

import (
	"encoding/binary"
	"net"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func TestByteField(t *testing.T) {
	f := NewByteField("test", 0x42)

	// default
	if f.DefaultVal() != uint8(0x42) {
		t.Errorf("default = %v, want 0x42", f.DefaultVal())
	}
	if f.FixedSize() != 1 {
		t.Errorf("size = %d, want 1", f.FixedSize())
	}

	// pack
	b, err := f.Pack(uint8(0xFF))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1 || b[0] != 0xFF {
		t.Errorf("pack = %x, want ff", b)
	}

	// unpack
	val, n, err := f.Unpack([]byte{0xAB})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint8) != 0xAB || n != 1 {
		t.Errorf("unpack = %x, %d, want ab, 1", val, n)
	}

	// unpack fail
	_, _, err = f.Unpack([]byte{})
	if err == nil {
		t.Fatal("expected error for empty buffer")
	}

	// type mismatch
	_, err = f.Pack("not uint8")
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestShortField(t *testing.T) {
	f := NewShortField("test", 0x1234)

	if f.DefaultVal() != uint16(0x1234) {
		t.Errorf("default = %x, want 1234", f.DefaultVal())
	}

	b, err := f.Pack(uint16(0xABCD))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 2 {
		t.Fatalf("len = %d, want 2", len(b))
	}
	if binary.BigEndian.Uint16(b) != 0xABCD {
		t.Errorf("pack = %x, want abcd", b)
	}

	val, n, err := f.Unpack([]byte{0x12, 0x34})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint16) != 0x1234 || n != 2 {
		t.Errorf("unpack = %x, %d, want 1234, 2", val, n)
	}
}

func TestLEShortField(t *testing.T) {
	f := NewLEShortField("test", 0x0000)

	b, err := f.Pack(uint16(0xABCD))
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(b) != 0xABCD {
		t.Errorf("LE pack wrong")
	}

	val, n, err := f.Unpack([]byte{0x34, 0x12})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint16) != 0x1234 || n != 2 {
		t.Errorf("LE unpack = %x, want 1234", val)
	}
}

func TestThreeBytesField(t *testing.T) {
	f := NewThreeBytesField("test", 0)

	b, err := f.Pack(uint32(0xAABBCC))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 3 {
		t.Fatalf("len = %d, want 3", len(b))
	}
	if b[0] != 0xAA || b[1] != 0xBB || b[2] != 0xCC {
		t.Errorf("pack = %x, want aabbcc", b)
	}

	val, n, err := f.Unpack([]byte{0x11, 0x22, 0x33})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint32) != 0x112233 || n != 3 {
		t.Errorf("unpack = %x, want 112233", val)
	}

	// overflow
	_, err = f.Pack(uint32(0x1000000))
	if err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestIntField(t *testing.T) {
	f := NewIntField("test", 0xDEADBEEF)

	b, err := f.Pack(uint32(0x12345678))
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(b) != 0x12345678 {
		t.Errorf("pack wrong")
	}

	val, n, err := f.Unpack([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint32) != 0xDEADBEEF || n != 4 {
		t.Errorf("unpack = %x, want deadbeef", val)
	}
}

func TestSignedIntField(t *testing.T) {
	f := NewSignedIntField("test", -1)

	b, err := f.Pack(int32(-1))
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(b) != 0xFFFFFFFF {
		t.Errorf("pack = %x, want ffffffff", b)
	}

	val, _, err := f.Unpack([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if err != nil {
		t.Fatal(err)
	}
	if val.(int32) != -1 {
		t.Errorf("unpack = %d, want -1", val)
	}
}

func TestLEIntField(t *testing.T) {
	f := NewLEIntField("test", 0)

	b, err := f.Pack(uint32(0x12345678))
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(b) != 0x12345678 {
		t.Errorf("LE int pack wrong")
	}

	val, _, err := f.Unpack([]byte{0x78, 0x56, 0x34, 0x12})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint32) != 0x12345678 {
		t.Errorf("LE int unpack = %x, want 12345678", val)
	}
}

func TestLongField(t *testing.T) {
	f := NewLongField("test", 0)

	val, n, err := f.Unpack([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint64) != 0x42 || n != 8 {
		t.Errorf("unpack = %x, want 42", val)
	}
}

func TestLELongField(t *testing.T) {
	f := NewLELongField("test", 0)

	val, _, err := f.Unpack([]byte{0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint64) != 0x42 {
		t.Errorf("LE long unpack = %x, want 42", val)
	}
}

func TestBitField(t *testing.T) {
	f := NewBitField("flags", 0, 3)

	if f.BitSize() != 3 {
		t.Errorf("bitsize = %d, want 3", f.BitSize())
	}
	if f.FixedSize() != 0 {
		t.Errorf("size = %d, want 0 (managed by bit-group)", f.FixedSize())
	}

	b, err := f.Pack(uint8(5))
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != 5 {
		t.Errorf("pack = %d, want 5", b[0])
	}

	// overflow
	_, err = f.Pack(uint8(8))
	if err == nil {
		t.Fatal("expected overflow for 3-bit field with value 8")
	}

	val, n, err := f.Unpack([]byte{0b11101001})
	if err != nil {
		t.Fatal(err)
	}
	if val.(uint8) != 1 || n != 0 {
		t.Errorf("unpack = %d, %d, want 1, 0", val, n)
	}
}

func TestMACField(t *testing.T) {
	f := NewMACField("mac", net.HardwareAddr{0, 0, 0, 0, 0, 0})

	// pack net.HardwareAddr
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	b, err := f.Pack(mac)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 6 {
		t.Errorf("len = %d", len(b))
	}

	// pack string
	b, err = f.Pack("11:22:33:44:55:66")
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != 0x11 || b[5] != 0x66 {
		t.Errorf("pack string wrong")
	}

	// pack []byte
	b, err = f.Pack([]byte{1, 2, 3, 4, 5, 6})
	if err != nil {
		t.Fatal(err)
	}

	// unpack
	val, n, err := f.Unpack([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	if err != nil {
		t.Fatal(err)
	}
	if mac, ok := val.(net.HardwareAddr); !ok || mac.String() != "aa:bb:cc:dd:ee:ff" || n != 6 {
		t.Errorf("unpack = %v, %d", val, n)
	}

	// invalid
	_, err = f.Pack(42)
	if err == nil {
		t.Fatal("expected error for int")
	}
}

func TestIPField(t *testing.T) {
	f := NewIPField("ip", net.IP{0, 0, 0, 0})

	// pack net.IP
	b, err := f.Pack(net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != 192 || b[3] != 1 {
		t.Errorf("pack = %v", b)
	}

	// pack string
	b, err = f.Pack("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	// reject IPv6
	_, err = f.Pack("::1")
	if err == nil {
		t.Fatal("expected error for IPv6")
	}

	// unpack
	val, n, err := f.Unpack([]byte{172, 16, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if ip, ok := val.(net.IP); !ok || ip.String() != "172.16.0.1" || n != 4 {
		t.Errorf("unpack = %v, %d", val, n)
	}
}

func TestStrField(t *testing.T) {
	f := NewStrField("data", "")

	if f.FixedSize() != 0 {
		t.Errorf("size = %d, want 0", f.FixedSize())
	}

	b, err := f.Pack("hello")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Errorf("pack = %q", b)
	}

	// pack []byte
	b, err = f.Pack([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}

	val, n, err := f.Unpack([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := val.([]byte); !ok || string(v) != "world" || n != 5 {
		t.Errorf("unpack = %v, %d", val, n)
	}
}

func TestStrLenField(t *testing.T) {
	f := NewStrLenField("payload", "", "payloadLen")

	if f.LengthFrom() != "payloadLen" {
		t.Errorf("LengthFrom = %q, want payloadLen", f.LengthFrom())
	}

	b, err := f.Pack("data")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "data" {
		t.Errorf("pack = %q", b)
	}
}

func TestPacketField(t *testing.T) {
	f := NewPacketField("body", "Raw")

	if f.PktName() != "Raw" {
		t.Errorf("PktName = %q, want Raw", f.PktName())
	}
}

func TestConditionalField(t *testing.T) {
	inner := NewByteField("opt", 0)
	cond := func(vals map[string]interface{}) bool {
		return vals["hasOpt"] == uint8(1)
	}
	f := NewConditionalField(inner, cond)

	if f.Name() != "opt" {
		t.Errorf("name = %q, want opt", f.Name())
	}
	if f.FixedSize() != 1 {
		t.Errorf("size = %d, want 1", f.FixedSize())
	}

	vals := map[string]interface{}{"hasOpt": uint8(1)}
	if !f.Active(vals) {
		t.Fatal("expected active when hasOpt=1")
	}

	vals["hasOpt"] = uint8(0)
	if f.Active(vals) {
		t.Fatal("expected inactive when hasOpt=0")
	}
}