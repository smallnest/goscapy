package ospf

import (
	"testing"
)

func TestNewOSPFLayer(t *testing.T) {
	layer := NewOSPF()
	if layer.Proto() != "OSPF" {
		t.Errorf("Proto = %q, want %q", layer.Proto(), "OSPF")
	}

	ver, _ := layer.Get("version")
	if ver != uint8(2) {
		t.Errorf("version = %v, want 2", ver)
	}

	typ, _ := layer.Get("type")
	if typ != uint8(TypeHello) {
		t.Errorf("type = %v, want %d", typ, TypeHello)
	}
}

func TestOSPFHelloLayer(t *testing.T) {
	layer := NewOSPFHello()
	if layer.Proto() != "OSPF Hello" {
		t.Errorf("Proto = %q, want %q", layer.Proto(), "OSPF Hello")
	}

	interval, _ := layer.Get("hello_interval")
	if interval != uint16(10) {
		t.Errorf("hello_interval = %v, want 10", interval)
	}

	prio, _ := layer.Get("prio")
	if prio != uint8(1) {
		t.Errorf("prio = %v, want 1", prio)
	}

	dead, _ := layer.Get("dead_interval")
	if dead != uint32(40) {
		t.Errorf("dead_interval = %v, want 40", dead)
	}
}

func TestOSPFDBDLayer(t *testing.T) {
	layer := NewOSPFDBD()

	mtu, _ := layer.Get("mtu")
	if mtu != uint16(1500) {
		t.Errorf("mtu = %v, want 1500", mtu)
	}

	flags, _ := layer.Get("flags")
	if flags != uint8(DBDFlagMS|DBDFlagM|DBDFlagI) {
		t.Errorf("flags = %v, want %v", flags, DBDFlagMS|DBDFlagM|DBDFlagI)
	}
}

func TestLSAHeaderRoundTrip(t *testing.T) {
	h := &LSAHeader{
		Age:       1,
		Options:   0x00,
		Type:      1, // Router LSA
		ID:        0xC0A80000,
		AdvRouter: 0x01010101,
		Seq:       0x80000001,
		Checksum:  0,
		Length:    36,
	}

	data := h.Serialize()
	if len(data) != 20 {
		t.Fatalf("Serialize len = %d, want 20", len(data))
	}

	parsed, err := ParseLSAHeader(data)
	if err != nil {
		t.Fatalf("ParseLSAHeader failed: %v", err)
	}

	if parsed.Age != h.Age {
		t.Errorf("Age = %d, want %d", parsed.Age, h.Age)
	}
	if parsed.Type != h.Type {
		t.Errorf("Type = %d, want %d", parsed.Type, h.Type)
	}
	if parsed.ID != h.ID {
		t.Errorf("ID = 0x%08x, want 0x%08x", parsed.ID, h.ID)
	}
	if parsed.AdvRouter != h.AdvRouter {
		t.Errorf("AdvRouter = 0x%08x, want 0x%08x", parsed.AdvRouter, h.AdvRouter)
	}
	if parsed.Seq != h.Seq {
		t.Errorf("Seq = 0x%08x, want 0x%08x", parsed.Seq, h.Seq)
	}
	if parsed.Length != h.Length {
		t.Errorf("Length = %d, want %d", parsed.Length, h.Length)
	}
}

func TestParseLSAHeaderTruncated(t *testing.T) {
	_, err := ParseLSAHeader([]byte{0x00, 0x01, 0x00})
	if err == nil {
		t.Error("expected error for truncated LSA header")
	}
}

func TestOSPFChecksum(t *testing.T) {
	// Test with known data - checksum of all zeros should be 0xFFFF
	data := make([]byte, 20)
	csum := OSPFChecksum(data)
	if csum != 0xFFFF {
		t.Errorf("Checksum of zeros = 0x%04x, want 0xFFFF", csum)
	}
}

func TestOSPFSetGet(t *testing.T) {
	layer := NewOSPF()
	layer.Set("router_id", "1.1.1.1")
	layer.Set("area_id", "0.0.0.0")
	layer.Set("type", uint8(TypeDBD))

	routerID, _ := layer.Get("router_id")
	if routerID == nil {
		t.Error("router_id is nil after Set")
	}

	typ, _ := layer.Get("type")
	if typ != uint8(TypeDBD) {
		t.Errorf("type = %v, want %d", typ, TypeDBD)
	}
}
