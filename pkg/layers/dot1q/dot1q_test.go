package dot1q

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestNewDot1QDefaults(t *testing.T) {
	d := NewDot1Q()

	tpid, _ := d.Get("tpid")
	if tpid.(uint16) != TPID8021Q {
		t.Errorf("tpid = %#x, want %#x", tpid, TPID8021Q)
	}
	tci, _ := d.Get("tci")
	if tci.(uint16) != 0 {
		t.Errorf("tci = %#x, want 0", tci)
	}
	etype, _ := d.Get("type")
	if etype.(uint16) != 0x0800 {
		t.Errorf("type = %#x, want 0x0800", etype)
	}
}

func TestDot1QBuilder(t *testing.T) {
	d := NewDot1Q().VID(100).PCP(3).DEI(true).Type(0x0800)

	if GetVID(d.Layer) != 100 {
		t.Errorf("VID = %d, want 100", GetVID(d.Layer))
	}
	if GetPCP(d.Layer) != 3 {
		t.Errorf("PCP = %d, want 3", GetPCP(d.Layer))
	}
	if !GetDEI(d.Layer) {
		t.Error("DEI should be true")
	}
	if GetType(d.Layer) != 0x0800 {
		t.Errorf("type = %#x, want 0x0800", GetType(d.Layer))
	}
}

func TestDot1QBuilderChaining(t *testing.T) {
	d := NewDot1Q().VID(4095).PCP(7).DEI(false)

	if GetVID(d.Layer) != 4095 {
		t.Errorf("VID = %d, want 4095", GetVID(d.Layer))
	}
	if GetPCP(d.Layer) != 7 {
		t.Errorf("PCP = %d, want 7", GetPCP(d.Layer))
	}
	if GetDEI(d.Layer) {
		t.Error("DEI should be false")
	}
}

func TestDot1QSerialize(t *testing.T) {
	d := NewDot1Q().VID(100).PCP(3)

	got, err := d.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Expected: tpid(0x8100) + tci(PCP=3,DEI=0,VID=100) + type(0x0800)
	// TCI: PCP=3<<13 | DEI=0<<12 | VID=100 = 0x6000 | 0x0064 = 0x6064
	want := []byte{
		0x81, 0x00, // TPID = 0x8100
		0x60, 0x64, // TCI: PCP=3, DEI=0, VID=100
		0x08, 0x00, // type = 0x0800 (IPv4)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("serialize mismatch:\n got  %#v\nwant %#v", got, want)
	}
}

func TestDot1QParse(t *testing.T) {
	raw := []byte{
		0x81, 0x00, // TPID = 0x8100
		0x60, 0x64, // TCI: PCP=3, DEI=0, VID=100
		0x08, 0x00, // type = 0x0800 (IPv4)
	}

	layer := NewDot1QLayer()
	consumed, err := layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed = %d, want %d", consumed, len(raw))
	}

	if GetVID(layer) != 100 {
		t.Errorf("VID = %d, want 100", GetVID(layer))
	}
	if GetPCP(layer) != 3 {
		t.Errorf("PCP = %d, want 3", GetPCP(layer))
	}
	if GetDEI(layer) {
		t.Error("DEI should be false")
	}
	if GetType(layer) != 0x0800 {
		t.Errorf("type = %#x, want 0x0800", GetType(layer))
	}
}

func TestDot1QWithDEI(t *testing.T) {
	d := NewDot1Q().VID(50).DEI(true)

	raw, err := d.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// TCI: PCP=0, DEI=1, VID=50 = 0x1000 | 0x0032 = 0x1032
	if raw[2] != 0x10 || raw[3] != 0x32 {
		t.Errorf("TCI = %#x %#x, want 0x10 0x32", raw[2], raw[3])
	}

	// Parse back.
	layer := NewDot1QLayer()
	layer.ParseFields(raw)
	if GetVID(layer) != 50 {
		t.Errorf("VID = %d, want 50", GetVID(layer))
	}
	if !GetDEI(layer) {
		t.Error("DEI should be true")
	}
}

func TestDot1QRoundTrip(t *testing.T) {
	d := NewDot1Q().VID(4094).PCP(5).DEI(true).Type(0x86DD)

	raw, err := d.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	layer := NewDot1QLayer()
	_, err = layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}

	if GetVID(layer) != 4094 {
		t.Errorf("VID = %d", GetVID(layer))
	}
	if GetPCP(layer) != 5 {
		t.Errorf("PCP = %d", GetPCP(layer))
	}
	if !GetDEI(layer) {
		t.Error("DEI mismatch")
	}
	if GetType(layer) != 0x86DD {
		t.Errorf("type = %#x", GetType(layer))
	}
}

func TestDot1QTPID(t *testing.T) {
	// Test QinQ outer tag with TPID 0x88A8.
	d := NewDot1Q().TPID(TPID8021AD).VID(200).Type(0x8100)

	raw, err := d.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// TPID should be 0x88A8.
	if binary.BigEndian.Uint16(raw[0:2]) != TPID8021AD {
		t.Errorf("TPID = %#x, want %#x", binary.BigEndian.Uint16(raw[0:2]), TPID8021AD)
	}

	// Parse back.
	layer := NewDot1QLayer()
	layer.ParseFields(raw)
	tpid, _ := layer.Get("tpid")
	if tpid.(uint16) != TPID8021AD {
		t.Errorf("parsed TPID = %#x", tpid)
	}
	typeVal, _ := layer.Get("type")
	if typeVal.(uint16) != 0x8100 {
		t.Errorf("parsed type = %#x", typeVal)
	}
}

func TestEtherDot1QIPv4(t *testing.T) {
	// Full stack: Ether / Dot1Q(vlan=100, pcp=3) / IP / Raw
	// Expected bytes from Scapy:
	// Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
	// Dot1Q(vlan=100, prio=3) /
	// IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) /
	// Raw(load="test")
	//
	// Total: Eth(14) + Dot1Q(6) + IP(20) + Raw(4) = 44

	eth := packet.NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		fields.NewMACField("src", net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		fields.NewShortField("type", 0x8100),
	})
	dot1q := NewDot1Q().VID(100).PCP(3).Type(0x0800)
	ip := packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45),
		fields.NewByteField("dscpecn", 0),
		fields.NewShortField("len", 20),
		fields.NewShortField("id", 0),
		fields.NewShortField("flagsfrag", 0),
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 0),
		fields.NewShortField("chksum", 0),
		fields.NewIPField("src", net.IPv4zero),
		fields.NewIPField("dst", net.IPv4zero),
	})
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")

	raw := packet.NewLayer("Raw", []fields.Field{
		fields.NewStrField("load", ""),
	})
	raw.Set("load", []byte("test"))

	pkt := packet.NewFrom(eth, dot1q.Layer, ip, raw)
	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Verify Dot1Q tag at offset 14 (after Eth header).
	if binary.BigEndian.Uint16(built[14:16]) != 0x8100 {
		t.Errorf("Dot1Q TPID = %#x", binary.BigEndian.Uint16(built[14:16]))
	}
	// TCI: PCP=3<<13 | DEI=0<<12 | VID=100 = 0x6064
	if binary.BigEndian.Uint16(built[16:18]) != 0x6064 {
		t.Errorf("Dot1Q TCI = %#x, want 0x6064", binary.BigEndian.Uint16(built[16:18]))
	}
	// inner type = 0x0800
	if binary.BigEndian.Uint16(built[18:20]) != 0x0800 {
		t.Errorf("Dot1Q type = %#x", binary.BigEndian.Uint16(built[18:20]))
	}
	// IP header starts at offset 20.
	if built[20] != 0x45 {
		t.Errorf("IP verihl = %#x", built[20])
	}

	// Total size: 14 + 6 + 20 + 4 = 44
	if len(built) != 44 {
		t.Errorf("len = %d, want 44", len(built))
	}
}

func TestQinQ(t *testing.T) {
	// QinQ: Ether / Dot1Q(outer, tpid=0x88A8, vid=200) / Dot1Q(inner, tpid=0x8100, vid=100) / IP
	// Total: Eth(14) + Outer(6) + Inner(6) + IP(20) = 46

	eth := packet.NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		fields.NewMACField("src", net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		fields.NewShortField("type", 0x88A8),
	})
	outer := NewDot1Q().TPID(0x88A8).VID(200).Type(0x8100)
	inner := NewDot1Q().TPID(0x8100).VID(100).Type(0x0800)
	ip := packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45),
		fields.NewByteField("dscpecn", 0),
		fields.NewShortField("len", 20),
		fields.NewShortField("id", 0),
		fields.NewShortField("flagsfrag", 0),
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 0),
		fields.NewShortField("chksum", 0),
		fields.NewIPField("src", net.IPv4zero),
		fields.NewIPField("dst", net.IPv4zero),
	})
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")

	pkt := packet.NewFrom(eth, outer.Layer, inner.Layer, ip)
	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Outer tag at offset 14.
	if binary.BigEndian.Uint16(built[14:16]) != 0x88A8 {
		t.Errorf("outer TPID = %#x", binary.BigEndian.Uint16(built[14:16]))
	}
	if GetVID(outer.Layer) != 200 {
		t.Errorf("outer VID = %d", GetVID(outer.Layer))
	}

	// Inner tag at offset 18.
	if binary.BigEndian.Uint16(built[18:20]) != 0x8100 {
		t.Errorf("inner TPID = %#x", binary.BigEndian.Uint16(built[18:20]))
	}
	if GetVID(inner.Layer) != 100 {
		t.Errorf("inner VID = %d", GetVID(inner.Layer))
	}

	// IP starts at offset 26.
	if built[26] != 0x45 {
		t.Errorf("IP verihl = %#x at offset 26", built[26])
	}

	if len(built) != 46 {
		t.Errorf("len = %d, want 46", len(built))
	}
}

func TestDot1QParseTruncated(t *testing.T) {
	layer := NewDot1QLayer()
	_, err := layer.ParseFields([]byte{0x81, 0x00}) // Only TPID, no TCI or type.
	if err == nil {
		t.Error("expected error for truncated Dot1Q data")
	}
}

func TestVIDBoundary(t *testing.T) {
	// VID is 12 bits, so max value is 4095.
	d := NewDot1Q().VID(4095)
	raw, _ := d.SerializeFields()
	// TCI: VID=4095 (0xFFF)
	if raw[2] != 0x0F || raw[3] != 0xFF {
		t.Errorf("TCI = %#x %#x, want 0x0F 0xFF", raw[2], raw[3])
	}

	// VID=4096 should be masked to 0.
	d2 := NewDot1Q().VID(4096)
	if GetVID(d2.Layer) != 0 {
		t.Errorf("VID(4096) = %d, want 0 (masked)", GetVID(d2.Layer))
	}
}

func TestPCPBoundary(t *testing.T) {
	// PCP is 3 bits, so max value is 7.
	d := NewDot1Q().PCP(7)
	raw, _ := d.SerializeFields()
	if raw[2] != 0xE0 || raw[3] != 0x00 {
		t.Errorf("TCI = %#x %#x, want 0xE0 0x00", raw[2], raw[3])
	}

	// PCP=8 should be masked to 0.
	d2 := NewDot1Q().PCP(8)
	if GetPCP(d2.Layer) != 0 {
		t.Errorf("PCP(8) = %d, want 0 (masked)", GetPCP(d2.Layer))
	}
}