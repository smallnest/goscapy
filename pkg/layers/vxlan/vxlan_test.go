package vxlan

import (
	"bytes"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestNewVXLANDefaults(t *testing.T) {
	v := NewVXLAN()

	flags, _ := v.Layer.Get("flags")
	if flags.(uint8) != FlagI {
		t.Errorf("flags = %#x, want %#x", flags, FlagI)
	}
	if GetVNI(v.Layer) != 0 {
		t.Errorf("VNI = %d, want 0", GetVNI(v.Layer))
	}
}

func TestVXLANBuilder(t *testing.T) {
	v := NewVXLAN().VNI(5000).Flags(0x08)

	if GetVNI(v.Layer) != 5000 {
		t.Errorf("VNI = %d, want 5000", GetVNI(v.Layer))
	}
	if GetFlags(v.Layer) != 0x08 {
		t.Errorf("flags = %#x, want 0x08", GetFlags(v.Layer))
	}
}

func TestVXLANSerialize(t *testing.T) {
	v := NewVXLAN().VNI(5000)

	got, err := v.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// VXLAN header: flags(0x08) + reserved1(3 bytes zeros) + VNI(0x001388) + reserved2(0x00)
	want := []byte{
		0x08,                   // flags (I=1)
		0x00, 0x00, 0x00,       // reserved1
		0x00, 0x13, 0x88,       // VNI = 5000 = 0x001388
		0x00,                   // reserved2
	}

	if !bytes.Equal(got, want) {
		t.Errorf("serialize mismatch:\n got  %#v\nwant %#v", got, want)
	}
}

func TestVXLANParse(t *testing.T) {
	raw := []byte{
		0x08,                   // flags (I=1)
		0x00, 0x00, 0x00,       // reserved1
		0x00, 0x13, 0x88,       // VNI = 5000
		0x00,                   // reserved2
	}

	layer := NewVXLANLayer()
	consumed, err := layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 8 {
		t.Fatalf("consumed = %d, want 8", consumed)
	}

	if GetVNI(layer) != 5000 {
		t.Errorf("VNI = %d, want 5000", GetVNI(layer))
	}
	if GetFlags(layer) != 0x08 {
		t.Errorf("flags = %#x, want 0x08", GetFlags(layer))
	}
}

func TestVXLANRoundTrip(t *testing.T) {
	v := NewVXLAN().VNI(0xABCDEF).Flags(0x08)

	raw, err := v.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	layer := NewVXLANLayer()
	_, err = layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}

	if GetVNI(layer) != 0xABCDEF {
		t.Errorf("VNI = %#x", GetVNI(layer))
	}
	if GetFlags(layer) != 0x08 {
		t.Errorf("flags = %#x", GetFlags(layer))
	}
}

func TestVXLANVNIBoundary(t *testing.T) {
	// VNI is 24 bits, max value is 0xFFFFFF.
	v := NewVXLAN().VNI(0xFFFFFF)
	if GetVNI(v.Layer) != 0xFFFFFF {
		t.Errorf("VNI = %#x, want 0xFFFFFF", GetVNI(v.Layer))
	}

	// VNI=0x1000000 should be masked to 0.
	v2 := NewVXLAN().VNI(0x1000000)
	if GetVNI(v2.Layer) != 0 {
		t.Errorf("VNI(0x1000000) = %#x, want 0 (masked)", GetVNI(v2.Layer))
	}
}

func TestVXLANFlags(t *testing.T) {
	v := NewVXLAN().Flags(0x08)
	if GetFlags(v.Layer) != 0x08 {
		t.Errorf("flags = %#x, want 0x08", GetFlags(v.Layer))
	}

	v2 := NewVXLAN().Flags(0x0F) // set extra reserved bits
	if GetFlags(v2.Layer) != 0x0F {
		t.Errorf("flags = %#x, want 0x0F", GetFlags(v2.Layer))
	}
}


func TestVXLANTunnel(t *testing.T) {
	// Full stack: Ether/IP/UDP/VXLAN/VNI=5000/inner Eth/inner IP/inner ICMP
	vxlan := NewVXLAN().VNI(5000)

	// Build outer headers.
	outerEth := packet.NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		fields.NewMACField("src", net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}),
		fields.NewShortField("type", 0x0800),
	})
	outerIP := packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45),
		fields.NewByteField("dscpecn", 0),
		fields.NewShortField("len", 20),
		fields.NewShortField("id", 0),
		fields.NewShortField("flagsfrag", 0),
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 17),
		fields.NewShortField("chksum", 0),
		fields.NewIPField("src", net.IPv4zero),
		fields.NewIPField("dst", net.IPv4zero),
	})
	outerIP.Set("src", "10.0.0.1")
	outerIP.Set("dst", "10.0.0.2")

	outerUDP := packet.NewLayer("UDP", []fields.Field{
		fields.NewShortField("sport", 0),
		fields.NewShortField("dport", 0),
		fields.NewShortField("len", 8),
		fields.NewShortField("chksum", 0),
	})
	outerUDP.Set("sport", uint16(1234))
	outerUDP.Set("dport", uint16(4789))

	// Inner headers.
	innerEth := packet.NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		fields.NewMACField("src", net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		fields.NewShortField("type", 0x0800),
	})
	innerIP := packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45),
		fields.NewByteField("dscpecn", 0),
		fields.NewShortField("len", 20),
		fields.NewShortField("id", 0),
		fields.NewShortField("flagsfrag", 0),
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 1),
		fields.NewShortField("chksum", 0),
		fields.NewIPField("src", net.IPv4zero),
		fields.NewIPField("dst", net.IPv4zero),
	})
	innerIP.Set("src", "192.168.1.1")
	innerIP.Set("dst", "192.168.1.2")

	innerICMP := packet.NewLayer("ICMP", []fields.Field{
		fields.NewByteField("type", 8),
		fields.NewByteField("code", 0),
		fields.NewShortField("chksum", 0),
		fields.NewShortField("id", 0x1234),
		fields.NewShortField("seq", 1),
	})

	pkt := packet.NewFrom(outerEth, outerIP, outerUDP, vxlan.Layer, innerEth, innerIP, innerICMP)
	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Verify VXLAN header at the right offset: Eth(14) + IP(20) + UDP(8) = 42
	if built[42] != 0x08 {
		t.Errorf("VXLAN flags at offset 42 = %#x, want 0x08", built[42])
	}
	// VNI at offset 46-48 (3 bytes): 5000 = 0x001388
	if built[46] != 0x00 || built[47] != 0x13 || built[48] != 0x88 {
		t.Errorf("VNI bytes = %#x %#x %#x, want 0x00 0x13 0x88",
			built[46], built[47], built[48])
	}

	// Inner Ethernet starts at offset 50 (42 + 8).
	if built[50] != 0xff {
		t.Errorf("inner Eth dst[0] at offset 50 = %#x, want 0xff", built[50])
	}

	// Total size: 14+20+8+8+14+20+8 = 92
	if len(built) != 92 {
		t.Errorf("len = %d, want 92", len(built))
	}
}

func TestVXLANParseTruncated(t *testing.T) {
	layer := NewVXLANLayer()
	_, err := layer.ParseFields([]byte{0x08, 0x00, 0x00}) // Only 3 bytes, need 8
	if err == nil {
		t.Error("expected error for truncated VXLAN header")
	}
}