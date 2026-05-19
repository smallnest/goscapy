package gre

import (
	"bytes"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestNewGREDefaults(t *testing.T) {
	g := NewGRE()

	fv, _ := g.Layer.Get("flagsver")
	if fv.(uint16) != 0 {
		t.Errorf("flagsver = %#x, want 0", fv)
	}
	if GetProtocolType(g.Layer) != ProtoIP {
		t.Errorf("proto = %#x, want %#x", GetProtocolType(g.Layer), ProtoIP)
	}
}

func TestGREBuilder(t *testing.T) {
	g := NewGRE().ProtocolType(ProtoEthernet).Key(100).Seq(42)

	if GetProtocolType(g.Layer) != ProtoEthernet {
		t.Errorf("proto = %#x", GetProtocolType(g.Layer))
	}
	if GetKey(g.Layer) != 100 {
		t.Errorf("key = %d, want 100", GetKey(g.Layer))
	}
	if GetSeq(g.Layer) != 42 {
		t.Errorf("seq = %d, want 42", GetSeq(g.Layer))
	}
	if !HasKey(g.Layer) {
		t.Error("K flag should be set")
	}
	if !HasSeq(g.Layer) {
		t.Error("S flag should be set")
	}
}

func TestGRESerializeBase(t *testing.T) {
	g := NewGRE().ProtocolType(0x0800)

	got, err := g.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Base header: flagsver(0) + proto(0x0800) = 4 bytes
	want := []byte{0x00, 0x00, 0x08, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("serialize base:\n got  %#v\nwant %#v", got, want)
	}
}

func TestGRESerializeWithKey(t *testing.T) {
	g := NewGRE().ProtocolType(0x0800).Key(100)

	got, err := g.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// flagsver(K=1)=0x2000 + proto(0x0800) + key(100) = 8 bytes
	want := []byte{
		0x20, 0x00, 0x08, 0x00, // base: K=1, proto=0x0800
		0x00, 0x00, 0x00, 0x64, // key = 100
	}
	if !bytes.Equal(got, want) {
		t.Errorf("serialize with key:\n got  %#v\nwant %#v", got, want)
	}
}

func TestGRESerializeWithSeq(t *testing.T) {
	g := NewGRE().ProtocolType(0x0800).Seq(999)

	got, err := g.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// flagsver(S=1)=0x1000 + proto(0x0800) + seq(999) = 8 bytes
	want := []byte{
		0x10, 0x00, 0x08, 0x00, // base: S=1, proto=0x0800
		0x00, 0x00, 0x03, 0xE7, // seq = 999
	}
	if !bytes.Equal(got, want) {
		t.Errorf("serialize with seq:\n got  %#v\nwant %#v", got, want)
	}
}

func TestGRESerializeWithKeyAndSeq(t *testing.T) {
	g := NewGRE().ProtocolType(0x0800).Key(100).Seq(42)

	got, err := g.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// K=1,S=1 (0x3000) + proto(0x0800) + key(100) + seq(42) = 12 bytes
	want := []byte{
		0x30, 0x00, 0x08, 0x00, // base: K=1,S=1, proto=0x0800
		0x00, 0x00, 0x00, 0x64, // key = 100
		0x00, 0x00, 0x00, 0x2A, // seq = 42
	}
	if !bytes.Equal(got, want) {
		t.Errorf("serialize with key+seq:\n got  %#v\nwant %#v", got, want)
	}
}

func TestGRESerializeWithChecksum(t *testing.T) {
	g := NewGRE().ProtocolType(0x0800).SetChecksum(0xABCD)

	got, err := g.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// C=1 (0x8000) + proto(0x0800) + chksum(0xABCD) + reserved1(0) = 8 bytes
	want := []byte{
		0x80, 0x00, 0x08, 0x00, // base: C=1, proto=0x0800
		0xAB, 0xCD, 0x00, 0x00, // chksum=0xABCD, reserved1=0
	}
	if !bytes.Equal(got, want) {
		t.Errorf("serialize with checksum:\n got  %#v\nwant %#v", got, want)
	}
}

func TestGREParseBase(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x08, 0x00}

	layer := NewGRELayer()
	consumed, err := layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 4 {
		t.Fatalf("consumed = %d, want 4", consumed)
	}
	if GetProtocolType(layer) != 0x0800 {
		t.Errorf("proto = %#x", GetProtocolType(layer))
	}
}

func TestGREParseWithKey(t *testing.T) {
	raw := []byte{
		0x20, 0x00, 0x08, 0x00, // K=1, proto=0x0800
		0x00, 0x00, 0x00, 0x64, // key = 100
	}

	layer := NewGRELayer()
	consumed, err := layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 8 {
		t.Fatalf("consumed = %d, want 8", consumed)
	}
	if !HasKey(layer) {
		t.Error("K flag should be set")
	}
	if GetKey(layer) != 100 {
		t.Errorf("key = %d, want 100", GetKey(layer))
	}
}

func TestGREParseWithKeyAndSeq(t *testing.T) {
	raw := []byte{
		0x30, 0x00, 0x08, 0x00, // K=1,S=1, proto=0x0800
		0x00, 0x00, 0x00, 0x64, // key = 100
		0x00, 0x00, 0x00, 0x2A, // seq = 42
	}

	layer := NewGRELayer()
	consumed, err := layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 12 {
		t.Fatalf("consumed = %d, want 12", consumed)
	}
	if GetKey(layer) != 100 {
		t.Errorf("key = %d", GetKey(layer))
	}
	if GetSeq(layer) != 42 {
		t.Errorf("seq = %d", GetSeq(layer))
	}
}

func TestGRERoundTrip(t *testing.T) {
	g := NewGRE().ProtocolType(0x6558).Key(0xDEADBEEF).Seq(0xCAFE)

	raw, err := g.Layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	layer := NewGRELayer()
	_, err = layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}

	if GetProtocolType(layer) != 0x6558 {
		t.Errorf("proto = %#x", GetProtocolType(layer))
	}
	if GetKey(layer) != 0xDEADBEEF {
		t.Errorf("key = %#x", GetKey(layer))
	}
	if GetSeq(layer) != 0xCAFE {
		t.Errorf("seq = %#x", GetSeq(layer))
	}
}

func TestGREProtocolType(t *testing.T) {
	// Ethernet bridging: proto=0x6558
	raw := []byte{0x00, 0x00, 0x65, 0x58}

	layer := NewGRELayer()
	layer.ParseFields(raw)
	if GetProtocolType(layer) != ProtoEthernet {
		t.Errorf("proto = %#x, want %#x", GetProtocolType(layer), ProtoEthernet)
	}
}

func TestGREOverEtherIP(t *testing.T) {
	// Full stack: IP(proto=47) / GRE(key=100) / inner IP / Raw
	outerIP := packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45),
		fields.NewByteField("dscpecn", 0),
		fields.NewShortField("len", 20),
		fields.NewShortField("id", 0),
		fields.NewShortField("flagsfrag", 0),
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 47),
		fields.NewShortField("chksum", 0),
		fields.NewIPField("src", net.IPv4zero),
		fields.NewIPField("dst", net.IPv4zero),
	})
	outerIP.Set("src", "10.0.0.1")
	outerIP.Set("dst", "10.0.0.2")

	gre := NewGRE().ProtocolType(0x0800).Key(100)

	innerIP := packet.NewLayer("IP", []fields.Field{
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
	innerIP.Set("src", "192.168.1.1")
	innerIP.Set("dst", "192.168.1.2")

	raw := packet.NewLayer("Raw", []fields.Field{
		fields.NewStrField("load", ""),
	})
	raw.Set("load", []byte("test"))

	pkt := packet.NewFrom(outerIP, gre.Layer, innerIP, raw)
	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// IP(20) + GRE(8 with key) + innerIP(20) + Raw(4) = 52
	if len(built) != 52 {
		t.Errorf("len = %d, want 52", len(built))
	}

	// GRE at offset 20: K=1 (0x2000)
	if built[20] != 0x20 || built[21] != 0x00 {
		t.Errorf("GRE flagsver = %#x %#x", built[20], built[21])
	}
	// ProtocolType at offset 22-23
	if built[22] != 0x08 || built[23] != 0x00 {
		t.Errorf("GRE proto = %#x %#x", built[22], built[23])
	}
	// Key at offset 24-27
	if built[24] != 0x00 || built[25] != 0x00 || built[26] != 0x00 || built[27] != 0x64 {
		t.Errorf("GRE key bytes = %#v", built[24:28])
	}
}

func TestGREParseTruncated(t *testing.T) {
	layer := NewGRELayer()
	_, err := layer.ParseFields([]byte{0x00, 0x00}) // Only 2 bytes, need at least 4
	if err == nil {
		t.Error("expected error for truncated GRE header")
	}
}

func TestGREParseTruncatedKey(t *testing.T) {
	// K=1 but key field is truncated
	raw := []byte{0x20, 0x00, 0x08, 0x00, 0x00} // Only 5 bytes, key needs 4

	layer := NewGRELayer()
	_, err := layer.ParseFields(raw)
	if err == nil {
		t.Error("expected error for truncated key field")
	}
}