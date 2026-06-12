package layers

import (
	"encoding/binary"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- ESP ----

func TestESPBuildDissect(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoESP)
	esp := NewESPWith(0xDEADBEEF, 42)
	_ = esp.Set("data", []byte{0x01, 0x02, 0x03, 0x04})

	pkt := packet.NewFrom(ip, esp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}
	espBytes := raw[20:]
	if binary.BigEndian.Uint32(espBytes[0:4]) != 0xDEADBEEF {
		t.Errorf("SPI wrong")
	}
	if binary.BigEndian.Uint32(espBytes[4:8]) != 42 {
		t.Errorf("seq wrong")
	}

	d, err := packet.DissectByProto(raw, "IP")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("ESP") {
		t.Errorf("missing ESP layer: %s", d.String())
	}
	espL := d.GetLayer("ESP")
	spi, _ := espL.Get("spi")
	if spi.(uint32) != 0xDEADBEEF {
		t.Errorf("parsed SPI = %#x", spi)
	}
	data, _ := espL.Get("data")
	if len(data.([]byte)) != 4 {
		t.Errorf("ESP data len = %d, want 4", len(data.([]byte)))
	}
}

// ---- AH ----

func TestAHBuildLenField(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoAH)
	ah := NewAHWith(IPProtoTCP, 0x11223344, 7)
	// 12-byte ICV → total header 24 bytes → len = 24/4 - 2 = 4.
	_ = ah.Set("icv", make([]byte, 12))

	pkt := packet.NewFrom(ip, ah)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}
	ahBytes := raw[20:]
	if ahBytes[0] != IPProtoTCP {
		t.Errorf("AH nh = %d, want %d", ahBytes[0], IPProtoTCP)
	}
	if ahBytes[1] != 4 {
		t.Errorf("AH len = %d, want 4", ahBytes[1])
	}
	if binary.BigEndian.Uint32(ahBytes[4:8]) != 0x11223344 {
		t.Errorf("AH SPI wrong")
	}
}

func TestAHDissectChain(t *testing.T) {
	// IP / AH / TCP — AH's nh field should chain to TCP.
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoAH)
	ah := NewAHWith(IPProtoTCP, 0x11223344, 7)
	_ = ah.Set("icv", make([]byte, 12))
	tcp := NewTCP()
	_ = tcp.Set("sport", uint16(1234))
	_ = tcp.Set("dport", uint16(80))

	pkt := packet.NewFrom(ip, ah, tcp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	d, err := packet.DissectByProto(raw, "IP")
	if err != nil {
		t.Fatal(err)
	}
	if d.String() != "IP / AH / TCP" {
		t.Errorf("dissect = %q, want IP / AH / TCP", d.String())
	}
	// Verify the TCP ports survived (header boundary was correct).
	tcpL := d.GetLayer("TCP")
	if tcpL == nil {
		t.Fatal("missing TCP")
	}
	dport, _ := tcpL.Get("dport")
	if dport.(uint16) != 80 {
		t.Errorf("TCP dport = %d, want 80", dport)
	}

	// The parsed ICV must be exactly 12 bytes (not the greedy remainder), and
	// rebuilding the dissected packet must reproduce the original wire bytes.
	icv, _ := d.GetLayer("AH").Get("icv")
	icvLen := 0
	switch v := icv.(type) {
	case string:
		icvLen = len(v)
	case []byte:
		icvLen = len(v)
	}
	if icvLen != 12 {
		t.Errorf("AH icv = %d bytes, want 12 (greedy over-read)", icvLen)
	}
	rebuilt, err := d.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(rebuilt) != len(raw) {
		t.Errorf("AH round-trip size mismatch: rebuilt %d, original %d", len(rebuilt), len(raw))
	}
}

// ---- GTP ----

func TestGTPBuildDissect(t *testing.T) {
	// GTP-U G-PDU carrying an inner IP/UDP packet over UDP 2152.
	outerIP := NewIP()
	_ = outerIP.Set("src", "10.0.0.1")
	_ = outerIP.Set("dst", "10.0.0.2")
	_ = outerIP.Set("proto", IPProtoUDP)
	outerUDP := NewUDP()
	_ = outerUDP.Set("sport", GTPUPort)
	_ = outerUDP.Set("dport", GTPUPort)
	gtp := NewGTPWith(GTPMsgGPDU, 0xCAFEBABE)

	innerIP := NewIP()
	_ = innerIP.Set("src", "192.168.1.1")
	_ = innerIP.Set("dst", "192.168.1.2")
	_ = innerIP.Set("proto", IPProtoUDP)
	innerUDP := NewUDP()
	_ = innerUDP.Set("sport", uint16(5000))
	_ = innerUDP.Set("dport", uint16(6000))

	pkt := packet.NewFrom(outerIP, outerUDP, gtp, innerIP, innerUDP)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Locate GTP header: outer IP(20) + UDP(8) = offset 28.
	gtpBytes := raw[28:]
	if GTPVersion(gtpBytes[0]) != 1 {
		t.Errorf("GTP version = %d, want 1", GTPVersion(gtpBytes[0]))
	}
	if gtpBytes[1] != GTPMsgGPDU {
		t.Errorf("GTP msgtype = %d", gtpBytes[1])
	}
	if binary.BigEndian.Uint32(gtpBytes[4:8]) != 0xCAFEBABE {
		t.Errorf("GTP TEID wrong")
	}
	// length = inner IP(20) + UDP(8) = 28.
	if binary.BigEndian.Uint16(gtpBytes[2:4]) != 28 {
		t.Errorf("GTP len = %d, want 28", binary.BigEndian.Uint16(gtpBytes[2:4]))
	}

	d, err := packet.DissectByProto(raw, "IP")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("GTP") {
		t.Errorf("missing GTP: %s", d.String())
	}
	// Inner IP should be dissected after GTP.
	ips := d.GetLayers("IP")
	if len(ips) != 2 {
		t.Errorf("expected 2 IP layers (outer+inner), got %d: %s", len(ips), d.String())
	}
}

func TestGTPHelpers(t *testing.T) {
	g := NewGTP()
	flags, _ := g.Get("flags")
	if GTPVersion(flags.(uint8)) != 1 {
		t.Errorf("default version = %d, want 1", GTPVersion(flags.(uint8)))
	}
	if GTPHasExtensions(flags.(uint8)) {
		t.Error("default header should have no extension flags")
	}
}
