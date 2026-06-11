package packet_test

import (
	"strings"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestHexdumpBasic(t *testing.T) {
	data := []byte{0x45, 0x00, 0x00, 0x28, 0x41, 0x42, 0x43, 0x44}
	out := packet.Hexdump(data)

	if !strings.Contains(out, "0000  ") {
		t.Errorf("Hexdump missing offset, got:\n%s", out)
	}
	if !strings.Contains(out, "45 00 00 28") {
		t.Errorf("Hexdump missing hex bytes, got:\n%s", out)
	}
	// Printable ASCII column should render A B C D.
	if !strings.Contains(out, "ABCD") {
		t.Errorf("Hexdump missing ASCII column, got:\n%s", out)
	}
}

func TestHexdumpEmpty(t *testing.T) {
	if packet.Hexdump(nil) != "" {
		t.Error("Hexdump(nil) should be empty")
	}
	if packet.Hexdump([]byte{}) != "" {
		t.Error("Hexdump([]) should be empty")
	}
}

func TestHexdumpMultiLine(t *testing.T) {
	data := make([]byte, 20)
	for i := range data {
		data[i] = byte(i)
	}
	out := packet.Hexdump(data)
	if !strings.Contains(out, "0000  ") {
		t.Errorf("missing first line offset, got:\n%s", out)
	}
	if !strings.Contains(out, "0010  ") {
		t.Errorf("missing second line offset, got:\n%s", out)
	}
}

func TestPacketHexdump(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", uint8(6))
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))

	pkt := packet.NewFrom(ip, tcp)
	out := pkt.Hexdump()
	if !strings.Contains(out, "0000  ") {
		t.Errorf("Packet.Hexdump missing offset, got:\n%s", out)
	}
}

func TestShow2(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", uint8(6))
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(0x02))

	pkt := packet.NewFrom(ip, tcp)
	out := pkt.Show2()
	if !strings.Contains(out, "###[ IP ]###") {
		t.Errorf("Show2 missing IP, got:\n%s", out)
	}
	if !strings.Contains(out, "###[ TCP ]###") {
		t.Errorf("Show2 missing TCP, got:\n%s", out)
	}
	// Auto-computed len should be filled in after rebuild.
	if !strings.Contains(out, "len") {
		t.Errorf("Show2 missing len field, got:\n%s", out)
	}
}

func TestShow2Empty(t *testing.T) {
	if packet.New().Show2() != "" {
		t.Error("empty Show2 should be empty")
	}
}

func TestLs(t *testing.T) {
	out := packet.Ls("IP")
	if !strings.Contains(out, "IP:") {
		t.Errorf("Ls(IP) missing header, got:\n%s", out)
	}
	if !strings.Contains(out, "src") {
		t.Errorf("Ls(IP) missing src field, got:\n%s", out)
	}

	all := packet.Ls("")
	if !strings.Contains(all, "IP") {
		t.Errorf("Ls() missing IP in list, got:\n%s", all)
	}

	if !strings.Contains(packet.Ls("NoSuchProto"), "unknown") {
		t.Error("Ls(unknown) should report unknown")
	}
}

func TestFieldNames(t *testing.T) {
	names := packet.FieldNames("IP")
	if len(names) == 0 {
		t.Fatal("FieldNames(IP) returned nothing")
	}
	if names[0] != "verihl" {
		t.Errorf("FieldNames(IP)[0] = %q, want verihl", names[0])
	}
	hasSrc := false
	for _, n := range names {
		if n == "src" {
			hasSrc = true
		}
	}
	if !hasSrc {
		t.Errorf("FieldNames(IP) missing src, got: %v", names)
	}
	if packet.FieldNames("NoSuchProto") != nil {
		t.Error("FieldNames(unknown) should be nil")
	}
}
