package packet_test

import (
	"net"
	"strings"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- Show() tests ----

func TestShowBasic(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(0x02)) // SYN

	pkt := packet.NewFrom(ip, tcp)
	out := pkt.Show()

	if !strings.Contains(out, "###[ IP ]###") {
		t.Errorf("Show() missing IP header, got:\n%s", out)
	}
	if !strings.Contains(out, "###[ TCP ]###") {
		t.Errorf("Show() missing TCP header, got:\n%s", out)
	}
	if !strings.Contains(out, "src") {
		t.Errorf("Show() missing src field, got:\n%s", out)
	}
	if !strings.Contains(out, "192.168.1.1") {
		t.Errorf("Show() missing src IP value, got:\n%s", out)
	}
	if !strings.Contains(out, "sport") {
		t.Errorf("Show() missing sport field, got:\n%s", out)
	}
}

func TestShowEmpty(t *testing.T) {
	pkt := packet.New()
	if pkt.Show() != "" {
		t.Errorf("empty packet Show() = %q, want empty", pkt.Show())
	}
}

func TestShowEthernetIP(t *testing.T) {
	eth := layers.NewEthernet()
	_ = eth.Set("src", net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	_ = eth.Set("dst", net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})

	pkt := packet.NewFrom(eth)
	out := pkt.Show()

	if !strings.Contains(out, "###[ Ethernet ]###") {
		t.Errorf("Show() missing Ethernet header, got:\n%s", out)
	}
	if !strings.Contains(out, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("Show() missing MAC address, got:\n%s", out)
	}
}

// ---- Summary() tests ----

func TestSummaryIPUDP(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", uint8(17))

	udp := layers.NewUDP()
	_ = udp.Set("sport", uint16(53))
	_ = udp.Set("dport", uint16(12345))

	pkt := packet.NewFrom(ip, udp)
	s := pkt.Summary()

	if !strings.Contains(s, "192.168.1.1") {
		t.Errorf("Summary() missing src IP: %q", s)
	}
	if !strings.Contains(s, "10.0.0.1") {
		t.Errorf("Summary() missing dst IP: %q", s)
	}
	if !strings.Contains(s, "UDP") {
		t.Errorf("Summary() missing UDP: %q", s)
	}
}

func TestSummaryTCPSyn(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "10.0.0.1")
	_ = ip.Set("dst", "10.0.0.2")
	_ = ip.Set("proto", uint8(6))

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(0x02)) // SYN

	pkt := packet.NewFrom(ip, tcp)
	s := pkt.Summary()

	if !strings.Contains(s, "S") {
		t.Errorf("Summary() missing SYN flag: %q", s)
	}
	if !strings.Contains(s, "TCP") {
		t.Errorf("Summary() missing TCP: %q", s)
	}
}

func TestSummaryTCPSynAck(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "10.0.0.2")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", uint8(6))

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(80))
	_ = tcp.Set("dport", uint16(12345))
	_ = tcp.Set("flags", uint8(0x12)) // SYN+ACK

	pkt := packet.NewFrom(ip, tcp)
	s := pkt.Summary()

	if !strings.Contains(s, "SA") {
		t.Errorf("Summary() missing SYN+ACK flags: %q", s)
	}
}

func TestSummaryEmpty(t *testing.T) {
	pkt := packet.New()
	if pkt.Summary() != "" {
		t.Errorf("empty packet Summary() = %q, want empty", pkt.Summary())
	}
}

func TestSummaryEthernet(t *testing.T) {
	eth := layers.NewEthernet()
	_ = eth.Set("src", net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	_ = eth.Set("dst", net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})

	pkt := packet.NewFrom(eth)
	s := pkt.Summary()

	if !strings.Contains(s, "Ether") {
		t.Errorf("Summary() missing Ether: %q", s)
	}
}

// ---- ListLayers() tests ----

func TestListLayers(t *testing.T) {
	ls := packet.ListLayers()
	if len(ls) == 0 {
		t.Error("ListLayers() returned empty list")
	}
	found := false
	for _, l := range ls {
		if l == "IP" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListLayers() missing IP, got: %v", ls)
	}
	// Should be sorted.
	for i := 1; i < len(ls); i++ {
		if ls[i] < ls[i-1] {
			t.Errorf("ListLayers() not sorted: %v", ls)
			break
		}
	}
}

// ---- Describe() tests ----

func TestDescribeIP(t *testing.T) {
	ip := layers.NewIP()
	desc := ip.Describe()

	if !strings.Contains(desc, "IP:") {
		t.Errorf("Describe() missing IP header, got:\n%s", desc)
	}
	if !strings.Contains(desc, "src") {
		t.Errorf("Describe() missing src field, got:\n%s", desc)
	}
	if !strings.Contains(desc, "IP)") {
		t.Errorf("Describe() missing IP type annotation, got:\n%s", desc)
	}
}

func TestDescribeTCP(t *testing.T) {
	tcp := layers.NewTCP()
	desc := tcp.Describe()

	if !strings.Contains(desc, "TCP:") {
		t.Errorf("Describe() missing TCP header, got:\n%s", desc)
	}
	if !strings.Contains(desc, "sport") {
		t.Errorf("Describe() missing sport field, got:\n%s", desc)
	}
	if !strings.Contains(desc, "flags") {
		t.Errorf("Describe() missing flags field, got:\n%s", desc)
	}
}

// ---- Layer.String() tests ----

func TestLayerString(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")

	s := ip.String()
	if !strings.HasPrefix(s, "<IP ") {
		t.Errorf("Layer.String() = %q, want <IP ...>", s)
	}
	if !strings.Contains(s, "src=") {
		t.Errorf("Layer.String() missing src=, got: %q", s)
	}
	if !strings.Contains(s, "192.168.1.1") {
		t.Errorf("Layer.String() missing IP value, got: %q", s)
	}
}

// ---- formatValue tests via Show ----

func TestShowHexField(t *testing.T) {
	l := packet.NewLayer("Test", []fields.Field{
		fields.NewXByteField("xval", 0),
		fields.NewByteField("bval", 0),
	})
	_ = l.Set("xval", uint8(0xAB))
	_ = l.Set("bval", uint8(0xAB))

	pkt := packet.NewFrom(l)
	out := pkt.Show()

	if !strings.Contains(out, "0xab") {
		t.Errorf("Show() hex field not displayed as hex, got:\n%s", out)
	}
	if !strings.Contains(out, "171") {
		t.Errorf("Show() byte field not displayed as decimal, got:\n%s", out)
	}
}

func TestShowByteArray(t *testing.T) {
	l := packet.NewLayer("Test", []fields.Field{
		fields.NewStrFixedField("data", 4, nil),
	})
	_ = l.Set("data", []byte{0xDE, 0xAD, 0xBE, 0xEF})

	pkt := packet.NewFrom(l)
	out := pkt.Show()

	if !strings.Contains(out, "deadbeef") {
		t.Errorf("Show() byte array not displayed as hex, got:\n%s", out)
	}
}

// ---- Packet.String() existing test (verify no regression) ----

func TestPacketStringExisting(t *testing.T) {
	ip := layers.NewIP()
	tcp := layers.NewTCP()
	pkt := packet.NewFrom(ip, tcp)

	s := pkt.String()
	if s != "IP / TCP" {
		t.Errorf("Packet.String() = %q, want %q", s, "IP / TCP")
	}
}

// ---- Integration: Show on dissected packet ----

func TestShowDissectedPacket(t *testing.T) {
	eth := layers.NewEthernet()
	_ = eth.Set("src", net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	_ = eth.Set("dst", net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	_ = eth.Set("type", uint16(0x0800))

	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", uint8(6))
	_ = ip.Set("ttl", uint8(64))

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(0x02))

	pkt := packet.NewFrom(eth, ip, tcp)
	data, err := pkt.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	dissected, err := packet.DissectByProto(data, "Ethernet")
	if err != nil {
		t.Fatalf("DissectByProto: %v", err)
	}

	show := dissected.Show()
	if !strings.Contains(show, "###[ Ethernet ]###") {
		t.Errorf("dissected Show() missing Ethernet, got:\n%s", show)
	}
	if !strings.Contains(show, "###[ IP ]###") {
		t.Errorf("dissected Show() missing IP, got:\n%s", show)
	}
	if !strings.Contains(show, "###[ TCP ]###") {
		t.Errorf("dissected Show() missing TCP, got:\n%s", show)
	}

	summary := dissected.Summary()
	if !strings.Contains(summary, "192.168.1.1") {
		t.Errorf("dissected Summary() missing src: %q", summary)
	}
}
