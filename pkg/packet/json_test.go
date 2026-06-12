package packet_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestToJSON(t *testing.T) {
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", layers.IPProtoTCP)
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	pkt := packet.NewFrom(eth, ip, tcp)

	data, err := pkt.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	var pj packet.PacketJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(pj.Layers) != 3 {
		t.Fatalf("got %d layers, want 3", len(pj.Layers))
	}
	if pj.Layers[0].Proto != "Ethernet" {
		t.Errorf("layer 0 = %s, want Ethernet", pj.Layers[0].Proto)
	}
	// MAC address rendered as string.
	if pj.Layers[0].Fields["src"] != "11:22:33:44:55:66" {
		t.Errorf("eth src = %v", pj.Layers[0].Fields["src"])
	}
	// IP rendered as string.
	if pj.Layers[1].Fields["src"] != "192.168.1.1" {
		t.Errorf("ip src = %v", pj.Layers[1].Fields["src"])
	}
	// Port rendered as number (JSON float64 after round-trip).
	if v, ok := pj.Layers[2].Fields["dport"].(float64); !ok || v != 80 {
		t.Errorf("tcp dport = %v (%T), want 80", pj.Layers[2].Fields["dport"], pj.Layers[2].Fields["dport"])
	}
	if !strings.Contains(pj.Summary, "192.168.1.1") {
		t.Errorf("summary missing src: %q", pj.Summary)
	}
}

func TestToJSONIndent(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", "1.2.3.4")
	pkt := packet.NewFrom(ip)
	data, err := pkt.ToJSONIndent("", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\n") {
		t.Error("indented JSON should contain newlines")
	}
}

func TestJSONByteField(t *testing.T) {
	raw := layers.NewRawWith([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	pkt := packet.NewFrom(raw)
	pj := pkt.JSON()
	if pj.Layers[0].Fields["load"] != "deadbeef" {
		t.Errorf("raw load = %v, want deadbeef hex string", pj.Layers[0].Fields["load"])
	}
}
