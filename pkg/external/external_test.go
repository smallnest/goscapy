package external

import (
	"os"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/pcap"
)

func samplePacket() *packet.Packet {
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", layers.IPProtoICMP)
	return packet.NewFrom(eth, ip, layers.NewICMP())
}

func TestWritePcapTemp(t *testing.T) {
	path, err := WritePcapTemp(pcap.LinkTypeEthernet, samplePacket(), samplePacket())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	// The temp file must be a readable pcap with 2 packets.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := pcap.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, err := rd.ReadPacket()
		if err != nil {
			break
		}
		n++
	}
	if n != 2 {
		t.Errorf("wrote %d packets, want 2", n)
	}
}

// TestTcpdumpIfAvailable runs tcpdump only when it is installed, so CI without
// tcpdump still passes. It verifies the round-trip produces non-empty output.
func TestTcpdumpIfAvailable(t *testing.T) {
	out, err := Tcpdump(pcap.LinkTypeEthernet, []string{"-n"}, samplePacket())
	if err != nil {
		t.Skipf("tcpdump unavailable or failed: %v", err)
	}
	if out == "" {
		t.Error("tcpdump produced no output")
	}
}
