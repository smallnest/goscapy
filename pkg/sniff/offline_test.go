package sniff_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/pcap"
	"github.com/smallnest/goscapy/pkg/sniff"
)

// writeFile writes data to path for tests.
func writeFile(t *testing.T, path string, data []byte) error {
	t.Helper()
	return os.WriteFile(path, data, 0o600)
}

// makeCapture builds an in-memory pcap with n Ethernet/IP/ICMP packets.
func makeCapture(t *testing.T, n int) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	w, err := pcap.NewWriter(&buf, pcap.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
		ip := layers.NewIP()
		_ = ip.Set("src", "192.168.1.1")
		_ = ip.Set("dst", "10.0.0.1")
		_ = ip.Set("proto", layers.IPProtoICMP)
		icmp := layers.NewICMP()
		_ = icmp.Set("id", uint16(i))
		pkt := packet.NewFrom(eth, ip, icmp)
		if err := w.WritePkt(pkt); err != nil {
			t.Fatal(err)
		}
	}
	return &buf
}

func TestSniffOfflineReader(t *testing.T) {
	buf := makeCapture(t, 5)

	var got int
	err := sniff.SniffOfflineReader(buf, sniff.OfflineConfig{}, func(pkt *packet.Packet) bool {
		got++
		if !pkt.HasLayer("ICMP") {
			t.Errorf("packet %d missing ICMP: %s", got, pkt.String())
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 5 {
		t.Errorf("processed %d packets, want 5", got)
	}
}

func TestSniffOfflineCount(t *testing.T) {
	buf := makeCapture(t, 10)
	var got int
	err := sniff.SniffOfflineReader(buf, sniff.OfflineConfig{Count: 3}, func(*packet.Packet) bool {
		got++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Errorf("processed %d, want 3 (count limit)", got)
	}
}

func TestSniffOfflineFilter(t *testing.T) {
	buf := makeCapture(t, 6)
	var got int
	// Only accept packets whose ICMP id is even.
	err := sniff.SniffOfflineReader(buf, sniff.OfflineConfig{
		Filter: func(pkt *packet.Packet) bool {
			ic := pkt.GetLayer("ICMP")
			if ic == nil {
				return false
			}
			id, _ := ic.Get("id")
			return id.(uint16)%2 == 0
		},
	}, func(*packet.Packet) bool {
		got++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Errorf("filtered count = %d, want 3", got)
	}
}

func TestSniffOfflineHandlerStop(t *testing.T) {
	buf := makeCapture(t, 10)
	var got int
	err := sniff.SniffOfflineReader(buf, sniff.OfflineConfig{}, func(*packet.Packet) bool {
		got++
		return got < 2 // stop after 2
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("processed %d, want 2 (handler stop)", got)
	}
}

func TestSniffOfflineNoPath(t *testing.T) {
	err := sniff.SniffOffline(sniff.OfflineConfig{}, func(*packet.Packet) bool { return true })
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSniffOfflineBPFExpr(t *testing.T) {
	// Build a capture with mixed TCP and UDP packets.
	var buf bytes.Buffer
	w, err := pcap.NewWriter(&buf, pcap.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
		ip := layers.NewIP()
		_ = ip.Set("src", "192.168.1.1")
		_ = ip.Set("dst", "10.0.0.1")
		_ = ip.Set("proto", layers.IPProtoTCP)
		tcp := layers.NewTCP()
		_ = tcp.Set("sport", uint16(1000+i))
		_ = tcp.Set("dport", uint16(80))
		_ = w.WritePkt(packet.NewFrom(eth, ip, tcp))
	}
	for i := 0; i < 2; i++ {
		eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
		ip := layers.NewIP()
		_ = ip.Set("src", "192.168.1.1")
		_ = ip.Set("dst", "10.0.0.1")
		_ = ip.Set("proto", layers.IPProtoUDP)
		udp := layers.NewUDP()
		_ = udp.Set("sport", uint16(5000+i))
		_ = udp.Set("dport", uint16(53))
		_ = w.WritePkt(packet.NewFrom(eth, ip, udp))
	}

	var tcpCount int
	err = sniff.SniffOfflineReader(&buf, sniff.OfflineConfig{FilterExpr: "tcp port 80"}, func(*packet.Packet) bool {
		tcpCount++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if tcpCount != 3 {
		t.Errorf("BPF filter matched %d, want 3 TCP packets", tcpCount)
	}
}

func TestSniffOfflineChan(t *testing.T) {
	buf := makeCapture(t, 4)
	// Write to a temp file since SniffOfflineChan uses SniffOffline (path-based).
	tmp := t.TempDir() + "/cap.pcap"
	if err := writeFile(t, tmp, buf.Bytes()); err != nil {
		t.Fatal(err)
	}

	ch, stop := sniff.SniffOfflineChan(sniff.OfflineConfig{Path: tmp})
	defer stop()

	var got int
	timeout := time.After(5 * time.Second)
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				if got != 4 {
					t.Errorf("got %d packets, want 4", got)
				}
				return
			}
			_ = pkt
			got++
		case <-timeout:
			t.Fatal("timed out waiting for packets")
		}
	}
}
