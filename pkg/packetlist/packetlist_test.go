package packetlist_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/packetlist"
	"github.com/smallnest/goscapy/pkg/pcap"
)

func mkTCP(t *testing.T, src, dst string, sport, dport uint16) *packet.Packet {
	t.Helper()
	ip := layers.NewIP()
	_ = ip.Set("src", src)
	_ = ip.Set("dst", dst)
	_ = ip.Set("proto", layers.IPProtoTCP)
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", sport)
	_ = tcp.Set("dport", dport)
	return packet.NewFrom(ip, tcp)
}

func mkUDP(t *testing.T, src, dst string, sport, dport uint16) *packet.Packet {
	t.Helper()
	ip := layers.NewIP()
	_ = ip.Set("src", src)
	_ = ip.Set("dst", dst)
	_ = ip.Set("proto", layers.IPProtoUDP)
	udp := layers.NewUDP()
	_ = udp.Set("sport", sport)
	_ = udp.Set("dport", dport)
	return packet.NewFrom(ip, udp)
}

func TestPacketListBasics(t *testing.T) {
	pl := packetlist.FromPackets(
		mkTCP(t, "1.1.1.1", "2.2.2.2", 100, 80),
		mkUDP(t, "1.1.1.1", "2.2.2.2", 53, 53),
	)
	if pl.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pl.Len())
	}
	if pl.Get(0) == nil || pl.Get(5) != nil {
		t.Error("Get bounds wrong")
	}
}

func TestPacketListFilter(t *testing.T) {
	pl := packetlist.FromPackets(
		mkTCP(t, "1.1.1.1", "2.2.2.2", 100, 80),
		mkUDP(t, "1.1.1.1", "2.2.2.2", 53, 53),
		mkTCP(t, "3.3.3.3", "4.4.4.4", 200, 443),
	)
	tcps := pl.FilterProto("TCP")
	if tcps.Len() != 2 {
		t.Errorf("TCP filter = %d, want 2", tcps.Len())
	}
	udps := pl.FilterProto("UDP")
	if udps.Len() != 1 {
		t.Errorf("UDP filter = %d, want 1", udps.Len())
	}
}

func TestPacketListSlice(t *testing.T) {
	pl := packetlist.FromPackets(
		mkTCP(t, "1.1.1.1", "2.2.2.2", 1, 2),
		mkTCP(t, "1.1.1.1", "2.2.2.2", 3, 4),
		mkTCP(t, "1.1.1.1", "2.2.2.2", 5, 6),
	)
	s := pl.Slice(1, 3)
	if s.Len() != 2 {
		t.Errorf("Slice len = %d, want 2", s.Len())
	}
	// Out-of-range clamps.
	if pl.Slice(-5, 100).Len() != 3 {
		t.Error("Slice clamp failed")
	}
}

func TestProtoCounts(t *testing.T) {
	pl := packetlist.FromPackets(
		mkTCP(t, "1.1.1.1", "2.2.2.2", 100, 80),
		mkUDP(t, "1.1.1.1", "2.2.2.2", 53, 53),
	)
	counts := pl.ProtoCounts()
	if counts["IP"] != 2 {
		t.Errorf("IP count = %d, want 2", counts["IP"])
	}
	if counts["TCP"] != 1 || counts["UDP"] != 1 {
		t.Errorf("transport counts wrong: %v", counts)
	}
}

func TestSessionsBidirectional(t *testing.T) {
	// Two directions of the same TCP flow must collapse to one session.
	pl := packetlist.FromPackets(
		mkTCP(t, "1.1.1.1", "2.2.2.2", 12345, 80),
		mkTCP(t, "2.2.2.2", "1.1.1.1", 80, 12345),
		mkTCP(t, "1.1.1.1", "2.2.2.2", 12345, 80),
		// A different flow.
		mkUDP(t, "3.3.3.3", "4.4.4.4", 53, 5000),
	)
	sessions := pl.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("session count = %d, want 2 (keys: %v)", len(sessions), pl.SessionKeys())
	}
	// The TCP session must contain all 3 TCP packets.
	var tcpSession *packetlist.PacketList
	for k, s := range sessions {
		if s.Len() == 3 {
			tcpSession = s
			_ = k
		}
	}
	if tcpSession == nil {
		t.Fatal("expected a 3-packet TCP session")
	}
}

func TestSessionsKeysSorted(t *testing.T) {
	pl := packetlist.FromPackets(
		mkTCP(t, "1.1.1.1", "2.2.2.2", 100, 80),
		mkUDP(t, "3.3.3.3", "4.4.4.4", 53, 5000),
	)
	keys := pl.SessionKeys()
	for i := 1; i < len(keys); i++ {
		if keys[i] < keys[i-1] {
			t.Errorf("keys not sorted: %v", keys)
		}
	}
}

func TestReadWritePcapRoundtrip(t *testing.T) {
	pl := packetlist.New("test")
	now := time.Now().Truncate(time.Microsecond)
	for i := 0; i < 4; i++ {
		eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
		ip := layers.NewIP()
		_ = ip.Set("src", "192.168.1.1")
		_ = ip.Set("dst", "10.0.0.1")
		_ = ip.Set("proto", layers.IPProtoTCP)
		tcp := layers.NewTCP()
		_ = tcp.Set("sport", uint16(1000+i))
		_ = tcp.Set("dport", uint16(80))
		pl.Append(packet.NewFrom(eth, ip, tcp), now.Add(time.Duration(i)*time.Second))
	}

	var buf bytes.Buffer
	if err := pl.WritePcapWriter(&buf, pcap.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	got, err := packetlist.ReadPcapReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 4 {
		t.Fatalf("read back %d packets, want 4", got.Len())
	}
	// First and last timestamps should be preserved.
	first, last := got.TimeSpan()
	if first.IsZero() || last.IsZero() {
		t.Error("timestamps not preserved")
	}
	if !got.Get(0).HasLayer("TCP") {
		t.Errorf("read back packet missing TCP: %s", got.Get(0).String())
	}
}

func TestSummaryAndStats(t *testing.T) {
	pl := packetlist.FromPackets(
		mkTCP(t, "1.1.1.1", "2.2.2.2", 100, 80),
		mkTCP(t, "1.1.1.1", "2.2.2.2", 101, 80),
		mkUDP(t, "1.1.1.1", "2.2.2.2", 53, 53),
	)
	stats := pl.Statistics()
	if stats["IP / TCP"] != 2 {
		t.Errorf("stats IP/TCP = %d, want 2 (%v)", stats["IP / TCP"], stats)
	}
	if stats["IP / UDP"] != 1 {
		t.Errorf("stats IP/UDP = %d, want 1", stats["IP / UDP"])
	}
	sum := pl.Summary()
	if sum == "" {
		t.Error("Summary empty")
	}
}
