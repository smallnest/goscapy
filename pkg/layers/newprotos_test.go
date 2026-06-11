package layers

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- SCTP ----

func TestSCTPBuildChecksum(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoSCTP)

	sctp := NewSCTPWith(1234, 5678, 0xDEADBEEF)
	// A minimal INIT chunk as payload.
	chunk := NewSCTPChunk()
	_ = chunk.Set("type", SCTPChunkInit)
	_ = chunk.Set("len", uint16(4))

	pkt := packet.NewFrom(ip, sctp, chunk)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// SCTP starts after the 20-byte IP header.
	sctpBytes := raw[20:]
	if len(sctpBytes) < 12 {
		t.Fatalf("SCTP too short: %d", len(sctpBytes))
	}

	// Verify CRC32c: zero the checksum field, recompute, compare (little-endian).
	stored := binary.LittleEndian.Uint32(sctpBytes[8:12])
	verify := make([]byte, len(sctpBytes))
	copy(verify, sctpBytes)
	verify[8], verify[9], verify[10], verify[11] = 0, 0, 0, 0
	want := crc32.Checksum(verify, crc32.MakeTable(crc32.Castagnoli))
	if stored != want {
		t.Errorf("SCTP CRC32c = %#x, want %#x", stored, want)
	}

	// Ports and vtag.
	if binary.BigEndian.Uint16(sctpBytes[0:2]) != 1234 {
		t.Errorf("sport wrong")
	}
	if binary.BigEndian.Uint32(sctpBytes[4:8]) != 0xDEADBEEF {
		t.Errorf("vtag wrong")
	}
}

func TestSCTPDissect(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoSCTP)
	sctp := NewSCTPWith(1234, 5678, 1)
	pkt := packet.NewFrom(ip, sctp)
	raw, _ := pkt.Build()

	d, err := packet.DissectByProto(raw, "IP")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("SCTP") {
		t.Errorf("dissected packet missing SCTP layer: %s", d.String())
	}
}

// ---- IGMP ----

func TestIGMPBuildChecksum(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.10")
	_ = ip.Set("dst", "224.0.0.1")
	_ = ip.Set("proto", IPProtoIGMP)
	igmp := NewIGMPWith(IGMPv2MembershipReport, "239.1.2.3")

	pkt := packet.NewFrom(ip, igmp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}
	igmpBytes := raw[20:]
	if len(igmpBytes) != 8 {
		t.Fatalf("IGMP len = %d, want 8", len(igmpBytes))
	}
	if igmpBytes[0] != IGMPv2MembershipReport {
		t.Errorf("type = %#x", igmpBytes[0])
	}
	// Verify checksum over full message folds to zero.
	if Checksum(igmpBytes) != 0 {
		t.Errorf("IGMP checksum verification failed")
	}
}

func TestIGMPDissect(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.10")
	_ = ip.Set("dst", "224.0.0.1")
	_ = ip.Set("proto", IPProtoIGMP)
	igmp := NewIGMPWith(IGMPMembershipQuery, "0.0.0.0")
	pkt := packet.NewFrom(ip, igmp)
	raw, _ := pkt.Build()

	d, err := packet.DissectByProto(raw, "IP")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("IGMP") {
		t.Errorf("missing IGMP layer: %s", d.String())
	}
}

// ---- MPLS ----

func TestMPLSLabelStackEntry(t *testing.T) {
	lse := MakeMPLSLSE(1048575, 5, true, 64) // max 20-bit label
	if MPLSLabel(lse) != 1048575 {
		t.Errorf("label = %d, want 1048575", MPLSLabel(lse))
	}
	if MPLSExp(lse) != 5 {
		t.Errorf("exp = %d, want 5", MPLSExp(lse))
	}
	if !MPLSBottom(lse) {
		t.Error("bottom should be set")
	}
	if MPLSTTL(lse) != 64 {
		t.Errorf("ttl = %d, want 64", MPLSTTL(lse))
	}
}

func TestMPLSStackSerialize(t *testing.T) {
	// Two-label stack over Ethernet, then IP.
	eth := NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", EtherTypeMPLSUnicast)
	outer := NewMPLSWith(100, 0, false, 64)
	inner := NewMPLSWith(200, 0, true, 64)
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")

	pkt := packet.NewFrom(eth, outer, inner, ip)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}
	// Ethernet (14) + 2 MPLS (8) + IP (20) = 42.
	if len(raw) != 42 {
		t.Fatalf("len = %d, want 42", len(raw))
	}
	// First MPLS entry at offset 14.
	lse0 := binary.BigEndian.Uint32(raw[14:18])
	if MPLSLabel(lse0) != 100 || MPLSBottom(lse0) {
		t.Errorf("outer label = %d bottom = %v", MPLSLabel(lse0), MPLSBottom(lse0))
	}
	lse1 := binary.BigEndian.Uint32(raw[18:22])
	if MPLSLabel(lse1) != 200 || !MPLSBottom(lse1) {
		t.Errorf("inner label = %d bottom = %v", MPLSLabel(lse1), MPLSBottom(lse1))
	}
}

// ---- PPPoE ----

func TestPPPoESessionBuild(t *testing.T) {
	eth := NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", EtherTypePPPoESession)
	pppoe := NewPPPoEWith(PPPoECodeSession, 0x1234)
	ppp := NewPPPWith(PPPProtoIPv4)
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoICMP)
	icmp := NewICMP()

	pkt := packet.NewFrom(eth, pppoe, ppp, ip, icmp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// PPPoE header at offset 14.
	pppoeBytes := raw[14:20]
	if pppoeBytes[0] != 0x11 {
		t.Errorf("ver_type = %#x, want 0x11", pppoeBytes[0])
	}
	if pppoeBytes[1] != PPPoECodeSession {
		t.Errorf("code = %#x", pppoeBytes[1])
	}
	if binary.BigEndian.Uint16(pppoeBytes[2:4]) != 0x1234 {
		t.Errorf("session_id wrong")
	}
	// Payload length = PPP (2) + IP (20) + ICMP (8) = 30.
	plen := binary.BigEndian.Uint16(pppoeBytes[4:6])
	if plen != 30 {
		t.Errorf("PPPoE len = %d, want 30", plen)
	}
	// PPP protocol field follows.
	if binary.BigEndian.Uint16(raw[20:22]) != PPPProtoIPv4 {
		t.Errorf("PPP proto wrong")
	}
}

func TestPPPoEDissect(t *testing.T) {
	eth := NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", EtherTypePPPoESession)
	pppoe := NewPPPoEWith(PPPoECodeSession, 0x1234)
	ppp := NewPPPWith(PPPProtoIPv4)
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoICMP)
	pkt := packet.NewFrom(eth, pppoe, ppp, ip, NewICMP())
	raw, _ := pkt.Build()

	d, err := packet.DissectByProto(raw, "Ethernet")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("PPPoE") {
		t.Errorf("missing PPPoE: %s", d.String())
	}
	if !d.HasLayer("PPP") {
		t.Errorf("missing PPP: %s", d.String())
	}
	if !d.HasLayer("IP") {
		t.Errorf("missing inner IP: %s", d.String())
	}
}
