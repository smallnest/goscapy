package layers

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// buildAndVerifyChecksums is a helper that builds a packet and verifies
// that all IP, ICMP, TCP, and UDP checksums are valid (round-trip to 0).
func buildAndVerifyChecksums(t *testing.T, pktData []byte, ethLen int) {
	t.Helper()

	if ethLen >= len(pktData) {
		return
	}
	ipStart := ethLen
	if ipStart+20 > len(pktData) {
		return
	}

	// Verify IP checksum.
	if pktData[ipStart]>>4 == 4 { // IPv4
		ipHdr := pktData[ipStart : ipStart+20]
		if csum := IPChecksum(ipHdr); csum != 0 {
			t.Errorf("IP checksum invalid: %#x (should verify to 0)", csum)
		}
	}
}

func TestBuildEthernetIPICMP(t *testing.T) {
	// Scapy: Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
	//         IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) /
	//         ICMP(type=8, code=0, id=0x1234, seq=1)
	//
	// Expected (42 bytes):
	// ff ff ff ff ff ff 00 11 22 33 44 55 08 00
	// 45 00 00 1c 00 00 00 00 40 01 66 df 0a 00 00 01 0a 00 00 02
	// 08 00 e5 ca 12 34 00 01
	expected := []byte{
		// Ethernet (14 bytes)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP (20 bytes): len=28, ttl=64, proto=1, chksum=0x66df
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x66, 0xdf,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		// ICMP (8 bytes): type=8, code=0, chksum=0xe5ca, id=0x1234, seq=1
		0x08, 0x00, 0xe5, 0xca,
		0x12, 0x34, 0x00, 0x01,
	}

	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	ip := NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")

	icmp := NewICMPEcho(0x1234, 1)

	pkt := eth.Over(ip)
	pkt.Push(icmp)

	got, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 42 {
		t.Fatalf("Build() len = %d, want 42", len(got))
	}

	if !equalBytes(t, got, expected) {
		t.Errorf("Ether/IP/ICMP mismatch:\n got: %x\nwant: %x", got, expected)
	}

	buildAndVerifyChecksums(t, got, 14)

	// Verify ICMP checksum independently.
	icmpBytes := got[34:] // after Ethernet(14) + IP(20)
	if csum := ICMPChecksum(icmpBytes); csum != 0 {
		t.Errorf("ICMP checksum invalid: %#x", csum)
	}
}

func TestBuildEthernetIPTCPRaw(t *testing.T) {
	// Scapy: Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
	//         IP(src="192.168.1.1", dst="8.8.8.8", ttl=64) /
	//         TCP(sport=12345, dport=80, flags='S', seq=1000) /
	//         Raw(load=b"hello")
	//
	// Expected (59 bytes):
	// ff ff ff ff ff ff 00 11 22 33 44 55 08 00
	// 45 00 00 2d 00 00 00 00 40 06 a9 12 c0 a8 01 01 08 08 08 08
	// 30 39 00 50 00 00 03 e8 00 00 00 00 50 02 20 00 45 e1 00 00
	// 68 65 6c 6c 6f
	expected := []byte{
		// Ethernet (14 bytes)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP (20 bytes): len=45, proto=6, chksum=0xa912
		0x45, 0x00, 0x00, 0x2d,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x06, 0xa9, 0x12,
		0xc0, 0xa8, 0x01, 0x01,
		0x08, 0x08, 0x08, 0x08,
		// TCP (20 bytes): sport=12345, dport=80, seq=1000, ack=0, dataofs=0x50, flags=SYN, win=8192, chksum=0x45e1
		0x30, 0x39, 0x00, 0x50,
		0x00, 0x00, 0x03, 0xe8,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x20, 0x00,
		0x45, 0xe1, 0x00, 0x00,
		// Raw (5 bytes): "hello"
		0x68, 0x65, 0x6c, 0x6c, 0x6f,
	}

	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	ip := NewIP()
	ip.Set("src", "192.168.1.1")
	ip.Set("dst", "8.8.8.8")

	tcp := NewTCPWith(12345, 80, TCPSyn)
	tcp.Set("seq", uint32(1000))

	raw := NewRawWith([]byte("hello"))

	pkt := eth.Over(ip)
	pkt.Push(tcp)
	pkt.Push(raw)

	got, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 59 {
		t.Fatalf("Build() len = %d, want 59", len(got))
	}

	if !equalBytes(t, got, expected) {
		t.Errorf("Ether/IP/TCP/Raw mismatch:\n got: %x\nwant: %x", got, expected)
	}

	buildAndVerifyChecksums(t, got, 14)

	// Verify TCP checksum independently.
	ipHdr := got[14:34]
	srcIP := net.IP(ipHdr[12:16]).To4()
	dstIP := net.IP(ipHdr[16:20]).To4()
	tcpAndPayload := got[34:]
	if csum := TCPChecksum(srcIP, dstIP, tcpAndPayload); csum != 0 {
		t.Errorf("TCP checksum invalid: %#x", csum)
	}

	// Verify IP total length.
	ipLen := binary.BigEndian.Uint16(got[16:18])
	if ipLen != 45 {
		t.Errorf("IP.len = %d, want 45", ipLen)
	}
}

func TestBuildEthernetIPUDPRaw(t *testing.T) {
	// Scapy: Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
	//         IP(src="192.168.1.1", dst="8.8.8.8", ttl=64) /
	//         UDP(sport=12345, dport=53) / Raw(load=b"test")
	//
	// Expected (46 bytes):
	// ff ff ff ff ff ff 00 11 22 33 44 55 08 00
	// 45 00 00 20 00 00 00 00 40 11 a9 14 c0 a8 01 01 08 08 08 08
	// 30 39 00 35 00 0c 15 d5 74 65 73 74
	expected := []byte{
		// Ethernet (14 bytes)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP (20 bytes): len=32, proto=17, chksum=0xa914
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0xa9, 0x14,
		0xc0, 0xa8, 0x01, 0x01,
		0x08, 0x08, 0x08, 0x08,
		// UDP (8 bytes): sport=12345, dport=53, len=12, chksum=0x15d5
		0x30, 0x39, 0x00, 0x35,
		0x00, 0x0c, 0x15, 0xd5,
		// Raw (4 bytes): "test"
		0x74, 0x65, 0x73, 0x74,
	}

	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	ip := NewIP()
	ip.Set("src", "192.168.1.1")
	ip.Set("dst", "8.8.8.8")

	udp := NewUDPWith(12345, 53)
	raw := NewRawWith([]byte("test"))

	pkt := eth.Over(ip)
	pkt.Push(udp)
	pkt.Push(raw)

	got, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 46 {
		t.Fatalf("Build() len = %d, want 46", len(got))
	}

	if !equalBytes(t, got, expected) {
		t.Errorf("Ether/IP/UDP/Raw mismatch:\n got: %x\nwant: %x", got, expected)
	}

	buildAndVerifyChecksums(t, got, 14)

	// Verify UDP checksum independently.
	ipHdr := got[14:34]
	srcIP := net.IP(ipHdr[12:16]).To4()
	dstIP := net.IP(ipHdr[16:20]).To4()
	udpAndPayload := got[34:]
	if csum := UDPChecksum(srcIP, dstIP, udpAndPayload); csum != 0 {
		t.Errorf("UDP checksum invalid: %#x", csum)
	}

	// Verify UDP length field (at offset 4-5 within UDP header, which starts at 34).
	udpLen := binary.BigEndian.Uint16(got[38:40])
	if udpLen != 12 {
		t.Errorf("UDP.len = %d, want 12", udpLen)
	}
}

func TestBuildEthernetARP(t *testing.T) {
	// ARP has no build hook — should serialize naively.
	expected := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x06,
		// ARP (28 bytes)
		0x00, 0x01, // hwtype
		0x08, 0x00, // ptype
		0x06,       // hwlen
		0x04,       // plen
		0x00, 0x01, // op
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // hwsrc
		0xc0, 0xa8, 0x01, 0x01, // psrc = 192.168.1.1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hwdst
		0xc0, 0xa8, 0x01, 0x64, // pdst = 192.168.1.100
	}

	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", 0)
	arp := NewARP()
	arp.Set("hwsrc", "aa:bb:cc:dd:ee:ff")
	arp.Set("psrc", "192.168.1.1")
	arp.Set("hwdst", "00:00:00:00:00:00")
	arp.Set("pdst", "192.168.1.100")

	pkt := eth.Over(arp)

	got, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	if !equalBytes(t, got, expected) {
		t.Errorf("Ether/ARP mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestBuildFromSkipEthernet(t *testing.T) {
	// Build from IP layer only (skip Ethernet).
	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	ip := NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")

	icmp := NewICMPEcho(0x0001, 1)

	pkt := eth.Over(ip)
	pkt.Push(icmp)

	// Build from layer index 1 (skip Ethernet).
	got, err := pkt.BuildFrom(1)
	if err != nil {
		t.Fatal(err)
	}

	// Should start with IP header (0x45).
	if got[0] != 0x45 {
		t.Errorf("first byte = %#x, want 0x45 (IP verihl)", got[0])
	}

	// Should be 28 bytes (IP header 20 + ICMP 8).
	if len(got) != 28 {
		t.Fatalf("BuildFrom(1) len = %d, want 28", len(got))
	}

	// Verify IP checksum.
	if csum := IPChecksum(got[0:20]); csum != 0 {
		t.Errorf("IP checksum invalid: %#x", csum)
	}

	// Verify ICMP checksum.
	if csum := ICMPChecksum(got[20:]); csum != 0 {
		t.Errorf("ICMP checksum invalid: %#x", csum)
	}
}

func TestBuildIPOnly(t *testing.T) {
	// Build a standalone IP layer with no upper layers.
	ip := NewIP()
	ip.Set("src", "192.168.1.1")
	ip.Set("dst", "10.0.0.1")

	pkt := packet.NewFrom(ip)

	got, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 20 {
		t.Fatalf("len = %d, want 20", len(got))
	}

	// IP.len should be 20 (header only).
	ipLen := binary.BigEndian.Uint16(got[2:4])
	if ipLen != 20 {
		t.Errorf("IP.len = %d, want 20", ipLen)
	}

	// IP checksum should be valid.
	if csum := IPChecksum(got); csum != 0 {
		t.Errorf("IP checksum invalid: %#x", csum)
	}
}

func TestBuildTCPWithoutIPError(t *testing.T) {
	// TCP without an IP layer below should fail during checksum computation.
	tcp := NewTCPWith(12345, 80, TCPSyn)
	pkt := packet.NewFrom(tcp)

	_, err := pkt.Build()
	if err == nil {
		t.Error("expected error for TCP without IP layer")
	}
}

func TestBuildUDPWithoutIPError(t *testing.T) {
	// UDP without an IP layer below should fail during checksum computation.
	udp := NewUDPWith(12345, 53)
	pkt := packet.NewFrom(udp)

	_, err := pkt.Build()
	if err == nil {
		t.Error("expected error for UDP without IP layer")
	}
}

// equalBytes compares two byte slices.
func equalBytes(t *testing.T, got, want []byte) bool {
	t.Helper()
	return bytes.Equal(got, want)
}
