package goscapy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
)

// ---- Builder API Tests ----

func TestBuilderEthernetIPICMP(t *testing.T) {
	// goscapy.NewEthernet().DstMAC("ff:ff:ff:ff:ff:ff").
	//     Over(goscapy.NewIP().DstIP("8.8.8.8")).
	//     Over(goscapy.NewICMP().Type(8)).
	//     Build()
	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2")).
		Over(NewICMP().Type(8).Code(0).ID(0x1234).Seq(1)).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		// Ethernet (14 bytes)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP (20 bytes)
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x66, 0xdf,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		// ICMP (8 bytes)
		0x08, 0x00, 0xe5, 0xca,
		0x12, 0x34, 0x00, 0x01,
	}

	if len(got) != 42 {
		t.Fatalf("len = %d, want 42", len(got))
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestBuilderEthernetIPTCP(t *testing.T) {
	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("192.168.1.1").DstIP("8.8.8.8")).
		Over(NewTCP().SrcPort(12345).DstPort(80).Flags(layers.TCPSyn).Seq(1000)).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// 14 (Ethernet) + 20 (IP) + 20 (TCP) = 54 bytes.
	if len(got) != 54 {
		t.Fatalf("len = %d, want 54", len(got))
	}

	// Verify key fields without hardcoding checksums.
	ipHdr := got[14:34]
	tcpSeg := got[34:]

	// IP fields.
	if ipHdr[0] != 0x45 {
		t.Errorf("IP verihl = %#x, want 0x45", ipHdr[0])
	}
	if ipHdr[9] != 6 {
		t.Errorf("IP proto = %d, want 6", ipHdr[9])
	}

	// TCP fields.
	sport := binary.BigEndian.Uint16(tcpSeg[0:2])
	dport := binary.BigEndian.Uint16(tcpSeg[2:4])
	if sport != 12345 || dport != 80 {
		t.Errorf("TCP ports = %d/%d, want 12345/80", sport, dport)
	}
	if tcpSeg[13] != layers.TCPSyn {
		t.Errorf("TCP flags = %#x, want %#x", tcpSeg[13], layers.TCPSyn)
	}

	// Verify checksums.
	if csum := ipChecksum(ipHdr); csum != 0 {
		t.Errorf("IP checksum invalid: %#x", csum)
	}
	srcIP := ipHdr[12:16]
	dstIP := ipHdr[16:20]
	if csum := tcpChecksum(srcIP, dstIP, tcpSeg); csum != 0 {
		t.Errorf("TCP checksum invalid: %#x", csum)
	}
}

func TestBuilderEthernetIPUDP(t *testing.T) {
	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("192.168.1.1").DstIP("8.8.8.8")).
		Over(NewUDP().SrcPort(12345).DstPort(53)).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// 14 (Ethernet) + 20 (IP) + 8 (UDP) = 42 bytes.
	if len(got) != 42 {
		t.Fatalf("len = %d, want 42", len(got))
	}

	ipHdr := got[14:34]
	udpDg := got[34:]

	// IP fields.
	if ipHdr[9] != 17 {
		t.Errorf("IP proto = %d, want 17", ipHdr[9])
	}

	// UDP fields.
	sport := binary.BigEndian.Uint16(udpDg[0:2])
	dport := binary.BigEndian.Uint16(udpDg[2:4])
	if sport != 12345 || dport != 53 {
		t.Errorf("UDP ports = %d/%d, want 12345/53", sport, dport)
	}

	// Verify checksums.
	if csum := ipChecksum(ipHdr); csum != 0 {
		t.Errorf("IP checksum invalid: %#x", csum)
	}
	srcIP := ipHdr[12:16]
	dstIP := ipHdr[16:20]
	if csum := udpChecksum(srcIP, dstIP, udpDg); csum != 0 {
		t.Errorf("UDP checksum invalid: %#x", csum)
	}
}

func TestBuilderEthernetARP(t *testing.T) {
	got, err := NewEthernet().
		SrcMAC("aa:bb:cc:dd:ee:ff").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewARP().
			Op(layers.ARPWhoHas).
			SrcMAC("aa:bb:cc:dd:ee:ff").SrcIP("192.168.1.1").
			DstMAC("00:00:00:00:00:00").DstIP("192.168.1.100")).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x06,
		0x00, 0x01, 0x08, 0x00,
		0x06, 0x04,
		0x00, 0x01,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xc0, 0xa8, 0x01, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0xa8, 0x01, 0x64,
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestBuilderEtherFieldSetters(t *testing.T) {
	eth := NewEthernet().SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").Type(0x0800)

	dst, _ := eth.layer.Get("dst")
	src, _ := eth.layer.Get("src")
	etype, _ := eth.layer.Get("type")

	if dst.(string) != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("dst = %v", dst)
	}
	if src.(string) != "00:11:22:33:44:55" {
		t.Errorf("src = %v", src)
	}
	if etype.(uint16) != 0x0800 {
		t.Errorf("type = %#x", etype)
	}
}

func TestBuilderIPFieldSetters(t *testing.T) {
	ip := NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2").TTL(128).Proto(6).ID(0x1234)

	src, _ := ip.layer.Get("src")
	dst, _ := ip.layer.Get("dst")
	ttl, _ := ip.layer.Get("ttl")
	proto, _ := ip.layer.Get("proto")
	id, _ := ip.layer.Get("id")

	if src.(string) != "10.0.0.1" {
		t.Errorf("src = %v", src)
	}
	if dst.(string) != "10.0.0.2" {
		t.Errorf("dst = %v", dst)
	}
	if ttl.(uint8) != 128 {
		t.Errorf("ttl = %d", ttl)
	}
	if proto.(uint8) != 6 {
		t.Errorf("proto = %d", proto)
	}
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
}

func TestBuilderTCPFieldSetters(t *testing.T) {
	tcp := NewTCP().SrcPort(12345).DstPort(80).Flags(layers.TCPSyn | layers.TCPAck).Seq(1000).Ack(2000).Window(65535)

	sport, _ := tcp.layer.Get("sport")
	dport, _ := tcp.layer.Get("dport")
	flags, _ := tcp.layer.Get("flags")
	seq, _ := tcp.layer.Get("seq")
	ack, _ := tcp.layer.Get("ack")
	window, _ := tcp.layer.Get("window")

	if sport.(uint16) != 12345 {
		t.Errorf("sport = %d", sport)
	}
	if dport.(uint16) != 80 {
		t.Errorf("dport = %d", dport)
	}
	if flags.(uint8) != layers.TCPSyn|layers.TCPAck {
		t.Errorf("flags = %#x", flags)
	}
	if seq.(uint32) != 1000 {
		t.Errorf("seq = %d", seq)
	}
	if ack.(uint32) != 2000 {
		t.Errorf("ack = %d", ack)
	}
	if window.(uint16) != 65535 {
		t.Errorf("window = %d", window)
	}
}

func TestBuilderUDPFieldSetters(t *testing.T) {
	udp := NewUDP().SrcPort(12345).DstPort(53)

	sport, _ := udp.layer.Get("sport")
	dport, _ := udp.layer.Get("dport")

	if sport.(uint16) != 12345 {
		t.Errorf("sport = %d", sport)
	}
	if dport.(uint16) != 53 {
		t.Errorf("dport = %d", dport)
	}
}

func TestBuilderARPFieldSetters(t *testing.T) {
	arp := NewARP().Op(layers.ARPIsAt).SrcMAC("aa:bb:cc:dd:ee:ff").SrcIP("10.0.0.1").DstMAC("00:11:22:33:44:55").DstIP("10.0.0.2")

	op, _ := arp.layer.Get("op")
	hwsrc, _ := arp.layer.Get("hwsrc")
	psrc, _ := arp.layer.Get("psrc")
	hwdst, _ := arp.layer.Get("hwdst")
	pdst, _ := arp.layer.Get("pdst")

	if op.(uint16) != layers.ARPIsAt {
		t.Errorf("op = %d", op)
	}
	if hwsrc.(string) != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("hwsrc = %v", hwsrc)
	}
	if psrc.(string) != "10.0.0.1" {
		t.Errorf("psrc = %v", psrc)
	}
	if hwdst.(string) != "00:11:22:33:44:55" {
		t.Errorf("hwdst = %v", hwdst)
	}
	if pdst.(string) != "10.0.0.2" {
		t.Errorf("pdst = %v", pdst)
	}
}

func TestBuilderICMPFieldSetters(t *testing.T) {
	icmp := NewICMP().Type(8).Code(0).ID(0x1234).Seq(1)

	itype, _ := icmp.layer.Get("type")
	code, _ := icmp.layer.Get("code")
	id, _ := icmp.layer.Get("id")
	seq, _ := icmp.layer.Get("seq")

	if itype.(uint8) != 8 {
		t.Errorf("type = %d", itype)
	}
	if code.(uint8) != 0 {
		t.Errorf("code = %d", code)
	}
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	if seq.(uint16) != 1 {
		t.Errorf("seq = %d", seq)
	}
}

// ---- Shortcut Function Tests ----

func TestShortcutEtherIPICMP(t *testing.T) {
	got, err := EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
	if err != nil {
		t.Fatal(err)
	}

	// 14 (Ethernet) + 20 (IP) + 8 (ICMP) = 42 bytes
	if len(got) != 42 {
		t.Fatalf("len = %d, want 42", len(got))
	}

	// Verify Ethernet header.
	if got[0] != 0xff || got[1] != 0xff {
		t.Error("dst MAC should be broadcast")
	}
	if got[12] != 0x08 || got[13] != 0x00 {
		t.Errorf("EtherType = %x, want 0800", got[12:14])
	}

	// Verify IP header: dst = 8.8.8.8.
	dstIP := got[30:34]
	if !bytes.Equal(dstIP, []byte{8, 8, 8, 8}) {
		t.Errorf("dst IP = %v, want 8.8.8.8", dstIP)
	}

	// Verify IP.proto = 1 (ICMP).
	if got[23] != 1 {
		t.Errorf("IP.proto = %d, want 1", got[23])
	}

	// Verify ICMP type/code.
	if got[34] != 8 || got[35] != 0 {
		t.Errorf("ICMP type/code = %d/%d, want 8/0", got[34], got[35])
	}

	// Verify checksums.
	if csum := ipChecksum(got[14:34]); csum != 0 {
		t.Errorf("IP checksum invalid: %#x", csum)
	}
	if csum := icmpChecksum(got[34:]); csum != 0 {
		t.Errorf("ICMP checksum invalid: %#x", csum)
	}
}

func TestShortcutEtherIPTCP(t *testing.T) {
	got, err := EtherIPTCP("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "8.8.8.8", 12345, 80, layers.TCPSyn)
	if err != nil {
		t.Fatal(err)
	}

	// 14 + 20 + 20 = 54 bytes.
	if len(got) != 54 {
		t.Fatalf("len = %d, want 54", len(got))
	}

	// Verify TCP ports.
	sport := binary.BigEndian.Uint16(got[34:36])
	dport := binary.BigEndian.Uint16(got[36:38])
	if sport != 12345 {
		t.Errorf("sport = %d", sport)
	}
	if dport != 80 {
		t.Errorf("dport = %d", dport)
	}

	// Verify TCP flags (offset 47 = 34 + 13).
	if got[47] != layers.TCPSyn {
		t.Errorf("flags = %#x, want %#x", got[47], layers.TCPSyn)
	}
}

func TestShortcutEtherIPUDP(t *testing.T) {
	got, err := EtherIPUDP("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "8.8.8.8", 12345, 53)
	if err != nil {
		t.Fatal(err)
	}

	// 14 + 20 + 8 = 42 bytes.
	if len(got) != 42 {
		t.Fatalf("len = %d, want 42", len(got))
	}

	// Verify UDP ports.
	sport := binary.BigEndian.Uint16(got[34:36])
	dport := binary.BigEndian.Uint16(got[36:38])
	if sport != 12345 {
		t.Errorf("sport = %d", sport)
	}
	if dport != 53 {
		t.Errorf("dport = %d", dport)
	}
}

func TestShortcutEtherARP(t *testing.T) {
	got, err := EtherARP("aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "192.168.1.100", layers.ARPWhoHas)
	if err != nil {
		t.Fatal(err)
	}

	// 14 (Ethernet) + 28 (ARP) = 42 bytes.
	if len(got) != 42 {
		t.Fatalf("len = %d, want 42", len(got))
	}

	// Verify EtherType = ARP.
	if got[12] != 0x08 || got[13] != 0x06 {
		t.Errorf("EtherType = %x, want 0806", got[12:14])
	}

	// Verify ARP op = WHO-HAS (1).
	op := binary.BigEndian.Uint16(got[20:22])
	if op != layers.ARPWhoHas {
		t.Errorf("ARP op = %d, want 1", op)
	}
}

func TestShortcutIPICMP(t *testing.T) {
	got, err := IPICMP("10.0.0.1", "10.0.0.2", 8, 0)
	if err != nil {
		t.Fatal(err)
	}

	// 20 (IP) + 8 (ICMP) = 28 bytes.
	if len(got) != 28 {
		t.Fatalf("len = %d, want 28", len(got))
	}

	// Should start with IP header (version=4, ihl=5).
	if got[0] != 0x45 {
		t.Errorf("first byte = %#x, want 0x45", got[0])
	}

	// Verify ICMP type.
	if got[20] != 8 {
		t.Errorf("ICMP type = %d, want 8", got[20])
	}
}

func TestShortcutIPTCP(t *testing.T) {
	got, err := IPTCP("192.168.1.1", "8.8.8.8", 12345, 80, layers.TCPSyn)
	if err != nil {
		t.Fatal(err)
	}

	// 20 + 20 = 40 bytes.
	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}

	// Verify TCP ports.
	sport := binary.BigEndian.Uint16(got[20:22])
	dport := binary.BigEndian.Uint16(got[22:24])
	if sport != 12345 || dport != 80 {
		t.Errorf("ports = %d/%d, want 12345/80", sport, dport)
	}
}

func TestShortcutIPUDP(t *testing.T) {
	got, err := IPUDP("192.168.1.1", "8.8.8.8", 12345, 53)
	if err != nil {
		t.Fatal(err)
	}

	// 20 + 8 = 28 bytes.
	if len(got) != 28 {
		t.Fatalf("len = %d, want 28", len(got))
	}

	// Verify UDP ports.
	sport := binary.BigEndian.Uint16(got[20:22])
	dport := binary.BigEndian.Uint16(got[22:24])
	if sport != 12345 || dport != 53 {
		t.Errorf("ports = %d/%d, want 12345/53", sport, dport)
	}
}

func TestShortcutEtherIP(t *testing.T) {
	payload := []byte("hello")
	got, err := EtherIP("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "8.8.8.8", payload)
	if err != nil {
		t.Fatal(err)
	}

	// 14 + 20 + 5 = 39 bytes.
	if len(got) != 39 {
		t.Fatalf("len = %d, want 39", len(got))
	}

	// Verify payload at end.
	if !bytes.Equal(got[34:], payload) {
		t.Errorf("payload = %s, want hello", got[34:])
	}
}

// ---- Checksum verification for IPICMP shortcut ----

func TestShortcutIPICMPChecksums(t *testing.T) {
	got, err := IPICMP("10.0.0.1", "10.0.0.2", 8, 0)
	if err != nil {
		t.Fatal(err)
	}

	if csum := ipChecksum(got[0:20]); csum != 0 {
		t.Errorf("IP checksum invalid: %#x", csum)
	}
	if csum := icmpChecksum(got[20:]); csum != 0 {
		t.Errorf("ICMP checksum invalid: %#x", csum)
	}
}

// ---- Edge Cases ----

func TestBuilderEmptyLayer(t *testing.T) {
	// Building a packet with just Ethernet (no upper layers) should work.
	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").Type(0x0800).
		Over(NewIP().SrcIP("192.168.1.1").DstIP("10.0.0.1")).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// 14 (Ethernet) + 20 (IP) = 34 bytes (IP with no upper layers).
	if len(got) != 34 {
		t.Fatalf("len = %d, want 34", len(got))
	}
}

func TestBuilderPacketAccessor(t *testing.T) {
	pb := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2"))

	pkt := pb.Packet()
	if pkt == nil {
		t.Fatal("Packet() returned nil")
	}
	if pkt.Len() != 2 {
		t.Errorf("packet len = %d, want 2", pkt.Len())
	}
}

func TestBuilderLayerBuilderInterface(t *testing.T) {
	// Verify all builders implement LayerBuilder.
	var _ LayerBuilder = NewEthernet()
	var _ LayerBuilder = NewIP()
	var _ LayerBuilder = NewICMP()
	var _ LayerBuilder = NewTCP()
	var _ LayerBuilder = NewUDP()
	var _ LayerBuilder = NewARP()
}

// ---- Helpers ----

func ipChecksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func icmpChecksum(b []byte) uint16 {
	return ipChecksum(b)
}

func tcpChecksum(srcIP, dstIP, seg []byte) uint16 {
	return protoChecksum(srcIP, dstIP, 6, seg)
}

func udpChecksum(srcIP, dstIP, dg []byte) uint16 {
	csum := protoChecksum(srcIP, dstIP, 17, dg)
	// RFC 768: if computed checksum is 0, it was stored as 0xFFFF.
	// The verification result of 0xFFFF means the checksum is valid.
	if csum == 0xFFFF {
		return 0
	}
	return csum
}

func protoChecksum(srcIP, dstIP []byte, proto uint8, data []byte) uint16 {
	// Build pseudo-header: srcIP + dstIP + zero + proto + length.
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(data)))

	// Sum pseudo-header + data.
	sum := uint32(0)
	for i := 0; i < len(pseudo)-1; i += 2 {
		sum += uint32(pseudo[i])<<8 | uint32(pseudo[i+1])
	}
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}