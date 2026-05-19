package goscapy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dhcp"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/layers/dot1q"
	"github.com/smallnest/goscapy/pkg/layers/gre"
	"github.com/smallnest/goscapy/pkg/layers/vxlan"
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
	var _ LayerBuilder = NewDNS()
	var _ LayerBuilder = NewDHCP()
	var _ LayerBuilder = NewIPv6()
	var _ LayerBuilder = NewICMPv6()
	var _ LayerBuilder = NewDot1Q()
	var _ LayerBuilder = NewVXLAN()
	var _ LayerBuilder = NewGRE()
}

// ---- New Builder Field Setter Tests ----

func TestBuilderDNSFieldSetters(t *testing.T) {
	q := dns.DNSQuestion{Name: "example.com", Type: dns.QtypeA, Class: dns.QclassIN}
	dnsB := NewDNS().ID(0x1234).Flags(0x0100).Questions([]dns.DNSQuestion{q})

	id, _ := dnsB.layer.Get("id")
	flags, _ := dnsB.layer.Get("flags")
	qdcount, _ := dnsB.layer.Get("qdcount")

	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	if flags.(uint16) != 0x0100 {
		t.Errorf("flags = %#x", flags)
	}
	if qdcount.(uint16) != 1 {
		t.Errorf("qdcount = %d, want 1", qdcount)
	}
}

func TestBuilderDHCPFieldSetters(t *testing.T) {
	dhcpB := NewDHCP().Op(dhcp.BOOTREQUEST).XID(0xDEADBEEF).CIAddr("10.0.0.1").YIAddr("10.0.0.2").
		SIAddr("10.0.0.3").GIAddr("10.0.0.4").MessageType(dhcp.DHCPDISCOVER)

	op, _ := dhcpB.layer.Get("op")
	xid, _ := dhcpB.layer.Get("xid")
	ciaddr, _ := dhcpB.layer.Get("ciaddr")
	yiaddr, _ := dhcpB.layer.Get("yiaddr")

	if op.(uint8) != dhcp.BOOTREQUEST {
		t.Errorf("op = %d", op)
	}
	if xid.(uint32) != 0xDEADBEEF {
		t.Errorf("xid = %#x", xid)
	}
	if ciaddr.(string) != "10.0.0.1" {
		t.Errorf("ciaddr = %v", ciaddr)
	}
	if yiaddr.(string) != "10.0.0.2" {
		t.Errorf("yiaddr = %v", yiaddr)
	}
}

func TestBuilderIPv6FieldSetters(t *testing.T) {
	ip6 := NewIPv6().SrcIP("fe80::1").DstIP("fe80::2").NH(58).HLim(255)

	src, _ := ip6.layer.Get("src")
	dst, _ := ip6.layer.Get("dst")
	nh, _ := ip6.layer.Get("nh")
	hlim, _ := ip6.layer.Get("hlim")

	if src.(string) != "fe80::1" {
		t.Errorf("src = %v", src)
	}
	if dst.(string) != "fe80::2" {
		t.Errorf("dst = %v", dst)
	}
	if nh.(uint8) != 58 {
		t.Errorf("nh = %d", nh)
	}
	if hlim.(uint8) != 255 {
		t.Errorf("hlim = %d", hlim)
	}
}

func TestBuilderIPv6TrafficClassFlowLabel(t *testing.T) {
	ip6 := NewIPv6().TC(0xAB).FL(0x12345)

	vtf, _ := ip6.layer.Get("ver_tc_fl")
	v := vtf.(uint32)

	if layers.IPv6TrafficClass(v) != 0xAB {
		t.Errorf("tc = %#x, want 0xAB", layers.IPv6TrafficClass(v))
	}
	if layers.IPv6FlowLabel(v) != 0x12345 {
		t.Errorf("fl = %#x, want 0x12345", layers.IPv6FlowLabel(v))
	}
	if layers.IPv6Version(v) != 6 {
		t.Errorf("version = %d, want 6", layers.IPv6Version(v))
	}
}

func TestBuilderICMPv6FieldSetters(t *testing.T) {
	icmp6 := NewICMPv6().Type(128).Code(0)

	itype, _ := icmp6.layer.Get("type")
	code, _ := icmp6.layer.Get("code")

	if itype.(uint8) != 128 {
		t.Errorf("type = %d", itype)
	}
	if code.(uint8) != 0 {
		t.Errorf("code = %d", code)
	}
}

func TestBuilderDot1QFieldSetters(t *testing.T) {
	dq := NewDot1Q().VID(100).PCP(5).DEI(true).Type(0x0800).TPID(dot1q.TPID8021Q)

	tci, _ := dq.layer.Get("tci")
	etype, _ := dq.layer.Get("type")
	tpid, _ := dq.layer.Get("tpid")

	if dot1q.GetVID(dq.layer) != 100 {
		t.Errorf("vid = %d", dot1q.GetVID(dq.layer))
	}
	if dot1q.GetPCP(dq.layer) != 5 {
		t.Errorf("pcp = %d", dot1q.GetPCP(dq.layer))
	}
	if !dot1q.GetDEI(dq.layer) {
		t.Error("dei should be true")
	}
	if etype.(uint16) != 0x0800 {
		t.Errorf("type = %#x", etype)
	}
	if tpid.(uint16) != dot1q.TPID8021Q {
		t.Errorf("tpid = %#x", tpid)
	}

	// Test the tci value directly: PCP=5(101) DEI=1 VID=100
	expectedTCI := uint16(5)<<13 | 0x1000 | 100
	if tci.(uint16) != expectedTCI {
		t.Errorf("tci = %#x, want %#x", tci, expectedTCI)
	}
}

func TestBuilderVXLANFieldSetters(t *testing.T) {
	vx := NewVXLAN().VNI(5000).Flags(vxlan.FlagI)

	vni, _ := vx.layer.Get("vni")
	flags, _ := vx.layer.Get("flags")

	if vni.(uint32) != 5000 {
		t.Errorf("vni = %d", vni)
	}
	if flags.(uint8) != vxlan.FlagI {
		t.Errorf("flags = %#x", flags)
	}
}

func TestBuilderGREFieldSetters(t *testing.T) {
	gr := NewGRE().ProtocolType(0x0800).Key(100).Seq(42)

	proto, _ := gr.layer.Get("proto")
	key, _ := gr.layer.Get("key")
	seq, _ := gr.layer.Get("seq")
	flagsver, _ := gr.layer.Get("flagsver")

	if proto.(uint16) != 0x0800 {
		t.Errorf("proto = %#x", proto)
	}
	if key.(uint32) != 100 {
		t.Errorf("key = %d", key)
	}
	if seq.(uint32) != 42 {
		t.Errorf("seq = %d", seq)
	}
	if flagsver.(uint16)&gre.FlagK == 0 {
		t.Error("K flag should be set")
	}
	if flagsver.(uint16)&gre.FlagS == 0 {
		t.Error("S flag should be set")
	}
}

// ---- Full Stack Builder Tests ----

func TestBuilderIPv6ICMPv6Echo(t *testing.T) {
	got, err := NewIPv6().SrcIP("fe80::1").DstIP("fe80::2").NH(58).
		Over(NewICMPv6().Type(128).Code(0)).
		Over(&rawBuilder{layers.NewICMPv6Echo(0x1234, 1)}).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// IPv6(40) + ICMPv6(4) + Echo(4) = 48 bytes
	if len(got) != 48 {
		t.Fatalf("len = %d, want 48", len(got))
	}

	// Verify IPv6 version (upper nibble of first 4 bytes).
	if got[0]>>4 != 6 {
		t.Errorf("IPv6 version = %d, want 6", got[0]>>4)
	}
	// Verify ICMPv6 type.
	if got[40] != 128 {
		t.Errorf("ICMPv6 type = %d, want 128", got[40])
	}
	// Verify Echo ID/Seq at offset 44.
	if got[44] != 0x12 || got[45] != 0x34 {
		t.Errorf("Echo ID bytes = %#v", got[44:46])
	}
}

func TestBuilderEthernetDot1QIP(t *testing.T) {
	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewDot1Q().VID(100)).
		Over(NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2")).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + Dot1Q(6) + IP(20) = 40 bytes.
	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}

	// Ethernet.type = 0x8100 (Dot1Q).
	if got[12] != 0x81 || got[13] != 0x00 {
		t.Errorf("EtherType = %#x, want 0x8100", got[12:14])
	}

	// Dot1Q: tpid=0x8100, tci=100 (VID=100), type=0x0800.
	if got[14] != 0x81 || got[15] != 0x00 {
		t.Errorf("TPID = %#x, want 0x8100", got[14:16])
	}
	tci := binary.BigEndian.Uint16(got[16:18])
	if tci != 100 {
		t.Errorf("TCI = %d, want 100", tci)
	}
	if got[18] != 0x08 || got[19] != 0x00 {
		t.Errorf("Dot1Q type = %#x, want 0x0800", got[18:20])
	}
}

func TestBuilderEthernetIPGRE(t *testing.T) {
	innerIP := []byte{
		0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0x02,
	}

	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2")).
		Over(NewGRE().ProtocolType(0x0800).Key(100)).
		Over(&rawBuilder{layers.NewRawWith(innerIP)}).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + GRE(8 with key) + innerIP(20) = 62.
	if len(got) != 62 {
		t.Fatalf("len = %d, want 62", len(got))
	}

	// GRE at offset 34: K=1 (0x2000).
	if got[34] != 0x20 || got[35] != 0x00 {
		t.Errorf("GRE flagsver = %#x %#x", got[34], got[35])
	}
	// GRE ProtocolType.
	if got[36] != 0x08 || got[37] != 0x00 {
		t.Errorf("GRE proto = %#x %#x", got[36], got[37])
	}
	// GRE key.
	key := binary.BigEndian.Uint32(got[38:42])
	if key != 100 {
		t.Errorf("GRE key = %d, want 100", key)
	}
}

func TestBuilderEthernetIPUDPVXLAN(t *testing.T) {
	innerEth := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
	}

	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2")).
		Over(NewUDP().SrcPort(4789).DstPort(4789)).
		Over(NewVXLAN().VNI(5000)).
		Over(&rawBuilder{layers.NewRawWith(innerEth)}).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + UDP(8) + VXLAN(8) + innerEth(14) = 64.
	if len(got) != 64 {
		t.Fatalf("len = %d, want 64", len(got))
	}

	// VXLAN at offset 42: flags(0x08) + reserved1(3B=0) + vni(3B).
	if got[42] != vxlan.FlagI {
		t.Errorf("VXLAN flags = %#x", got[42])
	}
	vni := uint32(got[46])<<16 | uint32(got[47])<<8 | uint32(got[48])
	if vni != 5000 {
		t.Errorf("VXLAN VNI = %d, want 5000", vni)
	}
}

func TestBuilderEthernetIPUDPDNS(t *testing.T) {
	q := dns.DNSQuestion{Name: "example.com", Type: dns.QtypeA, Class: dns.QclassIN}

	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("10.0.0.1").DstIP("8.8.8.8")).
		Over(NewUDP().SrcPort(12345).DstPort(53)).
		Over(NewDNS().ID(0x1234).Questions([]dns.DNSQuestion{q})).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + UDP(8) + DNS(12 header + name encoded) = varies.
	// DNS: id(2) + flags(2) + qdcount(2) + ancount(2) + nscount(2) + arcount(2) + question.
	ipHdr := got[14:34]
	udpDg := got[34:42]
	dnsData := got[42:]

	// IP proto = UDP(17).
	if ipHdr[9] != 17 {
		t.Errorf("IP.proto = %d, want 17", ipHdr[9])
	}

	// UDP port = 53.
	dport := binary.BigEndian.Uint16(udpDg[2:4])
	if dport != 53 {
		t.Errorf("UDP dport = %d, want 53", dport)
	}

	// DNS id.
	dnsID := binary.BigEndian.Uint16(dnsData[0:2])
	if dnsID != 0x1234 {
		t.Errorf("DNS id = %#x", dnsID)
	}
	// DNS qdcount.
	qdc := binary.BigEndian.Uint16(dnsData[4:6])
	if qdc != 1 {
		t.Errorf("DNS qdcount = %d, want 1", qdc)
	}
}

func TestBuilderEthernetIPUDPDHCP(t *testing.T) {
	got, err := NewEthernet().
		SrcMAC("00:11:22:33:44:55").DstMAC("ff:ff:ff:ff:ff:ff").
		Over(NewIP().SrcIP("0.0.0.0").DstIP("255.255.255.255")).
		Over(NewUDP().SrcPort(68).DstPort(67)).
		Over(NewDHCP().XID(0xDEADBEEF).MessageType(dhcp.DHCPDISCOVER)).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + UDP(8) + DHCP(240 + options) = varies.
	ipHdr := got[14:34]
	udpDg := got[34:42]

	// IP proto = UDP(17).
	if ipHdr[9] != 17 {
		t.Errorf("IP.proto = %d, want 17", ipHdr[9])
	}

	// UDP ports 68→67.
	sport := binary.BigEndian.Uint16(udpDg[0:2])
	dport := binary.BigEndian.Uint16(udpDg[2:4])
	if sport != 68 || dport != 67 {
		t.Errorf("UDP ports = %d/%d, want 68/67", sport, dport)
	}
}

// ---- Shortcut Function Tests (New) ----

func TestShortcutIPv6ICMPv6Echo(t *testing.T) {
	got, err := IPv6ICMPv6Echo("fe80::1", "fe80::2", 0x1234, 1)
	if err != nil {
		t.Fatal(err)
	}

	// IPv6(40) + ICMPv6(4) + Echo(4) = 48 bytes
	if len(got) != 48 {
		t.Fatalf("len = %d, want 48", len(got))
	}

	// IPv6 version.
	if got[0]>>4 != 6 {
		t.Errorf("IPv6 version = %d, want 6", got[0]>>4)
	}

	// ICMPv6 type = 128 (Echo Request).
	if got[40] != 128 {
		t.Errorf("ICMPv6 type = %d, want 128", got[40])
	}
}

func TestShortcutEtherDot1QIP(t *testing.T) {
	got, err := EtherDot1QIP("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "10.0.0.1", "10.0.0.2", 100)
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + Dot1Q(6) + IP(20) = 40 bytes.
	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}

	// Ethernet.type = 0x8100.
	if got[12] != 0x81 || got[13] != 0x00 {
		t.Errorf("EtherType = %#x", got[12:14])
	}

	// Dot1Q TCI = 100.
	tci := binary.BigEndian.Uint16(got[16:18])
	if tci != 100 {
		t.Errorf("Dot1Q TCI = %d, want 100", tci)
	}
}

func TestShortcutEtherIPUDPVXLAN(t *testing.T) {
	innerPayload := []byte("hello")
	got, err := EtherIPUDPVXLAN("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "10.0.0.1", "10.0.0.2", 5000, innerPayload)
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + UDP(8) + VXLAN(8) + payload(5) = 55.
	if len(got) != 55 {
		t.Fatalf("len = %d, want 55", len(got))
	}

	// VXLAN VNI at offset 45-47.
	vni := uint32(got[46])<<16 | uint32(got[47])<<8 | uint32(got[48])
	if vni != 5000 {
		t.Errorf("VNI = %d, want 5000", vni)
	}

	// Payload at end.
	if !bytes.Equal(got[50:], innerPayload) {
		t.Errorf("payload = %s", got[50:])
	}
}

func TestShortcutEtherIPGRE(t *testing.T) {
	innerPayload := []byte{0x45, 0x00, 0x00, 0x14}
	got, err := EtherIPGRE("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "10.0.0.1", "10.0.0.2", 0x0800, 100, innerPayload)
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + GRE(8 with key) + payload(4) = 46.
	if len(got) != 46 {
		t.Fatalf("len = %d, want 46", len(got))
	}

	// GRE at offset 34: K=1.
	if got[34]&0x20 == 0 {
		t.Error("GRE K flag should be set")
	}
	// GRE key.
	key := binary.BigEndian.Uint32(got[38:42])
	if key != 100 {
		t.Errorf("GRE key = %d, want 100", key)
	}
}

func TestShortcutEtherIPGREWithoutKey(t *testing.T) {
	innerPayload := []byte{0x45, 0x00, 0x00, 0x14}
	got, err := EtherIPGRE("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "10.0.0.1", "10.0.0.2", 0x0800, 0, innerPayload)
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + GRE(4 base) + payload(4) = 42.
	if len(got) != 42 {
		t.Fatalf("len = %d, want 42", len(got))
	}

	// GRE at offset 34: no flags.
	if got[34] != 0x00 {
		t.Errorf("GRE flagsver = %#x, want 0x00", got[34])
	}
}

func TestShortcutEtherIPUDPDNS(t *testing.T) {
	q := dns.DNSQuestion{Name: "example.com", Type: dns.QtypeA, Class: dns.QclassIN}
	got, err := EtherIPUDPDNS("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "10.0.0.1", "8.8.8.8", 53, []dns.DNSQuestion{q})
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + UDP(8) + DNS(12 + name) = at least 54.
	if len(got) < 54 {
		t.Fatalf("len = %d, want at least 54", len(got))
	}

	// Verify UDP port 53.
	dport := binary.BigEndian.Uint16(got[36:38])
	if dport != 53 {
		t.Errorf("UDP dport = %d, want 53", dport)
	}
}

func TestShortcutEtherIPUDPDHCP(t *testing.T) {
	got, err := EtherIPUDPDHCP("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", 0xDEADBEEF, dhcp.DHCPDISCOVER)
	if err != nil {
		t.Fatal(err)
	}

	// Eth(14) + IP(20) + UDP(8) + DHCP(240 + options) = at least 282.
	if len(got) < 282 {
		t.Fatalf("len = %d, want at least 282", len(got))
	}

	// Verify broadcast IP.
	dstIP := got[30:34]
	if !bytes.Equal(dstIP, []byte{255, 255, 255, 255}) {
		t.Errorf("dst IP = %v, want 255.255.255.255", dstIP)
	}

	// Verify UDP ports 68→67.
	sport := binary.BigEndian.Uint16(got[34:36])
	dport := binary.BigEndian.Uint16(got[36:38])
	if sport != 68 || dport != 67 {
		t.Errorf("UDP ports = %d/%d, want 68/67", sport, dport)
	}
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
