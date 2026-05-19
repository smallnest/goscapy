package layers

import (
	"fmt"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers/dot1q"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ethernetStartFn identifies raw bytes as starting with an Ethernet frame.
// Ethernet always starts with 6+6+2 bytes, so we just need the minimum size.
func ethernetStartFn(raw []byte) (string, error) {
	if len(raw) < 14 {
		return "", errTooShort("Ethernet", 14, len(raw))
	}
	return "Ethernet", nil
}

// errTooShort creates a descriptive error for short packets.
func errTooShort(proto string, need, got int) error {
	return fmt.Errorf("layers: %s needs at least %d bytes, got %d", proto, need, got)
}

func TestDissectEthernetIPICMP(t *testing.T) {
	// Same bytes as TestBuildEthernetIPICMP produces.
	raw := []byte{
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

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	// Verify 3 layers: Ethernet, IP, ICMP.
	if pkt.Len() != 3 {
		t.Fatalf("packet layers = %d, want 3", pkt.Len())
	}

	// Ethernet layer.
	eth := pkt.GetLayer("Ethernet")
	if eth == nil {
		t.Fatal("missing Ethernet layer")
	}
	dst, _ := eth.Get("dst")
	if mac := dst.(net.HardwareAddr); mac.String() != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("Ethernet.dst = %v, want ff:ff:ff:ff:ff:ff", mac)
	}
	src, _ := eth.Get("src")
	if mac := src.(net.HardwareAddr); mac.String() != "00:11:22:33:44:55" {
		t.Errorf("Ethernet.src = %v, want 00:11:22:33:44:55", mac)
	}
	etype, _ := eth.Get("type")
	if etype.(uint16) != 0x0800 {
		t.Errorf("Ethernet.type = %#x, want 0x0800", etype)
	}

	// IP layer.
	ip := pkt.GetLayer("IP")
	if ip == nil {
		t.Fatal("missing IP layer")
	}
	verihl, _ := ip.Get("verihl")
	if verihl.(uint8) != 0x45 {
		t.Errorf("IP.verihl = %#x, want 0x45", verihl)
	}
	ipLen, _ := ip.Get("len")
	if ipLen.(uint16) != 28 {
		t.Errorf("IP.len = %d, want 28", ipLen)
	}
	ttl, _ := ip.Get("ttl")
	if ttl.(uint8) != 64 {
		t.Errorf("IP.ttl = %d, want 64", ttl)
	}
	proto, _ := ip.Get("proto")
	if proto.(uint8) != 1 {
		t.Errorf("IP.proto = %d, want 1 (ICMP)", proto)
	}
	ipSrc, _ := ip.Get("src")
	if ip := ipSrc.(net.IP); !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP.src = %v, want 10.0.0.1", ip)
	}
	ipDst, _ := ip.Get("dst")
	if ip := ipDst.(net.IP); !ip.Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("IP.dst = %v, want 10.0.0.2", ip)
	}

	// ICMP layer.
	icmp := pkt.GetLayer("ICMP")
	if icmp == nil {
		t.Fatal("missing ICMP layer")
	}
	itype, _ := icmp.Get("type")
	if itype.(uint8) != 8 {
		t.Errorf("ICMP.type = %d, want 8", itype)
	}
	code, _ := icmp.Get("code")
	if code.(uint8) != 0 {
		t.Errorf("ICMP.code = %d, want 0", code)
	}
	chksum, _ := icmp.Get("chksum")
	if chksum.(uint16) != 0xe5ca {
		t.Errorf("ICMP.chksum = %#x, want 0xe5ca", chksum)
	}
	id, _ := icmp.Get("id")
	if id.(uint16) != 0x1234 {
		t.Errorf("ICMP.id = %#x, want 0x1234", id)
	}
	seq, _ := icmp.Get("seq")
	if seq.(uint16) != 1 {
		t.Errorf("ICMP.seq = %d, want 1", seq)
	}
}

func TestDissectEthernetIPTCPRaw(t *testing.T) {
	// Same bytes as TestBuildEthernetIPTCPRaw produces.
	raw := []byte{
		// Ethernet (14 bytes)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP (20 bytes)
		0x45, 0x00, 0x00, 0x2d,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x06, 0xa9, 0x12,
		0xc0, 0xa8, 0x01, 0x01,
		0x08, 0x08, 0x08, 0x08,
		// TCP (20 bytes)
		0x30, 0x39, 0x00, 0x50,
		0x00, 0x00, 0x03, 0xe8,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x20, 0x00,
		0x45, 0xe1, 0x00, 0x00,
		// Raw (5 bytes): "hello"
		0x68, 0x65, 0x6c, 0x6c, 0x6f,
	}

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	// Verify 4 layers: Ethernet, IP, TCP, Raw.
	if pkt.Len() != 4 {
		t.Fatalf("packet layers = %d, want 4", pkt.Len())
	}

	// IP layer checks.
	ip := pkt.GetLayer("IP")
	if ip == nil {
		t.Fatal("missing IP layer")
	}
	ipSrc, _ := ip.Get("src")
	if ip := ipSrc.(net.IP); !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("IP.src = %v, want 192.168.1.1", ip)
	}
	ipDst, _ := ip.Get("dst")
	if ip := ipDst.(net.IP); !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("IP.dst = %v, want 8.8.8.8", ip)
	}
	proto, _ := ip.Get("proto")
	if proto.(uint8) != 6 {
		t.Errorf("IP.proto = %d, want 6 (TCP)", proto)
	}

	// TCP layer checks.
	tcp := pkt.GetLayer("TCP")
	if tcp == nil {
		t.Fatal("missing TCP layer")
	}
	sport, _ := tcp.Get("sport")
	if sport.(uint16) != 12345 {
		t.Errorf("TCP.sport = %d, want 12345", sport)
	}
	dport, _ := tcp.Get("dport")
	if dport.(uint16) != 80 {
		t.Errorf("TCP.dport = %d, want 80", dport)
	}
	seq, _ := tcp.Get("seq")
	if seq.(uint32) != 1000 {
		t.Errorf("TCP.seq = %d, want 1000", seq)
	}
	dataofs, _ := tcp.Get("dataofs")
	if dataofs.(uint8) != 0x50 {
		t.Errorf("TCP.dataofs = %#x, want 0x50", dataofs)
	}
	flags, _ := tcp.Get("flags")
	if flags.(uint8) != TCPSyn {
		t.Errorf("TCP.flags = %#x, want 0x02 (SYN)", flags)
	}
	window, _ := tcp.Get("window")
	if window.(uint16) != 8192 {
		t.Errorf("TCP.window = %d, want 8192", window)
	}

	// Raw layer checks.
	rawLayer := pkt.GetLayer("Raw")
	if rawLayer == nil {
		t.Fatal("missing Raw layer")
	}
	load, _ := rawLayer.Get("load")
	loadBytes, ok := load.([]byte)
	if !ok {
		t.Fatalf("Raw.load type = %T, want []byte", load)
	}
	if string(loadBytes) != "hello" {
		t.Errorf("Raw.load = %q, want \"hello\"", string(loadBytes))
	}
}

func TestDissectEthernetIPUDPRaw(t *testing.T) {
	// Same bytes as TestBuildEthernetIPUDPRaw produces.
	raw := []byte{
		// Ethernet (14 bytes)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP (20 bytes)
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0xa9, 0x14,
		0xc0, 0xa8, 0x01, 0x01,
		0x08, 0x08, 0x08, 0x08,
		// UDP (8 bytes)
		0x30, 0x39, 0x00, 0x35,
		0x00, 0x0c, 0x15, 0xd5,
		// Raw (4 bytes): "test"
		0x74, 0x65, 0x73, 0x74,
	}

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	// Verify 4 layers: Ethernet, IP, UDP, Raw.
	if pkt.Len() != 4 {
		t.Fatalf("packet layers = %d, want 4", pkt.Len())
	}

	// UDP layer checks.
	udp := pkt.GetLayer("UDP")
	if udp == nil {
		t.Fatal("missing UDP layer")
	}
	sport, _ := udp.Get("sport")
	if sport.(uint16) != 12345 {
		t.Errorf("UDP.sport = %d, want 12345", sport)
	}
	dport, _ := udp.Get("dport")
	if dport.(uint16) != 53 {
		t.Errorf("UDP.dport = %d, want 53", dport)
	}
	udpLen, _ := udp.Get("len")
	if udpLen.(uint16) != 12 {
		t.Errorf("UDP.len = %d, want 12", udpLen)
	}

	// Raw layer checks.
	rawLayer := pkt.GetLayer("Raw")
	if rawLayer == nil {
		t.Fatal("missing Raw layer")
	}
	load, _ := rawLayer.Get("load")
	loadBytes, ok := load.([]byte)
	if !ok {
		t.Fatalf("Raw.load type = %T, want []byte", load)
	}
	if string(loadBytes) != "test" {
		t.Errorf("Raw.load = %q, want \"test\"", string(loadBytes))
	}
}

func TestDissectEthernetARP(t *testing.T) {
	// Same bytes as TestBuildEthernetARP produces.
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x06,
		// ARP (28 bytes)
		0x00, 0x01,
		0x08, 0x00,
		0x06,
		0x04,
		0x00, 0x01,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xc0, 0xa8, 0x01, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0xa8, 0x01, 0x64,
	}

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	// Verify 2 layers: Ethernet, ARP.
	if pkt.Len() != 2 {
		t.Fatalf("packet layers = %d, want 2", pkt.Len())
	}

	// Ethernet layer.
	eth := pkt.GetLayer("Ethernet")
	if eth == nil {
		t.Fatal("missing Ethernet layer")
	}
	etype, _ := eth.Get("type")
	if etype.(uint16) != 0x0806 {
		t.Errorf("Ethernet.type = %#x, want 0x0806 (ARP)", etype)
	}

	// ARP layer.
	arp := pkt.GetLayer("ARP")
	if arp == nil {
		t.Fatal("missing ARP layer")
	}
	hwtype, _ := arp.Get("hwtype")
	if hwtype.(uint16) != 1 {
		t.Errorf("ARP.hwtype = %d, want 1", hwtype)
	}
	op, _ := arp.Get("op")
	if op.(uint16) != ARPWhoHas {
		t.Errorf("ARP.op = %d, want 1 (WHO-HAS)", op)
	}
	hwsrc, _ := arp.Get("hwsrc")
	if mac := hwsrc.(net.HardwareAddr); mac.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ARP.hwsrc = %v, want aa:bb:cc:dd:ee:ff", mac)
	}
	psrc, _ := arp.Get("psrc")
	if ip := psrc.(net.IP); !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("ARP.psrc = %v, want 192.168.1.1", ip)
	}
	pdst, _ := arp.Get("pdst")
	if ip := pdst.(net.IP); !ip.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("ARP.pdst = %v, want 192.168.1.100", ip)
	}
}

func TestDissectEmptyInput(t *testing.T) {
	_, err := packet.Dissect([]byte{}, ethernetStartFn)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestDissectNilStartFn(t *testing.T) {
	_, err := packet.Dissect([]byte{0x00}, nil)
	if err == nil {
		t.Fatal("expected error for nil startFn")
	}
}

func TestDissectTooShortEthernet(t *testing.T) {
	_, err := packet.Dissect([]byte{0x01, 0x02}, ethernetStartFn)
	if err == nil {
		t.Fatal("expected error for too-short Ethernet frame")
	}
}

func TestDissectUnknownEtherType(t *testing.T) {
	// Ethernet frame with unknown EtherType — should parse only Ethernet layer
	// and wrap the rest as Raw.
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x99, 0x99, // unknown EtherType
		0x01, 0x02, 0x03, 0x04, // some payload
	}

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 2 layers: Ethernet + Raw.
	if pkt.Len() != 2 {
		t.Fatalf("packet layers = %d, want 2", pkt.Len())
	}

	if !pkt.HasLayer("Ethernet") {
		t.Error("missing Ethernet layer")
	}
	if !pkt.HasLayer("Raw") {
		t.Error("missing Raw layer (for unknown EtherType payload)")
	}

	eth := pkt.GetLayer("Ethernet")
	etype, _ := eth.Get("type")
	if etype.(uint16) != 0x9999 {
		t.Errorf("Ethernet.type = %#x, want 0x9999", etype)
	}
}

func TestDissectUnknownIPProto(t *testing.T) {
	// IP with unknown protocol number — should parse Ethernet + IP, rest as Raw.
	raw := []byte{
		// Ethernet (14 bytes)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP (20 bytes): proto=99 (unknown)
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x63, 0x00, 0x00, // proto=0x63=99, checksum=0 (invalid but ok for parsing)
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		// payload (8 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 3 layers: Ethernet + IP + Raw.
	if pkt.Len() != 3 {
		t.Fatalf("packet layers = %d, want 3", pkt.Len())
	}

	if !pkt.HasLayer("Ethernet") {
		t.Error("missing Ethernet layer")
	}
	if !pkt.HasLayer("IP") {
		t.Error("missing IP layer")
	}
	if !pkt.HasLayer("Raw") {
		t.Error("missing Raw layer (for unknown IP proto payload)")
	}

	ip := pkt.GetLayer("IP")
	proto, _ := ip.Get("proto")
	if proto.(uint8) != 99 {
		t.Errorf("IP.proto = %d, want 99", proto)
	}
}

func TestDissectEthernetOnly(t *testing.T) {
	// Only an Ethernet header, no payload.
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
	}

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	if pkt.Len() != 1 {
		t.Fatalf("packet layers = %d, want 1", pkt.Len())
	}
	if !pkt.HasLayer("Ethernet") {
		t.Error("missing Ethernet layer")
	}
}

func TestDissectRoundTripEthernetIPICMP(t *testing.T) {
	// Build a packet, serialize it, then Dissect it back and verify field values match.
	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	ip := NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")
	icmp := NewICMPEcho(0xABCD, 42)

	pkt := eth.Over(ip)
	pkt.Push(icmp)

	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Dissect the built bytes.
	parsed, err := packet.Dissect(built, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Len() != 3 {
		t.Fatalf("parsed layers = %d, want 3", parsed.Len())
	}

	// Verify ICMP fields round-trip correctly.
	parsedICMP := parsed.GetLayer("ICMP")
	parsedType, _ := parsedICMP.Get("type")
	if parsedType.(uint8) != ICMPEchoRequest {
		t.Errorf("ICMP.type = %d, want 8", parsedType)
	}
	parsedID, _ := parsedICMP.Get("id")
	if parsedID.(uint16) != 0xABCD {
		t.Errorf("ICMP.id = %#x, want 0xABCD", parsedID)
	}
	parsedSeq, _ := parsedICMP.Get("seq")
	if parsedSeq.(uint16) != 42 {
		t.Errorf("ICMP.seq = %d, want 42", parsedSeq)
	}

	// Verify IP checksum is correct.
	ipLayer := parsed.GetLayer("IP")
	chksum, _ := ipLayer.Get("chksum")
	hdr, _ := ipLayer.SerializeFields()
	// Zero the checksum for verification.
	hdr[10] = 0
	hdr[11] = 0
	// We need to verify by building a proper header.
	// The parsed checksum should verify.
	parsedChksum := chksum.(uint16)
	// Verify by building the header with zero checksum and computing.
	verifyIP := NewIP()
	ipSrc, _ := ipLayer.Get("src")
	ipDst, _ := ipLayer.Get("dst")
	verifyIP.Set("src", ipSrc)
	verifyIP.Set("dst", ipDst)
	verihl, _ := ipLayer.Get("verihl")
	verifyIP.Set("verihl", verihl)
	tos, _ := ipLayer.Get("tos")
	verifyIP.Set("tos", tos)
	ipLenField, _ := ipLayer.Get("len")
	verifyIP.Set("len", ipLenField)
	id, _ := ipLayer.Get("id")
	verifyIP.Set("id", id)
	frag, _ := ipLayer.Get("frag")
	verifyIP.Set("frag", frag)
	ttlVal, _ := ipLayer.Get("ttl")
	verifyIP.Set("ttl", ttlVal)
	protoVal, _ := ipLayer.Get("proto")
	verifyIP.Set("proto", protoVal)
	verifyIP.Set("chksum", uint16(0))
	verifyHdr, _ := verifyIP.SerializeFields()
	computed := IPChecksum(verifyHdr)
	if computed != parsedChksum {
		t.Errorf("IP checksum mismatch: parsed=%#x, computed=%#x", parsedChksum, computed)
	}
}

func TestDissectRoundTripEthernetIPTCPRaw(t *testing.T) {
	// Build Ether/IP/TCP/Raw, serialize, dissect, verify.
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

	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := packet.Dissect(built, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Len() != 4 {
		t.Fatalf("parsed layers = %d, want 4", parsed.Len())
	}

	// Verify TCP fields.
	parsedTCP := parsed.GetLayer("TCP")
	sport, _ := parsedTCP.Get("sport")
	if sport.(uint16) != 12345 {
		t.Errorf("TCP.sport = %d, want 12345", sport)
	}
	dport, _ := parsedTCP.Get("dport")
	if dport.(uint16) != 80 {
		t.Errorf("TCP.dport = %d, want 80", dport)
	}
	parsedSeq, _ := parsedTCP.Get("seq")
	if parsedSeq.(uint32) != 1000 {
		t.Errorf("TCP.seq = %d, want 1000", parsedSeq)
	}
	parsedFlags, _ := parsedTCP.Get("flags")
	if parsedFlags.(uint8) != TCPSyn {
		t.Errorf("TCP.flags = %#x, want 0x02 (SYN)", parsedFlags)
	}

	// Verify Raw payload.
	parsedRaw := parsed.GetLayer("Raw")
	load, _ := parsedRaw.Get("load")
	loadBytes := load.([]byte)
	if string(loadBytes) != "hello" {
		t.Errorf("Raw.load = %q, want \"hello\"", string(loadBytes))
	}
}

func TestDissectRoundTripEthernetIPUDPRaw(t *testing.T) {
	// Build Ether/IP/UDP/Raw, serialize, dissect, verify.
	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	ip := NewIP()
	ip.Set("src", "192.168.1.1")
	ip.Set("dst", "8.8.8.8")

	udp := NewUDPWith(12345, 53)
	raw := NewRawWith([]byte("test"))

	pkt := eth.Over(ip)
	pkt.Push(udp)
	pkt.Push(raw)

	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := packet.Dissect(built, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Len() != 4 {
		t.Fatalf("parsed layers = %d, want 4", parsed.Len())
	}

	// Verify UDP fields.
	parsedUDP := parsed.GetLayer("UDP")
	sport, _ := parsedUDP.Get("sport")
	if sport.(uint16) != 12345 {
		t.Errorf("UDP.sport = %d, want 12345", sport)
	}
	dport, _ := parsedUDP.Get("dport")
	if dport.(uint16) != 53 {
		t.Errorf("UDP.dport = %d, want 53", dport)
	}
	udpLen, _ := parsedUDP.Get("len")
	if udpLen.(uint16) != 12 {
		t.Errorf("UDP.len = %d, want 12", udpLen)
	}

	// Verify Raw payload.
	parsedRaw := parsed.GetLayer("Raw")
	load, _ := parsedRaw.Get("load")
	loadBytes := load.([]byte)
	if string(loadBytes) != "test" {
		t.Errorf("Raw.load = %q, want \"test\"", string(loadBytes))
	}
}

func TestDissectRoundTripEthernetARP(t *testing.T) {
	// Build Ether/ARP, serialize, dissect, verify.
	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", 0)
	arp := NewARP()
	arp.Set("hwsrc", "aa:bb:cc:dd:ee:ff")
	arp.Set("psrc", "192.168.1.1")
	arp.Set("hwdst", "00:00:00:00:00:00")
	arp.Set("pdst", "192.168.1.100")

	pkt := eth.Over(arp)

	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := packet.Dissect(built, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Len() != 2 {
		t.Fatalf("parsed layers = %d, want 2", parsed.Len())
	}

	// Verify ARP fields.
	parsedARP := parsed.GetLayer("ARP")
	op, _ := parsedARP.Get("op")
	if op.(uint16) != ARPWhoHas {
		t.Errorf("ARP.op = %d, want 1 (WHO-HAS)", op)
	}
	hwsrc, _ := parsedARP.Get("hwsrc")
	if mac := hwsrc.(net.HardwareAddr); mac.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ARP.hwsrc = %v, want aa:bb:cc:dd:ee:ff", mac)
	}
	psrc, _ := parsedARP.Get("psrc")
	if ip := psrc.(net.IP); !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("ARP.psrc = %v, want 192.168.1.1", ip)
	}
	pdst, _ := parsedARP.Get("pdst")
	if ip := pdst.(net.IP); !ip.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("ARP.pdst = %v, want 192.168.1.100", ip)
	}
}

func TestDissectLayerOrder(t *testing.T) {
	// Verify that layers are stacked in correct order (lowest first).
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, // proto=1 (ICMP), checksum=0
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		0x08, 0x00, 0x00, 0x00, // ICMP
		0x00, 0x01, 0x00, 0x01,
	}

	pkt, err := packet.Dissect(raw, ethernetStartFn)
	if err != nil {
		t.Fatal(err)
	}

	layers := pkt.Layers()
	if layers[0].Proto() != "Ethernet" {
		t.Errorf("layer 0 = %s, want Ethernet", layers[0].Proto())
	}
	if layers[1].Proto() != "IP" {
		t.Errorf("layer 1 = %s, want IP", layers[1].Proto())
	}
	if layers[2].Proto() != "ICMP" {
		t.Errorf("layer 2 = %s, want ICMP", layers[2].Proto())
	}

	// String() representation should match.
	s := pkt.String()
	if s != "Ethernet / IP / ICMP" {
		t.Errorf("String() = %q, want \"Ethernet / IP / ICMP\"", s)
	}
}

func TestDissectErrorInField(t *testing.T) {
	// Feed a truncated packet where IP header can't be fully parsed.
	raw := []byte{
		// Ethernet (14 bytes) — valid
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IP — truncated (only 10 bytes instead of 20)
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x01,
	}

	_, err := packet.Dissect(raw, ethernetStartFn)
	if err == nil {
		t.Fatal("expected error for truncated IP header")
	}
}

func TestDissectDot1Q(t *testing.T) {
	// Dissect Dot1Q(vlan=100, pcp=3) / IP / ICMP.
	// Dot1Q is 6 bytes: tpid(2) + tci(2) + type(2).
	raw := []byte{
		// Dot1Q (6 bytes)
		0x81, 0x00, 0x60, 0x64, 0x08, 0x00, // TPID=0x8100, TCI=PCP=3,VID=100, type=0x0800
		// IP (20 bytes): len=28, proto=1
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
		// ICMP (8 bytes)
		0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01,
	}

	pkt, err := packet.DissectByProto(raw, "Dot1Q")
	if err != nil {
		t.Fatal(err)
	}

	if !pkt.HasLayer("Dot1Q") {
		t.Fatal("Dot1Q layer not found")
	}
	if !pkt.HasLayer("IP") {
		t.Fatal("IP layer not found")
	}
	if !pkt.HasLayer("ICMP") {
		t.Fatal("ICMP layer not found")
	}

	dot1qLayer := pkt.GetLayer("Dot1Q")
	if dot1q.GetVID(dot1qLayer) != 100 {
		t.Errorf("VID = %d", dot1q.GetVID(dot1qLayer))
	}
	if dot1q.GetPCP(dot1qLayer) != 3 {
		t.Errorf("PCP = %d", dot1q.GetPCP(dot1qLayer))
	}
}

func TestDissectQinQ(t *testing.T) {
	// Dissect QinQ: outer(0x88A8, vid=200) / inner(0x8100, vid=100) / IP.
	// Each Dot1Q is 6 bytes: tpid(2) + tci(2) + type(2).
	raw := []byte{
		// Outer Dot1Q (6 bytes)
		0x88, 0xA8, 0x00, 0xC8, 0x81, 0x00, // TPID=0x88A8, TCI=VID=200, type=0x8100
		// Inner Dot1Q (6 bytes)
		0x81, 0x00, 0x00, 0x64, 0x08, 0x00, // TPID=0x8100, TCI=VID=100, type=0x0800
		// IP (20 bytes)
		0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
	}

	pkt, err := packet.DissectByProto(raw, "Dot1Q")
	if err != nil {
		t.Fatal(err)
	}

	layers := pkt.Layers()
	if len(layers) < 3 {
		t.Fatalf("expected at least 3 layers, got %d: %v", len(layers), pkt.String())
	}

	if layers[0].Proto() != "Dot1Q" {
		t.Errorf("layer 0 = %s, want Dot1Q", layers[0].Proto())
	}
	if layers[1].Proto() != "Dot1Q" {
		t.Errorf("layer 1 = %s, want Dot1Q", layers[1].Proto())
	}
	if layers[2].Proto() != "IP" {
		t.Errorf("layer 2 = %s, want IP", layers[2].Proto())
	}

	outer := layers[0]
	if dot1q.GetVID(outer) != 200 {
		t.Errorf("outer VID = %d, want 200", dot1q.GetVID(outer))
	}
	tpid, _ := outer.Get("tpid")
	if tpid.(uint16) != 0x88A8 {
		t.Errorf("outer TPID = %#x", tpid)
	}

	inner := layers[1]
	if dot1q.GetVID(inner) != 100 {
		t.Errorf("inner VID = %d, want 100", dot1q.GetVID(inner))
	}
	tpid2, _ := inner.Get("tpid")
	if tpid2.(uint16) != 0x8100 {
		t.Errorf("inner TPID = %#x", tpid2)
	}
}
