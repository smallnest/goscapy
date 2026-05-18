package layers

import (
	"bytes"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// serializeLayer manually serializes a Layer's values using each field's Pack method.
// This is a test helper; the real Build() will live in pkg/packet (Issue #6).
func serializeLayer(t *testing.T, l *packet.Layer) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, f := range l.Fields() {
		v, err := l.Get(f.Name())
		if err != nil {
			t.Fatalf("serializeLayer: %s", err)
		}
		b, err := f.Pack(v)
		if err != nil {
			t.Fatalf("serializeLayer pack %s: %v", f.Name(), err)
		}
		buf.Write(b)
	}
	return buf.Bytes()
}

func TestEthernetDefaults(t *testing.T) {
	eth := NewEthernet()

	dst, _ := eth.Get("dst")
	src, _ := eth.Get("src")
	etype, _ := eth.Get("type")

	// MAC fields with nil HardwareAddr default: interface holds (net.HardwareAddr)(nil).
	if dst != nil {
		mac, ok := dst.(net.HardwareAddr)
		if !ok || mac != nil {
			t.Errorf("dst default = %v (%T), want nil HardwareAddr", dst, dst)
		}
	}
	if src != nil {
		mac, ok := src.(net.HardwareAddr)
		if !ok || mac != nil {
			t.Errorf("src default = %v (%T), want nil HardwareAddr", src, src)
		}
	}

	if etype.(uint16) != 0 {
		t.Errorf("type default = %#x, want 0", etype)
	}
}

func TestEthernetWith(t *testing.T) {
	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", EtherTypeIPv4)

	dst, _ := eth.Get("dst")
	src, _ := eth.Get("src")
	etype, _ := eth.Get("type")

	// Set stores values as-is (string for MAC fields); Pack converts to bytes.
	if dst.(string) != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("dst = %v", dst)
	}
	if src.(string) != "00:11:22:33:44:55" {
		t.Errorf("src = %v", src)
	}
	if etype.(uint16) != EtherTypeIPv4 {
		t.Errorf("type = %#x", etype)
	}
}

func TestEthernetSerialization(t *testing.T) {
	// Scapy: Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800)
	// Expected bytes (14 bytes):
	// ff ff ff ff ff ff 00 11 22 33 44 55 08 00
	expected := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
		0x08, 0x00, // type (IPv4)
	}

	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", EtherTypeIPv4)
	got := serializeLayer(t, eth)

	if len(got) != 14 {
		t.Fatalf("serialized len = %d, want 14", len(got))
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("Ethernet serialization mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestEthernetARPSerialization(t *testing.T) {
	// Scapy: Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff", type=0x0806)
	// Expected: ff ff ff ff ff ff aa bb cc dd ee ff 08 06
	expected := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x06,
	}

	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", EtherTypeARP)
	got := serializeLayer(t, eth)

	if !bytes.Equal(got, expected) {
		t.Errorf("Ethernet ARP serialization mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestARPDefaults(t *testing.T) {
	arp := NewARP()

	hwtype, _ := arp.Get("hwtype")
	ptype, _ := arp.Get("ptype")
	hwlen, _ := arp.Get("hwlen")
	plen, _ := arp.Get("plen")
	op, _ := arp.Get("op")
	hwsrc, _ := arp.Get("hwsrc")
	psrc, _ := arp.Get("psrc")
	hwdst, _ := arp.Get("hwdst")
	pdst, _ := arp.Get("pdst")

	if hwtype.(uint16) != ARPHwEthernet {
		t.Errorf("hwtype = %d, want 1", hwtype)
	}
	if ptype.(uint16) != EtherTypeIPv4 {
		t.Errorf("ptype = %#x", ptype)
	}
	if hwlen.(uint8) != 6 {
		t.Errorf("hwlen = %d, want 6", hwlen)
	}
	if plen.(uint8) != 4 {
		t.Errorf("plen = %d, want 4", plen)
	}
	if op.(uint16) != ARPWhoHas {
		t.Errorf("op = %d, want 1 (WHO-HAS)", op)
	}

	// MAC fields with nil HardwareAddr default: stored as net.HardwareAddr(nil).
	if mac, ok := hwsrc.(net.HardwareAddr); !ok || mac != nil {
		t.Errorf("hwsrc = %v (%T), want nil HardwareAddr", hwsrc, hwsrc)
	}
	if ip, ok := psrc.(net.IP); !ok || ip != nil {
		t.Errorf("psrc = %v (%T), want nil IP", psrc, psrc)
	}
	if mac, ok := hwdst.(net.HardwareAddr); !ok || mac != nil {
		t.Errorf("hwdst = %v (%T), want nil HardwareAddr", hwdst, hwdst)
	}
	if ip, ok := pdst.(net.IP); !ok || ip != nil {
		t.Errorf("pdst = %v (%T), want nil IP", pdst, pdst)
	}
}

func TestARPSerialization(t *testing.T) {
	// Scapy: ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.1",
	//            hwdst="00:00:00:00:00:00", pdst="192.168.1.100")
	// Expected bytes (28 bytes):
	// 00 01 08 00 06 04 00 01
	// 00 11 22 33 44 55 (hwsrc)
	// c0 a8 01 01 (psrc)
	// 00 00 00 00 00 00 (hwdst)
	// c0 a8 01 64 (pdst)
	expected := []byte{
		0x00, 0x01, // hwtype (Ethernet)
		0x08, 0x00, // ptype (IPv4)
		0x06, // hwlen (6)
		0x04, // plen (4)
		0x00, 0x01, // op (WHO-HAS / request)
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // hwsrc MAC
		0xc0, 0xa8, 0x01, 0x01, // psrc IP 192.168.1.1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hwdst MAC (zero)
		0xc0, 0xa8, 0x01, 0x64, // pdst IP 192.168.1.100
	}

	arp := NewARP()
	arp.Set("hwsrc", "00:11:22:33:44:55")
	arp.Set("psrc", "192.168.1.1")
	arp.Set("hwdst", "00:00:00:00:00:00")
	arp.Set("pdst", "192.168.1.100")

	got := serializeLayer(t, arp)

	if len(got) != 28 {
		t.Fatalf("serialized len = %d, want 28", len(got))
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("ARP serialization mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestARPReplySerialization(t *testing.T) {
	// Scapy: ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="10.0.0.1",
	//            hwdst="00:11:22:33:44:55", pdst="10.0.0.2")
	// Expected op=0x0002 (IS-AT / reply)
	b := []byte{
		0x00, 0x01, // hwtype
		0x08, 0x00, // ptype
		0x06, // hwlen
		0x04, // plen
		0x00, 0x02, // op (IS-AT / reply)
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // hwsrc
		0x0a, 0x00, 0x00, 0x01, // psrc
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // hwdst
		0x0a, 0x00, 0x00, 0x02, // pdst
	}

	arp := NewARP()
	arp.Set("op", ARPIsAt)
	arp.Set("hwsrc", "aa:bb:cc:dd:ee:ff")
	arp.Set("psrc", "10.0.0.1")
	arp.Set("hwdst", "00:11:22:33:44:55")
	arp.Set("pdst", "10.0.0.2")

	got := serializeLayer(t, arp)
	if !bytes.Equal(got, b) {
		t.Errorf("ARP reply serialization mismatch:\n got: %x\nwant: %x", got, b)
	}
}

func TestEthernetARPStacking(t *testing.T) {
	// Scapy: Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1")
	// After stacking, Ether.type should be auto-set to 0x0806 by binding.
	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	arp := NewARP()
	arp.Set("pdst", "192.168.1.1")

	pkt := eth.Over(arp)

	etherType, _ := eth.Get("type")
	if etherType.(uint16) != EtherTypeARP {
		t.Errorf("Ether.type after Over(ARP) = %#x, want 0x0806", etherType)
	}
	if pkt.Len() != 2 {
		t.Fatalf("packet len = %d, want 2", pkt.Len())
	}
}

func TestLayerFieldsOrder(t *testing.T) {
	// Verify field ordering matches protocol spec byte order.
	eth := NewEthernet()
	ethFields := eth.Fields()
	if ethFields[0].Name() != "dst" {
		t.Errorf("Ethernet field 0 = %s, want dst", ethFields[0].Name())
	}
	if ethFields[1].Name() != "src" {
		t.Errorf("Ethernet field 1 = %s, want src", ethFields[1].Name())
	}
	if ethFields[2].Name() != "type" {
		t.Errorf("Ethernet field 2 = %s, want type", ethFields[2].Name())
	}

	arp := NewARP()
	arpFields := arp.Fields()
	if arpFields[0].Name() != "hwtype" {
		t.Errorf("ARP field 0 = %s, want hwtype", arpFields[0].Name())
	}
	if arpFields[8].Name() != "pdst" {
		t.Errorf("ARP field 8 = %s, want pdst", arpFields[8].Name())
	}
}

func TestEtherTypeConstants(t *testing.T) {
	if EtherTypeIPv4 != 0x0800 {
		t.Errorf("EtherTypeIPv4 = %#x", EtherTypeIPv4)
	}
	if EtherTypeARP != 0x0806 {
		t.Errorf("EtherTypeARP = %#x", EtherTypeARP)
	}
	if EtherTypeIPv6 != 0x86DD {
		t.Errorf("EtherTypeIPv6 = %#x", EtherTypeIPv6)
	}
}

// ---- IP tests ----

func TestIPDefaults(t *testing.T) {
	ip := NewIP()

	verihl, _ := ip.Get("verihl")
	tos, _ := ip.Get("tos")
	length, _ := ip.Get("len")
	ttl, _ := ip.Get("ttl")
	proto, _ := ip.Get("proto")

	if verihl.(uint8) != 0x45 {
		t.Errorf("verihl = %#x, want 0x45 (v4, ihl=5)", verihl)
	}
	if tos.(uint8) != 0 {
		t.Errorf("tos = %d, want 0", tos)
	}
	if length.(uint16) != 20 {
		t.Errorf("len = %d, want 20", length)
	}
	if ttl.(uint8) != 64 {
		t.Errorf("ttl = %d, want 64", ttl)
	}
	if proto.(uint8) != 0 {
		t.Errorf("proto = %d, want 0", proto)
	}

	src, _ := ip.Get("src")
	dst, _ := ip.Get("dst")
	if ip, ok := src.(net.IP); !ok || ip != nil {
		t.Errorf("src = %v, want nil IP", src)
	}
	if ip, ok := dst.(net.IP); !ok || ip != nil {
		t.Errorf("dst = %v, want nil IP", dst)
	}
}

func TestIPVersionIHL(t *testing.T) {
	if IPVersion(0x45) != 4 {
		t.Errorf("IPVersion(0x45) = %d", IPVersion(0x45))
	}
	if IPIHL(0x45) != 5 {
		t.Errorf("IPIHL(0x45) = %d", IPIHL(0x45))
	}
	if IPVersion(0x64) != 6 {
		t.Errorf("IPVersion(0x64) = %d", IPVersion(0x64))
	}
}

func TestIPFlagsFrag(t *testing.T) {
	if IPFlags(0x4000) != 2 { // DF bit set
		t.Errorf("IPFlags(0x4000) = %d, want 2", IPFlags(0x4000))
	}
	if IPFragOffset(0x1FFF) != 0x1FFF {
		t.Errorf("IPFragOffset(0x1FFF) = %d", IPFragOffset(0x1FFF))
	}
	if IPFlags(0x0000) != 0 {
		t.Errorf("IPFlags(0x0000) = %d", IPFlags(0x0000))
	}
}

func TestIPSerialization(t *testing.T) {
	// Scapy: IP(src="192.168.1.1", dst="8.8.8.8", ttl=64, proto=17)
	// Expected bytes (20 bytes, no options):
	// 45 00 00 14 00 00 00 00 40 11 [chksum] c0 a8 01 01 08 08 08 08
	expected := []byte{
		0x45, // ver=4, ihl=5
		0x00, // tos
		0x00, 0x14, // total length (20)
		0x00, 0x00, // id
		0x00, 0x00, // flags + frag
		0x40, // ttl (64)
		0x11, // proto (17 = UDP)
		0x00, 0x00, // checksum placeholder (set to 0 for comparison)
		0xc0, 0xa8, 0x01, 0x01, // src = 192.168.1.1
		0x08, 0x08, 0x08, 0x08, // dst = 8.8.8.8
	}

	ip := NewIP()
	ip.Set("src", "192.168.1.1")
	ip.Set("dst", "8.8.8.8")
	ip.Set("proto", IPProtoUDP)

	got := serializeLayer(t, ip)

	if len(got) != 20 {
		t.Fatalf("serialized len = %d, want 20", len(got))
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("IP serialization mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestIPChecksumCalc(t *testing.T) {
	// Scapy: IP(src="10.0.0.1", dst="10.0.0.2", proto=1, ttl=64)
	// Build the header, zero checksum, compute, verify.
	ip := NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")
	ip.Set("proto", IPProtoICMP)

	hdr := serializeLayer(t, ip)
	if len(hdr) != 20 {
		t.Fatalf("header len = %d", len(hdr))
	}

	// IP checksum over the header bytes (checksum field zeroed).
	csum := IPChecksum(hdr)
	if csum == 0 {
		t.Error("checksum should not be zero")
	}

	// Verify: set checksum, re-serialize, re-compute → should be 0x0000
	hdr[10] = uint8(csum >> 8)
	hdr[11] = uint8(csum)
	verify := IPChecksum(hdr)
	if verify != 0 {
		t.Errorf("checksum verification failed: got %#x, want 0", verify)
	}
}

func TestIPStackingWithICMP(t *testing.T) {
	eth := NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0)
	ip := NewIP()
	icmp := NewICMP()

	pkt := eth.Over(ip)
	pkt.Push(icmp)
	pkt.Sync()

	etherType, _ := eth.Get("type")
	ipProto, _ := ip.Get("proto")

	if etherType.(uint16) != EtherTypeIPv4 {
		t.Errorf("Ether.type = %#x, want 0x0800", etherType)
	}
	if ipProto.(uint8) != IPProtoICMP {
		t.Errorf("IP.proto = %d, want 1 (ICMP)", ipProto)
	}
	if pkt.Len() != 3 {
		t.Fatalf("packet len = %d, want 3", pkt.Len())
	}
}

// ---- ICMP tests ----

func TestICMPDefaults(t *testing.T) {
	icmp := NewICMP()

	itype, _ := icmp.Get("type")
	code, _ := icmp.Get("code")
	chksum, _ := icmp.Get("chksum")

	if itype.(uint8) != ICMPEchoRequest {
		t.Errorf("type = %d, want 8 (Echo Request)", itype)
	}
	if code.(uint8) != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if chksum.(uint16) != 0 {
		t.Errorf("chksum = %d, want 0 (auto-computed during Build)", chksum)
	}
}

func TestICMPEcho(t *testing.T) {
	icmp := NewICMPEcho(0x1234, 0x0001)

	itype, _ := icmp.Get("type")
	id, _ := icmp.Get("id")
	seq, _ := icmp.Get("seq")

	if itype.(uint8) != ICMPEchoRequest {
		t.Errorf("type = %d", itype)
	}
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	if seq.(uint16) != 1 {
		t.Errorf("seq = %d", seq)
	}
}

func TestICMPSerialization(t *testing.T) {
	// Scapy: ICMP(type=8, code=0, id=0x1234, seq=1)
	// Expected bytes (8 bytes):
	// 08 00 [chksum] 12 34 00 01
	expected := []byte{
		0x08,       // type (Echo Request)
		0x00,       // code
		0x00, 0x00, // checksum (0 placeholder)
		0x12, 0x34, // id
		0x00, 0x01, // seq
	}

	icmp := NewICMPEcho(0x1234, 1)
	got := serializeLayer(t, icmp)

	if len(got) != 8 {
		t.Fatalf("serialized len = %d, want 8", len(got))
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("ICMP serialization mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestICMPEchoReplySerialization(t *testing.T) {
	// Scapy: ICMP(type=0, code=0, id=0x0001, seq=42)
	expected := []byte{
		0x00,       // type (Echo Reply)
		0x00,       // code
		0x00, 0x00, // checksum
		0x00, 0x01, // id
		0x00, 0x2a, // seq (42)
	}

	icmp := NewICMP()
	icmp.Set("type", ICMPEchoReply)
	icmp.Set("id", uint16(1))
	icmp.Set("seq", uint16(42))

	got := serializeLayer(t, icmp)
	if !bytes.Equal(got, expected) {
		t.Errorf("ICMP Echo Reply mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestICMPChecksumCalc(t *testing.T) {
	// Build an ICMP Echo Request, compute checksum over the message.
	icmp := NewICMPEcho(0x1234, 1)
	msg := serializeLayer(t, icmp)

	csum := ICMPChecksum(msg)
	if csum == 0 {
		t.Error("checksum should not be zero")
	}

	// Verify: set checksum, re-compute → should be 0x0000
	msg[2] = uint8(csum >> 8)
	msg[3] = uint8(csum)
	verify := ICMPChecksum(msg)
	if verify != 0 {
		t.Errorf("ICMP checksum verification failed: got %#x, want 0", verify)
	}
}

// ---- checksum tests ----

func TestChecksumKnown(t *testing.T) {
	// Known test vector: all zeros should produce 0xFFFF
	b := make([]byte, 20)
	csum := Checksum(b)
	if csum != 0xFFFF {
		t.Errorf("Checksum of 20 zero bytes = %#x, want 0xFFFF", csum)
	}
}

func TestChecksumOddLength(t *testing.T) {
	// Odd-length input: [0x00, 0x01, 0x02]
	// Words: 0x0001, then pad: 0x0200
	// Sum: 0x0001 + 0x0200 = 0x0201
	// No carry. ^0x0201 = 0xFDFE
	b := []byte{0x00, 0x01, 0x02}
	csum := Checksum(b)
	if csum != 0xFDFE {
		t.Errorf("Checksum of [00 01 02] = %#x, want 0xFDFE", csum)
	}
}

func TestChecksumOfData(t *testing.T) {
	// Ping-style ICMP payload "hello".
	// "hello" → 0x68 0x65 0x6c 0x6c 0x6f
	// As words: 0x6865 + 0x6C6C + pad(0x6F00) = 0x6865 + 0x6C6C + 0x6F00 = 0x143D1
	// Fold: 0x43D1 + 0x0001 = 0x43D2. ^0x43D2 = 0xBC2D
	payload := []byte("hello")
	csum := Checksum(payload)
	if csum != 0xBC2D {
		t.Errorf("Checksum('hello') = %#x, want 0xBC2D", csum)
	}
}

func TestIPProtoConstants(t *testing.T) {
	if IPProtoICMP != 1 {
		t.Errorf("IPProtoICMP = %d", IPProtoICMP)
	}
	if IPProtoTCP != 6 {
		t.Errorf("IPProtoTCP = %d", IPProtoTCP)
	}
	if IPProtoUDP != 17 {
		t.Errorf("IPProtoUDP = %d", IPProtoUDP)
	}
}

func TestICMPTypeConstants(t *testing.T) {
	if ICMPEchoReply != 0 {
		t.Errorf("ICMPEchoReply = %d", ICMPEchoReply)
	}
	if ICMPEchoRequest != 8 {
		t.Errorf("ICMPEchoRequest = %d", ICMPEchoRequest)
	}
	if ICMPDestUnreach != 3 {
		t.Errorf("ICMPDestUnreach = %d", ICMPDestUnreach)
	}
	if ICMPTimeExceed != 11 {
		t.Errorf("ICMPTimeExceed = %d", ICMPTimeExceed)
	}
}