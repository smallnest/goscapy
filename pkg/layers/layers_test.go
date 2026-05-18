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