package layers

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- VRRP ----

func TestVRRPBuildChecksum(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "224.0.0.18") // VRRP multicast
	_ = ip.Set("proto", IPProtoVRRP)
	vrrp := NewVRRPWith(1, 100, "192.168.1.254")

	pkt := packet.NewFrom(ip, vrrp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}
	vb := raw[20:]
	if VRRPVersion(vb[0]) != 2 || VRRPType(vb[0]) != 1 {
		t.Errorf("ver_type = %#x", vb[0])
	}
	if vb[1] != 1 {
		t.Errorf("vrid = %d, want 1", vb[1])
	}
	if vb[2] != 100 {
		t.Errorf("priority = %d, want 100", vb[2])
	}
	// Checksum must fold to zero over the VRRP message.
	if Checksum(vb) != 0 {
		t.Errorf("VRRP checksum verification failed")
	}
	// Virtual IP present.
	if !net.IP(vb[8:12]).Equal(net.ParseIP("192.168.1.254")) {
		t.Errorf("virtual IP = %v", net.IP(vb[8:12]))
	}
}

func TestVRRPDissect(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "224.0.0.18")
	_ = ip.Set("proto", IPProtoVRRP)
	vrrp := NewVRRPWith(7, 200, "10.0.0.1")
	raw, _ := packet.NewFrom(ip, vrrp).Build()

	d, err := packet.DissectByProto(raw, "IP")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("VRRP") {
		t.Fatalf("missing VRRP: %s", d.String())
	}
	v := d.GetLayer("VRRP")
	vrid, _ := v.Get("vrid")
	if vrid.(uint8) != 7 {
		t.Errorf("parsed vrid = %d, want 7", vrid)
	}
}

// ---- HSRP ----

func TestHSRPBuild(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "224.0.0.2")
	_ = ip.Set("proto", IPProtoUDP)
	udp := NewUDP()
	_ = udp.Set("sport", HSRPPort)
	_ = udp.Set("dport", HSRPPort)
	hsrp := NewHSRPWith(1, 110, "192.168.1.254")

	pkt := packet.NewFrom(ip, udp, hsrp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}
	// HSRP starts after IP(20) + UDP(8) = 28.
	hb := raw[28:]
	if len(hb) != 20 {
		t.Fatalf("HSRP len = %d, want 20", len(hb))
	}
	if hb[1] != HSRPOpHello {
		t.Errorf("opcode = %d", hb[1])
	}
	if hb[6] != 1 {
		t.Errorf("group = %d, want 1", hb[6])
	}
	if hb[5] != 110 {
		t.Errorf("priority = %d, want 110", hb[5])
	}
	// auth "cisco".
	if string(hb[8:13]) != "cisco" {
		t.Errorf("auth = %q, want cisco", string(hb[8:13]))
	}
	// Virtual IP at the end.
	if !net.IP(hb[16:20]).Equal(net.ParseIP("192.168.1.254")) {
		t.Errorf("virtual IP = %v", net.IP(hb[16:20]))
	}
}

func TestHSRPDissect(t *testing.T) {
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "224.0.0.2")
	_ = ip.Set("proto", IPProtoUDP)
	udp := NewUDP()
	_ = udp.Set("sport", HSRPPort)
	_ = udp.Set("dport", HSRPPort)
	raw, _ := packet.NewFrom(ip, udp, NewHSRPWith(5, 100, "10.0.0.1")).Build()

	d, err := packet.DissectByProto(raw, "IP")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("HSRP") {
		t.Errorf("missing HSRP: %s", d.String())
	}
}

// ---- STP ----

func TestSTPBuild(t *testing.T) {
	stp := NewSTPConfig(0x8000, "aa:bb:cc:dd:ee:ff")
	raw, err := stp.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 35 {
		t.Fatalf("STP len = %d, want 35", len(raw))
	}
	if binary.BigEndian.Uint16(raw[0:2]) != STPProtocolID {
		t.Errorf("proto id wrong")
	}
	if raw[3] != STPBPDUConfig {
		t.Errorf("bpdu type = %#x", raw[3])
	}
	// Bridge ID priority.
	if binary.BigEndian.Uint16(raw[17:19]) != 0x8000 {
		t.Errorf("bridge priority = %#x", binary.BigEndian.Uint16(raw[17:19]))
	}
	// Bridge MAC.
	wantMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if string(raw[19:25]) != string(wantMAC) {
		t.Errorf("bridge MAC mismatch")
	}
}

func TestSTPParse(t *testing.T) {
	stp := NewSTPConfig(0x7000, "11:22:33:44:55:66")
	raw, _ := stp.SerializeFields()

	parsed := NewSTP()
	n, err := parsed.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if n != 35 {
		t.Fatalf("consumed = %d, want 35", n)
	}
	maxage, _ := parsed.Get("maxage")
	if maxage.(uint16) != 20*256 {
		t.Errorf("maxage = %d, want %d", maxage, 20*256)
	}
}

// ---- EAPOL / EAP ----

func TestEAPOLEAPBuild(t *testing.T) {
	eth := NewEthernetWith("01:80:c2:00:00:03", "11:22:33:44:55:66", EtherTypeEAPOL)
	eapol := NewEAPOLWith(EAPOLTypeEAP)
	eap := NewEAPWith(EAPCodeRequest, 1)
	_ = eap.Set("data", []byte{0x01}) // EAP type = Identity

	pkt := packet.NewFrom(eth, eapol, eap)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// EAPOL header at offset 14.
	eb := raw[14:]
	if eb[1] != EAPOLTypeEAP {
		t.Errorf("EAPOL type = %d", eb[1])
	}
	// EAPOL length = EAP header(4) + data(1) = 5.
	if binary.BigEndian.Uint16(eb[2:4]) != 5 {
		t.Errorf("EAPOL len = %d, want 5", binary.BigEndian.Uint16(eb[2:4]))
	}
	// EAP at offset 18.
	ep := raw[18:]
	if ep[0] != EAPCodeRequest {
		t.Errorf("EAP code = %d", ep[0])
	}
	if binary.BigEndian.Uint16(ep[2:4]) != 5 {
		t.Errorf("EAP len = %d, want 5", binary.BigEndian.Uint16(ep[2:4]))
	}
}

func TestEAPOLStartBuild(t *testing.T) {
	// EAPOL-Start has no body.
	eth := NewEthernetWith("01:80:c2:00:00:03", "11:22:33:44:55:66", EtherTypeEAPOL)
	eapol := NewEAPOLWith(EAPOLTypeStart)
	raw, err := packet.NewFrom(eth, eapol).Build()
	if err != nil {
		t.Fatal(err)
	}
	eb := raw[14:]
	if eb[1] != EAPOLTypeStart {
		t.Errorf("type = %d, want Start", eb[1])
	}
	if binary.BigEndian.Uint16(eb[2:4]) != 0 {
		t.Errorf("EAPOL-Start len = %d, want 0", binary.BigEndian.Uint16(eb[2:4]))
	}
}

func TestEAPOLDissect(t *testing.T) {
	eth := NewEthernetWith("01:80:c2:00:00:03", "11:22:33:44:55:66", EtherTypeEAPOL)
	eapol := NewEAPOLWith(EAPOLTypeEAP)
	eap := NewEAPWith(EAPCodeResponse, 2)
	_ = eap.Set("data", []byte{0x01, 'u', 's', 'e', 'r'})
	raw, _ := packet.NewFrom(eth, eapol, eap).Build()

	d, err := packet.DissectByProto(raw, "Ethernet")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasLayer("EAPOL") {
		t.Errorf("missing EAPOL: %s", d.String())
	}
	if !d.HasLayer("EAP") {
		t.Errorf("missing EAP: %s", d.String())
	}
	eapL := d.GetLayer("EAP")
	code, _ := eapL.Get("code")
	if code.(uint8) != EAPCodeResponse {
		t.Errorf("EAP code = %d, want Response", code)
	}
}
