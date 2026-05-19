package layers

import (
	"bytes"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- NDP option parsing ----

func TestParseNDPOptionsBasic(t *testing.T) {
	// Source Link-Layer option: type=1, len=1 (8 bytes), value=MAC
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	opt := BuildSourceLinkLayerOption(mac)
	raw := BuildNDPOptions([]NDPOption{opt})

	opts, err := ParseNDPOptions(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Fatalf("got %d options, want 1", len(opts))
	}
	if opts[0].Type != NDPOptSourceLinkLayer {
		t.Errorf("type = %d, want 1", opts[0].Type)
	}
	if !bytes.Equal(opts[0].Value, mac) {
		t.Errorf("MAC = %v, want %v", opts[0].Value, mac)
	}
}

func TestParseNDPOptionsMultiple(t *testing.T) {
	slla := BuildSourceLinkLayerOption(net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	tlla := BuildTargetLinkLayerOption(net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	mtu := BuildMTUOption(1500)
	raw := BuildNDPOptions([]NDPOption{slla, tlla, mtu})

	opts, err := ParseNDPOptions(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 3 {
		t.Fatalf("got %d options, want 3", len(opts))
	}
	if opts[0].Type != NDPOptSourceLinkLayer {
		t.Error("wrong first type")
	}
	if opts[1].Type != NDPOptTargetLinkLayer {
		t.Error("wrong second type")
	}
	if opts[2].Type != NDPOptMTU {
		t.Error("wrong third type")
	}
}

func TestParseNDPOptionsTruncated(t *testing.T) {
	_, err := ParseNDPOptions([]byte{0x01}) // type without length
	if err == nil {
		t.Fatal("expected error for truncated option")
	}
}

func TestBuildNDPOptionsEmpty(t *testing.T) {
	raw := BuildNDPOptions(nil)
	if len(raw) != 0 {
		t.Errorf("got %d bytes, want 0", len(raw))
	}
}

// ---- NDP Router Solicitation tests ----

func TestNDPRouterSolicitationSerialize(t *testing.T) {
	rs := NewNDPRouterSolicitation()
	rs.Set("reserved", uint32(0))
	rs.Set("options", []byte{})

	got, err := rs.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4 (reserved only)", len(got))
	}
}

func TestNDPRouterSolicitationWithOptions(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	slla := BuildSourceLinkLayerOption(mac)
	optRaw := BuildNDPOptions([]NDPOption{slla})

	rs := NewNDPRouterSolicitation()
	rs.Set("reserved", uint32(0))
	rs.Set("options", optRaw)

	got, err := rs.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	// 4 reserved + 8 SLLA option = 12 bytes
	if len(got) != 12 {
		t.Fatalf("len = %d, want 12", len(got))
	}
}

func TestNDPRouterSolicitationParse(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	slla := BuildSourceLinkLayerOption(mac)
	optRaw := BuildNDPOptions([]NDPOption{slla})

	raw := make([]byte, 4+len(optRaw))
	// reserved = 0
	raw[0], raw[1], raw[2], raw[3] = 0, 0, 0, 0
	copy(raw[4:], optRaw)

	rs := NewNDPRouterSolicitation()
	consumed, err := rs.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed = %d, want %d", consumed, len(raw))
	}

	optVal, _ := rs.Get("options")
	opts, err := ParseNDPOptions(optVal.([]byte))
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 || opts[0].Type != NDPOptSourceLinkLayer {
		t.Error("option not parsed correctly")
	}
}

// ---- NDP Router Advertisement tests ----

func TestNDPRouterAdvertisementDefaults(t *testing.T) {
	ra := NewNDPRouterAdvertisement()

	hoplimit, _ := ra.Get("hoplimit")
	if hoplimit.(uint8) != 64 {
		t.Errorf("hoplimit = %d, want 64", hoplimit)
	}
	lifetime, _ := ra.Get("lifetime")
	if lifetime.(uint16) != 1800 {
		t.Errorf("lifetime = %d, want 1800", lifetime)
	}
}

func TestNDPRouterAdvertisementSerialize(t *testing.T) {
	ra := NewNDPRouterAdvertisement()
	ra.Set("options", []byte{})

	got, err := ra.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	// hoplimit(1) + flags(1) + lifetime(2) + reachable(4) + retrans(4) = 12
	if len(got) != 12 {
		t.Fatalf("len = %d, want 12", len(got))
	}
}

// ---- NDP Neighbor Solicitation tests ----

func TestNDPNeighborSolicitationSerialize(t *testing.T) {
	target := net.ParseIP("fe80::1")

	ns := NewNDPNeighborSolicitation()
	ns.Set("reserved", uint32(0))
	ns.Set("target", target)
	ns.Set("options", []byte{})

	got, err := ns.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	// reserved(4) + target(16) = 20
	if len(got) != 20 {
		t.Fatalf("len = %d, want 20", len(got))
	}
}

func TestNDPNeighborSolicitationParse(t *testing.T) {
	target := net.ParseIP("fe80::1").To16()

	raw := make([]byte, 20)
	// reserved = 0
	raw[0], raw[1], raw[2], raw[3] = 0, 0, 0, 0
	copy(raw[4:20], target)

	ns := NewNDPNeighborSolicitation()
	consumed, err := ns.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 20 {
		t.Fatalf("consumed = %d, want 20", consumed)
	}

	targetVal, _ := ns.Get("target")
	if !targetVal.(net.IP).Equal(target) {
		t.Errorf("target = %v, want %v", targetVal, target)
	}
}

// ---- NDP Neighbor Advertisement tests ----

func TestNDPNeighborAdvertisementSerialize(t *testing.T) {
	target := net.ParseIP("fe80::1")

	na := NewNDPNeighborAdvertisement()
	na.Set("flags", uint8(NDPNARouter|NDPNASolicited|NDPNAOverride))
	na.Set("reserved", uint32(0))
	na.Set("target", target)
	na.Set("options", []byte{})

	got, err := na.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	// flags(1) + reserved(3) + target(16) = 20
	if len(got) != 20 {
		t.Fatalf("len = %d, want 20", len(got))
	}
	if got[0] != NDPNARouter|NDPNASolicited|NDPNAOverride {
		t.Errorf("flags = %#x", got[0])
	}
}

// ---- NDP Redirect tests ----

func TestNDPRedirectSerialize(t *testing.T) {
	target := net.ParseIP("fe80::1")
	dest := net.ParseIP("2001:db8::1")

	rd := NewNDPRedirect()
	rd.Set("reserved", uint32(0))
	rd.Set("target", target)
	rd.Set("dest", dest)
	rd.Set("options", []byte{})

	got, err := rd.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	// reserved(4) + target(16) + dest(16) = 36
	if len(got) != 36 {
		t.Fatalf("len = %d, want 36", len(got))
	}
}

// ---- Packed build: IPv6 + ICMPv6 + NDP NS ----

func TestNDPPackedBuild(t *testing.T) {
	ipv6 := NewIPv6()
	ipv6.Set("src", "fe80::1")
	ipv6.Set("dst", "ff02::1")

	icmpBase := NewICMPv6()
	icmpBase.Set("type", NDPNeighborSolicitation)
	icmpBase.Set("code", uint8(0))

	target := net.ParseIP("fe80::2")
	slla := BuildSourceLinkLayerOption(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	optRaw := BuildNDPOptions([]NDPOption{slla})

	ns := NewNDPNeighborSolicitation()
	ns.Set("reserved", uint32(0))
	ns.Set("target", target)
	ns.Set("options", optRaw)

	pkt := packet.NewFrom(ipv6)
	pkt.Push(icmpBase)
	pkt.Push(ns)

	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// 40 (IPv6) + 4 (ICMPv6) + 4 (reserved) + 16 (target) + 8 (SLLA) = 72
	if len(raw) != 72 {
		t.Fatalf("packet len = %d, want 72", len(raw))
	}

	// Verify checksum is set.
	icmpType, _ := icmpBase.Get("type")
	if icmpType.(uint8) != NDPNeighborSolicitation {
		t.Error("type not set")
	}
	chksum, _ := icmpBase.Get("chksum")
	if chksum.(uint16) == 0 {
		t.Error("checksum should be non-zero")
	}
}

// ---- Packed build: IPv6 + ICMPv6 + NDP RA ----

func TestNDPPackedBuildRA(t *testing.T) {
	ipv6 := NewIPv6()
	ipv6.Set("src", "fe80::1")
	ipv6.Set("dst", "ff02::1")

	icmpBase := NewICMPv6()
	icmpBase.Set("type", NDPRouterAdvertisement)
	icmpBase.Set("code", uint8(0))

	ra := NewNDPRouterAdvertisement()
	ra.Set("options", []byte{})

	pkt := packet.NewFrom(ipv6)
	pkt.Push(icmpBase)
	pkt.Push(ra)

	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// 40 (IPv6) + 4 (ICMPv6) + 12 (RA body) = 56
	if len(raw) != 56 {
		t.Fatalf("packet len = %d, want 56", len(raw))
	}
}

// ---- MTU option builder ----

func TestBuildMTUOption(t *testing.T) {
	mtu := BuildMTUOption(1500)
	if mtu.Type != NDPOptMTU {
		t.Errorf("type = %d", mtu.Type)
	}
	if mtu.Length != 1 {
		t.Errorf("length = %d", mtu.Length)
	}

	raw := BuildNDPOptions([]NDPOption{mtu})
	opts, _ := ParseNDPOptions(raw)
	if len(opts) != 1 {
		t.Fatal("parse failed")
	}

	// MTU value is 2 reserved + 4 MTU = 6 bytes total
	mtuVal := uint32(opts[0].Value[2])<<24 | uint32(opts[0].Value[3])<<16 |
		uint32(opts[0].Value[4])<<8 | uint32(opts[0].Value[5])
	if mtuVal != 1500 {
		t.Errorf("MTU = %d, want 1500", mtuVal)
	}
}