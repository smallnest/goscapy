package layers

import (
	"bytes"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// buildFragPayload makes an IP packet carrying a large UDP payload for tests.
func buildFragIPUDP(t *testing.T, payloadLen int) *packet.Packet {
	t.Helper()
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoUDP)
	_ = ip.Set("id", uint16(0xABCD))

	udp := NewUDP()
	_ = udp.Set("sport", uint16(1234))
	_ = udp.Set("dport", uint16(5678))

	data := make([]byte, payloadLen)
	for i := range data {
		data[i] = byte(i)
	}
	return packet.NewFrom(ip, udp, NewRawWith(data))
}

func TestFragmentSingle(t *testing.T) {
	pkt := buildFragIPUDP(t, 100)
	frags, err := Fragment(pkt, 1480)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 1 {
		t.Fatalf("len(frags) = %d, want 1", len(frags))
	}
}

func TestFragmentMultiple(t *testing.T) {
	// UDP header (8) + 2000 bytes payload = 2008 bytes of L4 payload.
	pkt := buildFragIPUDP(t, 2000)
	frags, err := Fragment(pkt, 800)
	if err != nil {
		t.Fatal(err)
	}
	// 2008 bytes / 800 (rounded to 800) = 3 fragments (800, 800, 408).
	if len(frags) != 3 {
		t.Fatalf("len(frags) = %d, want 3", len(frags))
	}

	// Verify MF flags: first two set, last clear.
	for i, f := range frags {
		ip := f.GetLayer("IP")
		if ip == nil {
			t.Fatalf("frag %d missing IP", i)
		}
		fragVal, _ := ip.Get("frag")
		frag := fragVal.(uint16)
		mf := frag&0x2000 != 0
		offset := (frag & 0x1FFF) * 8
		wantMF := i < len(frags)-1
		if mf != wantMF {
			t.Errorf("frag %d MF = %v, want %v", i, mf, wantMF)
		}
		wantOff := uint16(i * 800)
		if offset != wantOff {
			t.Errorf("frag %d offset = %d, want %d", i, offset, wantOff)
		}
		// id should be preserved.
		id, _ := ip.Get("id")
		if id.(uint16) != 0xABCD {
			t.Errorf("frag %d id = %#x, want 0xABCD", i, id)
		}
	}
}

func TestFragmentReassembleEquivalence(t *testing.T) {
	pkt := buildFragIPUDP(t, 3000)
	frags, err := Fragment(pkt, 1000)
	if err != nil {
		t.Fatal(err)
	}

	// Concatenate fragment payloads in offset order and compare to original L4.
	origL4, err := pkt.BuildFrom(0)
	if err != nil {
		t.Fatal(err)
	}
	// Strip the original IP header (20 bytes) to get L4 payload.
	origPayload := origL4[20:]

	var reassembled []byte
	for _, f := range frags {
		raw, err := f.Build()
		if err != nil {
			t.Fatal(err)
		}
		reassembled = append(reassembled, raw[20:]...) // skip IP header
	}
	if !bytes.Equal(reassembled, origPayload) {
		t.Errorf("reassembled payload mismatch: got %d bytes, want %d bytes", len(reassembled), len(origPayload))
	}
}

func TestFragmentRoundsToEight(t *testing.T) {
	pkt := buildFragIPUDP(t, 2000)
	frags, err := Fragment(pkt, 1003) // should round down to 1000
	if err != nil {
		t.Fatal(err)
	}
	// Each non-final fragment payload must be a multiple of 8.
	for i, f := range frags[:len(frags)-1] {
		raw, _ := f.Build()
		payloadLen := len(raw) - 20
		if payloadLen%8 != 0 {
			t.Errorf("frag %d payload %d not multiple of 8", i, payloadLen)
		}
	}
}

func TestFragmentNoIP(t *testing.T) {
	eth := NewEthernet()
	pkt := packet.NewFrom(eth)
	_, err := Fragment(pkt, 100)
	if err == nil {
		t.Fatal("expected error for packet with no IP layer")
	}
}

func TestFragmentPreservesEthernet(t *testing.T) {
	eth := NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", EtherTypeIPv4)
	ip := NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", IPProtoUDP)
	udp := NewUDP()
	data := make([]byte, 2000)
	pkt := packet.NewFrom(eth, ip, udp, NewRawWith(data))

	frags, err := Fragment(pkt, 800)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}
	for i, f := range frags {
		if f.GetLayer("Ethernet") == nil {
			t.Errorf("frag %d missing Ethernet layer", i)
		}
	}
}

func TestFragment6Multiple(t *testing.T) {
	ip := NewIPv6()
	_ = ip.Set("src", "2001:db8::1")
	_ = ip.Set("dst", "2001:db8::2")
	_ = ip.Set("nh", IPv6NextHdrUDP)
	udp := NewUDP()
	_ = udp.Set("sport", uint16(1234))
	_ = udp.Set("dport", uint16(5678))
	data := make([]byte, 2000)
	for i := range data {
		data[i] = byte(i)
	}
	pkt := packet.NewFrom(ip, udp, NewRawWith(data))

	frags, err := Fragment6(pkt, 800, 0xDEADBEEF)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}

	for i, f := range frags {
		fh := f.GetLayer("IPv6 Fragment")
		if fh == nil {
			t.Fatalf("frag %d missing IPv6 Fragment header", i)
		}
		id, _ := fh.Get("id")
		if id.(uint32) != 0xDEADBEEF {
			t.Errorf("frag %d id = %#x, want 0xDEADBEEF", i, id)
		}
		fragVal, _ := fh.Get("frag")
		frag := fragVal.(uint16)
		mf := frag&0x0001 != 0
		wantMF := i < len(frags)-1
		if mf != wantMF {
			t.Errorf("frag %d M flag = %v, want %v", i, mf, wantMF)
		}
		// IPv6 header nh should be 44 (Fragment).
		nh, _ := f.GetLayer("IPv6").Get("nh")
		if nh.(uint8) != IPv6ExtHdrFragment {
			t.Errorf("frag %d IPv6 nh = %d, want %d", i, nh, IPv6ExtHdrFragment)
		}
		// Fragment header nh should advertise the inner UDP protocol.
		innerNH, _ := fh.Get("nh")
		if innerNH.(uint8) != IPv6NextHdrUDP {
			t.Errorf("frag %d fragment nh = %d, want %d (UDP)", i, innerNH, IPv6NextHdrUDP)
		}
	}
}

func TestFragment6Single(t *testing.T) {
	ip := NewIPv6()
	_ = ip.Set("src", "2001:db8::1")
	_ = ip.Set("dst", "2001:db8::2")
	_ = ip.Set("nh", IPv6NextHdrUDP)
	udp := NewUDP()
	pkt := packet.NewFrom(ip, udp, NewRawWith(make([]byte, 50)))

	frags, err := Fragment6(pkt, 1480, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 1 {
		t.Fatalf("len(frags) = %d, want 1", len(frags))
	}
}

func TestFragment6NoIPv6(t *testing.T) {
	ip := NewIP()
	pkt := packet.NewFrom(ip)
	_, err := Fragment6(pkt, 100, 1)
	if err == nil {
		t.Fatal("expected error for packet with no IPv6 layer")
	}
}
