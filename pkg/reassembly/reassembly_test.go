package reassembly

import (
	"net"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// buildFragment creates a fragmented IP packet for testing.
// offset is in 8-byte units, moreFragments sets the MF flag.
func buildFragment(src, dst string, id uint16, proto uint8, offset uint16, moreFragments bool, payload []byte) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", src)
	ip.Set("dst", dst)
	ip.Set("id", id)
	ip.Set("proto", proto)

	flags := uint16(0)
	if moreFragments {
		flags = 0x01 << 13 // MF flag
	}
	frag := flags | (offset & 0x1FFF)
	ip.Set("frag", frag)

	// Manually set length to include payload.
	ip.Set("len", uint16(20+len(payload)))

	raw := layers.NewRawWith(payload)
	return packet.NewFrom(ip, raw)
}

func TestNonFragmentedPassthrough(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	ip := layers.NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")
	ip.Set("id", uint16(1))
	ip.Set("proto", layers.IPProtoTCP)
	ip.Set("frag", uint16(0)) // no flags, no offset

	pkt := packet.NewFrom(ip)
	result := r.Submit(pkt)
	if result == nil {
		t.Fatal("expected non-fragmented packet to pass through")
	}
}

func TestTwoFragmentReassembly(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	// Fragment 1: offset=0, MF=1, 16 bytes of ICMP data.
	payload1 := make([]byte, 16)
	for i := range payload1 {
		payload1[i] = byte(i)
	}
	frag1 := buildFragment("10.0.0.1", "10.0.0.2", 0x1234, layers.IPProtoICMP, 0, true, payload1)

	// Fragment 2: offset=2 (16/8=2), MF=0, 8 bytes of ICMP data.
	payload2 := make([]byte, 8)
	for i := range payload2 {
		payload2[i] = byte(i + 16)
	}
	frag2 := buildFragment("10.0.0.1", "10.0.0.2", 0x1234, layers.IPProtoICMP, 2, false, payload2)

	// Submit first fragment — should return nil (incomplete).
	result := r.Submit(frag1)
	if result != nil {
		t.Fatal("expected nil for first fragment")
	}

	// Submit second fragment — should complete reassembly.
	result = r.Submit(frag2)
	if result == nil {
		t.Fatal("expected reassembled packet")
	}

	// Verify the reassembled packet has an IP layer.
	ipLayer := result.GetLayer("IP")
	if ipLayer == nil {
		t.Fatal("reassembled packet missing IP layer")
	}
	srcVal, _ := ipLayer.Get("src")
	srcIP, _ := srcVal.(net.IP)
	if srcIP.String() != "10.0.0.1" {
		t.Errorf("src: expected 10.0.0.1, got %s", srcIP)
	}
}

func TestThreeFragmentOutOfOrder(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	// 3 fragments of 8 bytes each (24 bytes total).
	// Send them out of order: 2, 0, 1.
	payload := [3][]byte{
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		{0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
	}

	frag0 := buildFragment("192.168.1.1", "192.168.1.2", 0xABCD, layers.IPProtoUDP, 0, true, payload[0])
	frag1 := buildFragment("192.168.1.1", "192.168.1.2", 0xABCD, layers.IPProtoUDP, 1, true, payload[1])
	frag2 := buildFragment("192.168.1.1", "192.168.1.2", 0xABCD, layers.IPProtoUDP, 2, false, payload[2])

	// Submit out of order: frag2, frag0, frag1.
	if r.Submit(frag2) != nil {
		t.Fatal("expected nil for fragment 2")
	}
	if r.Submit(frag0) != nil {
		t.Fatal("expected nil for fragment 0")
	}

	result := r.Submit(frag1)
	if result == nil {
		t.Fatal("expected reassembled packet after all fragments")
	}
}

func TestDifferentGroupsIndependent(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	// Two different fragment groups (different IDs).
	frag1a := buildFragment("10.0.0.1", "10.0.0.2", 1, layers.IPProtoICMP, 0, true, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	frag2a := buildFragment("10.0.0.1", "10.0.0.2", 2, layers.IPProtoICMP, 0, true, []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18})

	r.Submit(frag1a)
	r.Submit(frag2a)

	if r.Stats() != 2 {
		t.Errorf("expected 2 groups, got %d", r.Stats())
	}

	// Complete group 1.
	frag1b := buildFragment("10.0.0.1", "10.0.0.2", 1, layers.IPProtoICMP, 1, false, []byte{0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10})
	result := r.Submit(frag1b)
	if result == nil {
		t.Fatal("expected group 1 to reassemble")
	}

	if r.Stats() != 1 {
		t.Errorf("expected 1 remaining group, got %d", r.Stats())
	}
}

func TestTimeoutExpiry(t *testing.T) {
	r := New(WithTimeout(50 * time.Millisecond))
	defer r.Close()

	frag := buildFragment("10.0.0.1", "10.0.0.2", 99, layers.IPProtoTCP, 0, true, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	r.Submit(frag)

	if r.Stats() != 1 {
		t.Fatalf("expected 1 group, got %d", r.Stats())
	}

	// Wait for GC to clean up.
	time.Sleep(100 * time.Millisecond)

	if r.Stats() != 0 {
		t.Errorf("expected 0 groups after timeout, got %d", r.Stats())
	}
}

func TestMaxGroupsDoSProtection(t *testing.T) {
	r := New(WithTimeout(5*time.Second), WithMaxGroups(3))
	defer r.Close()

	// Fill up to max.
	for i := range 3 {
		frag := buildFragment("10.0.0.1", "10.0.0.2", uint16(i), layers.IPProtoICMP, 0, true, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
		r.Submit(frag)
	}

	if r.Stats() != 3 {
		t.Fatalf("expected 3 groups, got %d", r.Stats())
	}

	// 4th group should be dropped.
	frag := buildFragment("10.0.0.1", "10.0.0.2", 100, layers.IPProtoICMP, 0, true, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	result := r.Submit(frag)
	if result != nil {
		t.Fatal("expected nil (dropped) for group exceeding maxGroups")
	}

	if r.Stats() != 3 {
		t.Errorf("expected 3 groups (unchanged), got %d", r.Stats())
	}
}

func TestOversizedReassemblyRejected(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	// Create a fragment with offset that would cause total > 65535.
	// offset=8191 (max 13-bit value) * 8 = 65528 bytes offset.
	// Plus 16 bytes of data = 65544 > 65535.
	bigFrag := buildFragment("10.0.0.1", "10.0.0.2", 42, layers.IPProtoUDP, 8191, false, make([]byte, 16))
	firstFrag := buildFragment("10.0.0.1", "10.0.0.2", 42, layers.IPProtoUDP, 0, true, make([]byte, 8))

	r.Submit(firstFrag)
	result := r.Submit(bigFrag)
	if result != nil {
		t.Fatal("expected nil for oversized reassembly")
	}

	// Group should be removed.
	if r.Stats() != 0 {
		t.Errorf("expected group removed after oversize, got %d", r.Stats())
	}
}

func TestGapDetection(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	// Fragment at offset 0 with MF=1 (8 bytes), and fragment at offset 2 with MF=0 (8 bytes).
	// Missing fragment at offset 1 (bytes 8-15).
	frag0 := buildFragment("10.0.0.1", "10.0.0.2", 7, layers.IPProtoICMP, 0, true, make([]byte, 8))
	frag2 := buildFragment("10.0.0.1", "10.0.0.2", 7, layers.IPProtoICMP, 2, false, make([]byte, 8))

	r.Submit(frag0)
	result := r.Submit(frag2)

	// Should not reassemble — gap at offset 1 (bytes 8-15).
	if result != nil {
		t.Fatal("expected nil due to gap in fragment coverage")
	}

	if r.Stats() != 1 {
		t.Errorf("expected group still active, got %d", r.Stats())
	}
}

func TestOverlappingFragments(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	// Two overlapping fragments that together cover [0, 16).
	// Fragment 0: offset=0, length=16 bytes, MF=1.
	// Fragment 1: offset=1, length=8 bytes, MF=0 (overlaps bytes 8-15, ends at 16).
	frag0 := buildFragment("10.0.0.1", "10.0.0.2", 55, layers.IPProtoTCP, 0, true, make([]byte, 16))
	frag1 := buildFragment("10.0.0.1", "10.0.0.2", 55, layers.IPProtoTCP, 1, false, make([]byte, 8))

	r.Submit(frag0)
	result := r.Submit(frag1)

	// Should reassemble successfully (overlap is fine, last writer wins).
	if result == nil {
		t.Fatal("expected reassembled packet with overlapping fragments")
	}
}

func TestNoIPLayerPassthrough(t *testing.T) {
	r := New(WithTimeout(5 * time.Second))
	defer r.Close()

	// Non-IP packet should pass through.
	eth := layers.NewEthernet()
	pkt := packet.NewFrom(eth)

	result := r.Submit(pkt)
	if result == nil {
		t.Fatal("expected non-IP packet to pass through")
	}
}
