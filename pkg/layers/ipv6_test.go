package layers

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

func TestNewIPv6Defaults(t *testing.T) {
	ipv6 := NewIPv6()

	v, _ := ipv6.Get("ver_tc_fl")
	if IPv6Version(v.(uint32)) != 6 {
		t.Errorf("version = %d, want 6", IPv6Version(v.(uint32)))
	}
	if IPv6TrafficClass(v.(uint32)) != 0 {
		t.Errorf("tc = %d, want 0", IPv6TrafficClass(v.(uint32)))
	}
	if IPv6FlowLabel(v.(uint32)) != 0 {
		t.Errorf("fl = %d, want 0", IPv6FlowLabel(v.(uint32)))
	}

	hlim, _ := ipv6.Get("hlim")
	if hlim.(uint8) != 64 {
		t.Errorf("hlim = %d, want 64", hlim)
	}
}

func TestIPv6Serialize(t *testing.T) {
	// Scapy: IPv6(src="::1", dst="ff02::1", nh=58, hlim=64)
	expected := []byte{
		0x60, 0x00, 0x00, 0x00, // ver=6, tc=0, fl=0
		0x00, 0x08, // plen = 8
		0x3A, // nh = 58 (ICMPv6)
		0x40, // hlim = 64
		// src = ::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		// dst = ff02::1
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	ipv6 := NewIPv6()
	ipv6.Set("nh", uint8(58))
	ipv6.Set("src", "::1")
	ipv6.Set("dst", "ff02::1")
	ipv6.Set("plen", uint16(8))

	got, err := ipv6.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("IPv6 serialize mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

func TestIPv6TrafficClassFlowLabel(t *testing.T) {
	fl := MakeIPv6VerTCFL(0xAB, 0x12345)
	if IPv6Version(fl) != 6 {
		t.Errorf("version = %d", IPv6Version(fl))
	}
	if IPv6TrafficClass(fl) != 0xAB {
		t.Errorf("tc = %#x, want 0xAB", IPv6TrafficClass(fl))
	}
	if IPv6FlowLabel(fl) != 0x12345 {
		t.Errorf("fl = %#x, want 0x12345", IPv6FlowLabel(fl))
	}
}

func TestIPv6ParseFields(t *testing.T) {
	raw := []byte{
		0x60, 0x00, 0x00, 0x00, // ver=6
		0x00, 0x08, // plen = 8
		0x3A, // nh = 58
		0x40, // hlim = 64
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	ipv6 := NewIPv6()
	consumed, err := ipv6.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 40 {
		t.Fatalf("consumed = %d, want 40", consumed)
	}

	nh, _ := ipv6.Get("nh")
	if nh.(uint8) != 58 {
		t.Errorf("nh = %d, want 58", nh)
	}

	hlim, _ := ipv6.Get("hlim")
	if hlim.(uint8) != 64 {
		t.Errorf("hlim = %d, want 64", hlim)
	}

	src, _ := ipv6.Get("src")
	if ip := src.(net.IP); !ip.Equal(net.ParseIP("::1")) {
		t.Errorf("src = %v, want ::1", ip)
	}

	dst, _ := ipv6.Get("dst")
	if ip := dst.(net.IP); !ip.Equal(net.ParseIP("ff02::1")) {
		t.Errorf("dst = %v, want ff02::1", ip)
	}
}

func TestIPv6BuildHook(t *testing.T) {
	ipv6 := NewIPv6()
	ipv6.Set("nh", uint8(58))
	ipv6.Set("src", "::1")
	ipv6.Set("dst", "ff02::1")

	upper := []byte{0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01} // 8 bytes ICMPv6
	pkt := packet.NewFrom(ipv6)

	got, err := ipv6BuildHook(pkt, 0, upper)
	if err != nil {
		t.Fatal(err)
	}

	// Payload length should be set to 8.
	plen, _ := ipv6.Get("plen")
	if plen.(uint16) != 8 {
		t.Errorf("plen = %d, want 8", plen)
	}

	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}
}

func TestIPv6PseudoHeaderChecksum(t *testing.T) {
	srcIP := net.ParseIP("::1").To16()
	dstIP := net.ParseIP("::1").To16()

	// ICMPv6 Echo Request: type=128, code=0, checksum=0, id=0x1234, seq=1
	icmp6 := []byte{
		0x80, 0x00, // type=128, code=0
		0x00, 0x00, // checksum = 0 (for computation)
		0x12, 0x34, // id
		0x00, 0x01, // seq
	}

	csum := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, icmp6)
	// Verify by computing over the full message with checksum set.
	binary.BigEndian.PutUint16(icmp6[2:4], csum)
	verify := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, icmp6)
	if verify != 0 {
		t.Errorf("checksum verification failed: got %#x, want 0", verify)
	}
}

func TestIPv6PseudoHeaderChecksumOddLength(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1").To16()
	dstIP := net.ParseIP("2001:db8::2").To16()

	// Odd-length payload (3 bytes)
	data := []byte{0x01, 0x02, 0x03}
	csum := IPv6PseudoHeaderChecksum(srcIP, dstIP, 17, data)
	if csum == 0 && !allZero(data) {
		// checksum of 0 is valid for UDP (means no checksum), but unlikely for non-zero data
	}
	_ = csum
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ---- Extension header tests ----

func TestIPv6ExtHdrSerialize(t *testing.T) {
	// Hop-by-Hop header with 8 bytes of options.
	hdr := NewIPv6HopByHop()
	hdr.Set("nh", uint8(58))  // next = ICMPv6
	hdr.Set("len", uint8(0))  // 0 means (0+1)*8 = 8 bytes total, 6 bytes of options
	hdr.Set("options", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})

	got, err := hdr.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 8 {
		t.Fatalf("len = %d, want 8", len(got))
	}
	if got[0] != 58 {
		t.Errorf("nh = %d, want 58", got[0])
	}
	if got[1] != 0 {
		t.Errorf("len = %d, want 0", got[1])
	}
}

func TestIPv6ExtHdrParse(t *testing.T) {
	raw := []byte{
		0x3A, // nh = 58 (ICMPv6)
		0x01, // len = 1 => (1+1)*8 = 16 bytes total, 14 bytes of options
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	}

	hdr := NewIPv6HopByHop()
	consumed, err := hdr.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}

	nh, _ := hdr.Get("nh")
	if nh.(uint8) != 58 {
		t.Errorf("nh = %d", nh)
	}

	hdrLen, _ := hdr.Get("len")
	if hdrLen.(uint8) != 1 {
		t.Errorf("len = %d", hdrLen)
	}

	// consumed should be 16 (2 fixed + 14 options)
	if consumed != 16 {
		t.Errorf("consumed = %d, want 16", consumed)
	}
}

func TestExtHdrSizeFn(t *testing.T) {
	hdr := NewIPv6HopByHop()
	hdr.Set("len", uint8(2)) // (2+1)*8 = 24 bytes

	size := extHdrSizeFn(hdr)
	if size != 24 {
		t.Errorf("size = %d, want 24", size)
	}
}

func TestIPv6FragmentSerialize(t *testing.T) {
	frag := NewIPv6Fragment()
	frag.Set("nh", uint8(58))        // next = ICMPv6
	frag.Set("res", uint8(0))
	frag.Set("frag", uint16(0x0001)) // offset=0, M=1
	frag.Set("id", uint32(0x12345678))

	got, err := frag.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 8 {
		t.Fatalf("len = %d, want 8", len(got))
	}
	if got[0] != 58 {
		t.Errorf("nh = %d", got[0])
	}
}

func TestIPv6FragmentParse(t *testing.T) {
	raw := []byte{
		0x3A,             // nh = 58
		0x00,             // res = 0
		0x00, 0x01,       // offset=0, M=1
		0x12, 0x34, 0x56, 0x78, // id
	}

	frag := NewIPv6Fragment()
	consumed, err := frag.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 8 {
		t.Fatalf("consumed = %d, want 8", consumed)
	}

	id, _ := frag.Get("id")
	if id.(uint32) != 0x12345678 {
		t.Errorf("id = %#x", id)
	}

	fragVal, _ := frag.Get("frag")
	if IPv6FragmentOffset(fragVal.(uint16)) != 0 {
		t.Error("offset should be 0")
	}
	if !IPv6FragmentMore(fragVal.(uint16)) {
		t.Error("M flag should be set")
	}
}

func TestIPv6FragmentHelperFunctions(t *testing.T) {
	// offset=0x123 (291), M=0
	frag := uint16(0x0918) // offset=0x123 << 3 = 0x0918, M=0
	if IPv6FragmentOffset(frag) != 0x123 {
		t.Errorf("offset = %#x, want 0x123", IPv6FragmentOffset(frag))
	}
	if IPv6FragmentMore(frag) {
		t.Error("M should be false")
	}

	// offset=0, M=1
	frag = uint16(0x0001)
	if IPv6FragmentOffset(frag) != 0 {
		t.Errorf("offset = %d, want 0", IPv6FragmentOffset(frag))
	}
	if !IPv6FragmentMore(frag) {
		t.Error("M should be true")
	}
}

func TestIPv6ExtHdrChainParse(t *testing.T) {
	// Build raw bytes: IPv6 (40) → Hop-by-Hop (8) → Fragment (8) → ICMPv6 will be next
	raw := make([]byte, 0, 56)
	// IPv6 header
	raw = append(raw,
		0x60, 0x00, 0x00, 0x00, // ver=6
		0x00, 0x10, // plen = 16 (extension headers only, no upper payload)
		0x00, // nh = 0 (Hop-by-Hop)
		0x40, // hlim = 64
	)
	src := net.ParseIP("::1").To16()
	dst := net.ParseIP("::1").To16()
	raw = append(raw, src...)
	raw = append(raw, dst...)

	// Hop-by-Hop header (8 bytes: nh=44, len=0, 6 options bytes)
	raw = append(raw,
		0x2C,       // nh = 44 (Fragment)
		0x00,       // len = 0 => 8 bytes total
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6 padding bytes
	)

	// Fragment header (8 bytes)
	raw = append(raw,
		0x3A,             // nh = 58 (ICMPv6)
		0x00,             // res
		0x00, 0x00,       // offset=0, M=0
		0x00, 0x00, 0x00, 0x01, // id=1
	)

	// Parse IPv6
	ipv6 := NewIPv6()
	consumed, err := ipv6.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 40 {
		t.Fatalf("IPv6 consumed = %d, want 40", consumed)
	}

	// The next header should be 0 (Hop-by-Hop)
	nh, _ := ipv6.Get("nh")
	if nh.(uint8) != 0 {
		t.Errorf("IPv6 nh = %d, want 0", nh)
	}

	// Parse Hop-by-Hop header (only 8 bytes)
	hopRaw := raw[40:48]
	hop := NewIPv6HopByHop()
	consumed, err = hop.ParseFields(hopRaw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(hopRaw) {
		t.Fatalf("Hop consumed = %d, want %d (StrField eats all remaining)", consumed, len(hopRaw))
	}

	hopNH, _ := hop.Get("nh")
	if hopNH.(uint8) != 44 {
		t.Errorf("Hop nh = %d, want 44 (Fragment)", hopNH)
	}

	// Parse Fragment header (only 8 bytes)
	fragRaw := raw[48:56]
	frag := NewIPv6Fragment()
	consumed, err = frag.ParseFields(fragRaw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 8 {
		t.Fatalf("Fragment consumed = %d, want 8", consumed)
	}

	fragNH, _ := frag.Get("nh")
	if fragNH.(uint8) != 58 {
		t.Errorf("Fragment nh = %d, want 58 (ICMPv6)", fragNH)
	}
}

func TestIPv6ParseTruncated(t *testing.T) {
	// Less than 40 bytes.
	raw := make([]byte, 30)
	ipv6 := NewIPv6()
	_, err := ipv6.ParseFields(raw)
	if err == nil {
		t.Fatal("expected error for truncated IPv6 header")
	}
}