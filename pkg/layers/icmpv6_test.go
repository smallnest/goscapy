package layers

import (
	"bytes"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- ICMPv6 base header tests (refactored: 4-byte header) ----

func TestNewICMPv6Defaults(t *testing.T) {
	icmp := NewICMPv6()

	typ, _ := icmp.Get("type")
	if typ.(uint8) != ICMPv6EchoRequest {
		t.Errorf("type = %d, want 128", typ)
	}

	code, _ := icmp.Get("code")
	if code.(uint8) != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestICMPv6Serialize(t *testing.T) {
	icmp := NewICMPv6()
	icmp.Set("type", uint8(128))
	icmp.Set("code", uint8(0))
	icmp.Set("chksum", uint16(0))

	got, err := icmp.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	if got[0] != 128 {
		t.Errorf("type = %d", got[0])
	}
	if got[1] != 0 {
		t.Errorf("code = %d", got[1])
	}
}

func TestICMPv6Parse(t *testing.T) {
	raw := []byte{0x81, 0x00, 0x12, 0x34} // type=129, code=0, chksum=0x1234

	icmp := NewICMPv6()
	consumed, err := icmp.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 4 {
		t.Fatalf("consumed = %d, want 4", consumed)
	}

	typ, _ := icmp.Get("type")
	if typ.(uint8) != 129 {
		t.Errorf("type = %d, want 129", typ)
	}
	code, _ := icmp.Get("code")
	if code.(uint8) != 0 {
		t.Errorf("code = %d", code)
	}
	csum, _ := icmp.Get("chksum")
	if csum.(uint16) != 0x1234 {
		t.Errorf("chksum = %#x", csum)
	}
}

func TestICMPv6ChecksumVerification(t *testing.T) {
	srcIP := net.ParseIP("::1").To16()
	dstIP := net.ParseIP("::1").To16()

	// ICMPv6 base header (4 bytes) + Echo body (4 bytes id+seq).
	msg := []byte{
		0x80, 0x00, 0x00, 0x00, // type=128, code=0, chksum=0
		0x12, 0x34, 0x00, 0x01, // id, seq
	}

	csum := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, msg)
	msg[2] = byte(csum >> 8)
	msg[3] = byte(csum)

	verify := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, msg)
	if verify != 0 {
		t.Errorf("checksum verification failed: got %#x, want 0", verify)
	}
}

func TestICMPv6ChecksumWithData(t *testing.T) {
	srcIP := net.ParseIP("::1").To16()
	dstIP := net.ParseIP("::1").To16()

	hdr := []byte{0x80, 0x00, 0x00, 0x00} // type=128, code=0, chksum=0
	echo := []byte{0x12, 0x34, 0x00, 0x01} // id, seq
	data := []byte("hello")
	msg := append(append(hdr, echo...), data...)

	csum := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, msg)
	msg[2] = byte(csum >> 8)
	msg[3] = byte(csum)

	verify := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, msg)
	if verify != 0 {
		t.Errorf("checksum with data failed: got %#x, want 0", verify)
	}
}

func TestICMPv6BuildHook(t *testing.T) {
	ipv6 := NewIPv6()
	ipv6.Set("src", "::1")
	ipv6.Set("dst", "::1")

	icmpBase := NewICMPv6()
	icmpBase.Set("type", ICMPv6EchoRequest)
	icmpBase.Set("code", uint8(0))

	echo := NewICMPv6Echo(0x1234, 1)
	echo.Set("data", []byte("hello"))

	pkt := packet.NewFrom(ipv6)
	pkt.Push(icmpBase)
	pkt.Push(echo)

	// Upper bytes for ICMPv6 base = Echo sub-layer bytes.
	echoBytes, _ := echo.SerializeFields()
	buf := make([]byte, icmpBase.WireSize())
	n, err := icmpv6BuildHook(pkt, 1, echoBytes, buf)
	if err != nil {
		t.Fatal(err)
	}

	chksum, _ := icmpBase.Get("chksum")
	if chksum.(uint16) == 0 {
		t.Error("checksum should be non-zero after build hook")
	}

	// Verify checksum with pseudo-header.
	srcIP := net.ParseIP("::1").To16()
	dstIP := net.ParseIP("::1").To16()
	fullMsg := append(buf[:n], echoBytes...)
	verify := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, fullMsg)
	if verify != 0 {
		t.Errorf("build hook checksum invalid: got %#x, want 0", verify)
	}
}

func TestICMPv6AllTypes(t *testing.T) {
	types := []struct {
		val  uint8
		name string
	}{
		{1, "DestUnreach"},
		{2, "PacketTooBig"},
		{3, "TimeExceed"},
		{4, "ParamProblem"},
		{128, "EchoRequest"},
		{129, "EchoReply"},
	}

	for _, tt := range types {
		icmp := NewICMPv6()
		icmp.Set("type", tt.val)
		icmp.Set("code", uint8(0))

		got, err := icmp.SerializeFields()
		if err != nil {
			t.Fatalf("%s: error: %v", tt.name, err)
		}
		if got[0] != tt.val {
			t.Errorf("%s: type byte = %d", tt.name, got[0])
		}
	}
}

func TestICMPv6ParseTruncated(t *testing.T) {
	icmp := NewICMPv6()
	_, err := icmp.ParseFields([]byte{0x80}) // need 4 bytes, got 1
	if err == nil {
		t.Fatal("expected error for truncated ICMPv6")
	}
}

// ---- ICMPv6 Echo sub-layer tests ----

func TestICMPv6EchoSerialize(t *testing.T) {
	echo := NewICMPv6Echo(0x1234, 1)
	echo.Set("data", []byte("hello"))

	got, err := echo.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 9 {
		t.Fatalf("len = %d, want 9 (id+seq+data)", len(got))
	}
}

func TestICMPv6EchoParse(t *testing.T) {
	raw := []byte{
		0x12, 0x34, // id
		0x00, 0x01, // seq
		'w', 'o', 'r', 'l', 'd',
	}

	echo := NewICMPv6Echo(0, 0)
	consumed, err := echo.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 9 {
		t.Fatalf("consumed = %d, want 9", consumed)
	}

	id, _ := echo.Get("id")
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	seq, _ := echo.Get("seq")
	if seq.(uint16) != 1 {
		t.Errorf("seq = %d", seq)
	}
	data, _ := echo.Get("data")
	if !bytes.Equal(data.([]byte), []byte("world")) {
		t.Errorf("data = %q", data)
	}
}

func TestICMPv6EchoRoundTrip(t *testing.T) {
	echo := NewICMPv6Echo(0x1234, 1)
	echo.Set("data", []byte("testdata"))

	ser, _ := echo.SerializeFields()
	echo2 := NewICMPv6Echo(0, 0)
	_, err := echo2.ParseFields(ser)
	if err != nil {
		t.Fatal(err)
	}

	id, _ := echo2.Get("id")
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	seq, _ := echo2.Get("seq")
	if seq.(uint16) != 1 {
		t.Errorf("seq = %d", seq)
	}
}

// ---- Packed build: IPv6 + ICMPv6 base + ICMPv6 Echo ----

func TestICMPv6PackedBuild(t *testing.T) {
	ipv6 := NewIPv6()
	ipv6.Set("src", "::1")
	ipv6.Set("dst", "::1")

	icmpBase := NewICMPv6()
	icmpBase.Set("type", ICMPv6EchoRequest)
	icmpBase.Set("code", uint8(0))

	echo := NewICMPv6Echo(0x1234, 1)

	pkt := packet.NewFrom(ipv6)
	pkt.Push(icmpBase)
	pkt.Push(echo)

	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// 40 (IPv6) + 4 (ICMPv6 base) + 4 (Echo: id+seq) = 48
	if len(raw) != 48 {
		t.Fatalf("packet len = %d, want 48", len(raw))
	}

	// Parse back and verify.
	pkt2, err := packet.DissectByProto(raw, "IPv6")
	if err != nil {
		t.Fatal(err)
	}

	plen, _ := pkt2.GetLayer("IPv6").Get("plen")
	if plen.(uint16) != 8 {
		t.Errorf("IPv6 plen = %d, want 8", plen)
	}
}