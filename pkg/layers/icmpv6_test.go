package layers

import (
	"bytes"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

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

func TestICMPv6SerializeFields(t *testing.T) {
	// ICMPv6 Echo Request: type=128, code=0, chksum=0, id=0x1234, seq=1, data="hello"
	icmp := NewICMPv6()
	icmp.Set("type", uint8(128))
	icmp.Set("code", uint8(0))
	icmp.Set("chksum", uint16(0))
	icmp.Set("id", uint16(0x1234))
	icmp.Set("seq", uint16(1))
	icmp.Set("data", []byte("hello"))

	got, err := icmp.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 13 {
		t.Fatalf("len = %d, want 13", len(got))
	}
	if got[0] != 128 {
		t.Errorf("type = %d, want 128", got[0])
	}
	if got[1] != 0 {
		t.Errorf("code = %d, want 0", got[1])
	}
}

func TestICMPv6ParseFields(t *testing.T) {
	// ICMPv6 Echo Reply: type=129, code=0, chksum=0xABCD, id=0x1234, seq=1, data="world"
	raw := []byte{
		0x81, 0x00, // type=129, code=0
		0xAB, 0xCD, // checksum
		0x12, 0x34, // id
		0x00, 0x01, // seq
		'w', 'o', 'r', 'l', 'd',
	}

	icmp := NewICMPv6()
	consumed, err := icmp.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 13 {
		t.Fatalf("consumed = %d, want 13", consumed)
	}

	typ, _ := icmp.Get("type")
	if typ.(uint8) != 129 {
		t.Errorf("type = %d, want 129", typ)
	}

	code, _ := icmp.Get("code")
	if code.(uint8) != 0 {
		t.Errorf("code = %d, want 0", code)
	}

	csum, _ := icmp.Get("chksum")
	if csum.(uint16) != 0xABCD {
		t.Errorf("chksum = %#x, want 0xABCD", csum)
	}

	id, _ := icmp.Get("id")
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x, want 0x1234", id)
	}

	seq, _ := icmp.Get("seq")
	if seq.(uint16) != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}

	data, _ := icmp.Get("data")
	if !bytes.Equal(data.([]byte), []byte("world")) {
		t.Errorf("data = %q, want \"world\"", data)
	}
}

func TestICMPv6ChecksumVerification(t *testing.T) {
	// Verify checksum with known values: src=::1, dst=::1, nh=58.
	srcIP := net.ParseIP("::1").To16()
	dstIP := net.ParseIP("::1").To16()

	// ICMPv6 Echo Request without checksum.
	msg := []byte{
		0x80, 0x00, // type=128, code=0
		0x00, 0x00, // checksum = 0 (for computation)
		0x12, 0x34, // id
		0x00, 0x01, // seq
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

	// ICMPv6 Echo Request with data payload.
	hdr := []byte{
		0x80, 0x00, // type=128, code=0
		0x00, 0x00, // checksum = 0
		0x12, 0x34, // id
		0x00, 0x01, // seq
	}
	data := []byte("hello")
	msg := append(hdr, data...)

	csum := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, msg)
	msg[2] = byte(csum >> 8)
	msg[3] = byte(csum)

	verify := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, msg)
	if verify != 0 {
		t.Errorf("checksum verification with data failed: got %#x, want 0", verify)
	}
}

func TestICMPv6BuildHook(t *testing.T) {
	ipv6 := NewIPv6()
	ipv6.Set("src", "::1")
	ipv6.Set("dst", "::1")

	icmp := NewICMPv6Echo(0x1234, 1)
	icmp.Set("data", []byte("hello"))

	// Build packet: layers = [IPv6, ICMPv6]
	pkt := packet.NewFrom(ipv6)
	pkt.Push(icmp)

	// Manually invoke build hook to verify checksum.
	got, err := icmpv6BuildHook(pkt, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	chksum, _ := icmp.Get("chksum")
	if chksum.(uint16) == 0 {
		t.Error("checksum should be non-zero after build hook")
	}

	// Verify checksum is valid.
	srcIP := net.ParseIP("::1").To16()
	dstIP := net.ParseIP("::1").To16()
	verify := IPv6PseudoHeaderChecksum(srcIP, dstIP, 58, got)
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
			t.Fatalf("%s: SerializeFields error: %v", tt.name, err)
		}

		if got[0] != tt.val {
			t.Errorf("%s: type byte = %d, want %d", tt.name, got[0], tt.val)
		}
	}
}

func TestICMPv6ParseTruncated(t *testing.T) {
	raw := make([]byte, 3) // Need at least 4 bytes (type+code+chksum)
	icmp := NewICMPv6()
	_, err := icmp.ParseFields(raw)
	// Should fail because "id" field needs 2 bytes and only 3 available.
	if err == nil {
		t.Fatal("expected error for truncated ICMPv6")
	}
}

func TestICMPv6RoundTrip(t *testing.T) {
	icmp := NewICMPv6()
	icmp.Set("type", ICMPv6EchoRequest)
	icmp.Set("code", uint8(0))
	icmp.Set("id", uint16(0x1234))
	icmp.Set("seq", uint16(1))
	icmp.Set("data", []byte("testdata"))

	ser, err := icmp.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	icmp2 := NewICMPv6()
	_, err = icmp2.ParseFields(ser)
	if err != nil {
		t.Fatal(err)
	}

	typ, _ := icmp2.Get("type")
	if typ.(uint8) != ICMPv6EchoRequest {
		t.Errorf("type = %d", typ)
	}
	id, _ := icmp2.Get("id")
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	seq, _ := icmp2.Get("seq")
	if seq.(uint16) != 1 {
		t.Errorf("seq = %d", seq)
	}
	data, _ := icmp2.Get("data")
	if !bytes.Equal(data.([]byte), []byte("testdata")) {
		t.Errorf("data = %q", data)
	}
}