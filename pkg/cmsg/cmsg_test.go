//go:build linux || darwin

package cmsg

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"
)

// buildCmsg constructs a single socket control message for testing.
func buildCmsg(t *testing.T, level, typ int32, data []byte) []byte {
	t.Helper()
	hdrSize := int(syscall.SizeofCmsghdr)
	padded := len(data)
	if padded%8 != 0 {
		padded += 8 - padded%8
	}
	total := hdrSize + padded
	buf := make([]byte, total)

	if hdrSize == 12 {
		binary.NativeEndian.PutUint32(buf[0:4], uint32(total))
		binary.NativeEndian.PutUint32(buf[4:8], uint32(level))
		binary.NativeEndian.PutUint32(buf[8:12], uint32(typ))
	} else {
		binary.NativeEndian.PutUint64(buf[0:8], uint64(total))
		binary.NativeEndian.PutUint32(buf[8:12], uint32(level))
		binary.NativeEndian.PutUint32(buf[12:16], uint32(typ))
	}
	copy(buf[hdrSize:], data)
	return buf
}

// ---- ParseTimestamping tests ----

func TestParseTimestamping_SO_TIMESTAMP(t *testing.T) {
	sec := int64(1700000000)
	usec := int64(123456)

	tvData := make([]byte, 16)
	binary.NativeEndian.PutUint64(tvData[0:8], uint64(sec))
	binary.NativeEndian.PutUint64(tvData[8:16], uint64(usec))

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestamp, tvData)

	ts, err := ParseTimestamping(oob)
	if err != nil {
		t.Fatalf("ParseTimestamping returned error: %v", err)
	}
	if ts.Source != TimestampSoftware {
		t.Errorf("expected TimestampSoftware, got %d", ts.Source)
	}
	expected := time.Unix(sec, usec*1000)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestamping_SO_TIMESTAMPNS(t *testing.T) {
	if soTimestampNS == 0 {
		t.Skip("SO_TIMESTAMPNS not available on this platform")
	}

	sec := int64(1700000000)
	nsec := int64(987654321)

	tsData := make([]byte, 16)
	binary.NativeEndian.PutUint64(tsData[0:8], uint64(sec))
	binary.NativeEndian.PutUint64(tsData[8:16], uint64(nsec))

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestampNS, tsData)

	ts, err := ParseTimestamping(oob)
	if err != nil {
		t.Fatalf("ParseTimestamping returned error: %v", err)
	}
	if ts.Source != TimestampSoftware {
		t.Errorf("expected TimestampSoftware, got %d", ts.Source)
	}
	expected := time.Unix(sec, nsec)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestamping_SO_TIMESTAMPING_SoftwareOnly(t *testing.T) {
	if soTimestamping == 0 {
		t.Skip("SO_TIMESTAMPING not available on this platform")
	}

	sec := int64(1700000000)
	nsec := int64(500000000)

	data := make([]byte, 48)
	binary.NativeEndian.PutUint64(data[0:8], uint64(sec))
	binary.NativeEndian.PutUint64(data[8:16], uint64(nsec))
	// Index 1 (hw) and 2 (hw raw) are zero.

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestamping, data)

	ts, err := ParseTimestamping(oob)
	if err != nil {
		t.Fatalf("ParseTimestamping returned error: %v", err)
	}
	if ts.Source != TimestampSoftware {
		t.Errorf("expected TimestampSoftware, got %d", ts.Source)
	}
	expected := time.Unix(sec, nsec)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestamping_SO_TIMESTAMPING_Hardware(t *testing.T) {
	if soTimestamping == 0 {
		t.Skip("SO_TIMESTAMPING not available on this platform")
	}

	swSec := int64(1700000000)
	swNsec := int64(100000000)
	hwSec := int64(1700000000)
	hwNsec := int64(200000000)

	data := make([]byte, 48)
	binary.NativeEndian.PutUint64(data[0:8], uint64(swSec))
	binary.NativeEndian.PutUint64(data[8:16], uint64(swNsec))
	binary.NativeEndian.PutUint64(data[16:24], uint64(hwSec))
	binary.NativeEndian.PutUint64(data[24:32], uint64(hwNsec))

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestamping, data)

	ts, err := ParseTimestamping(oob)
	if err != nil {
		t.Fatalf("ParseTimestamping returned error: %v", err)
	}
	if ts.Source != TimestampHardware {
		t.Errorf("expected TimestampHardware, got %d", ts.Source)
	}
	expected := time.Unix(hwSec, hwNsec)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestamping_Empty(t *testing.T) {
	_, err := ParseTimestamping(nil)
	if err == nil {
		t.Error("expected error for nil oob")
	}
	_, err = ParseTimestamping([]byte{})
	if err == nil {
		t.Error("expected error for empty oob")
	}
}

func TestParseTimestamping_NoMatchingCmsg(t *testing.T) {
	// Build a cmsg with an unrecognized type.
	data := make([]byte, 16)
	oob := buildCmsg(t, syscall.SOL_SOCKET, 0xFFFE, data)

	_, err := ParseTimestamping(oob)
	if err == nil {
		t.Error("expected error for non-timestamp cmsg")
	}
}

// ---- ParsePktInfo tests ----

func TestParsePktInfo_IP_PKTINFO(t *testing.T) {
	if ipPktInfo == 0 {
		t.Skip("IP_PKTINFO not available on this platform")
	}

	// struct in_pktinfo: ifindex(4) + spec_dst(4) + addr(4) = 12 bytes
	data := make([]byte, 12)
	binary.NativeEndian.PutUint32(data[0:4], 2) // ifindex = 2
	copy(data[4:8], []byte{192, 168, 1, 1})     // spec_dst
	copy(data[8:12], []byte{10, 0, 0, 1})       // addr

	oob := buildCmsg(t, int32(ipProtoIP), ipPktInfo, data)

	pi, err := ParsePktInfo(oob)
	if err != nil {
		t.Fatalf("ParsePktInfo returned error: %v", err)
	}
	if pi.IsIPv6 {
		t.Error("expected IPv4 pktinfo")
	}
	if pi.IPv4.IfIndex != 2 {
		t.Errorf("expected ifindex 2, got %d", pi.IPv4.IfIndex)
	}
	expectedSpecDst := net.IPv4(192, 168, 1, 1)
	if !pi.IPv4.SpecDst.Equal(expectedSpecDst) {
		t.Errorf("expected spec_dst %v, got %v", expectedSpecDst, pi.IPv4.SpecDst)
	}
	expectedAddr := net.IPv4(10, 0, 0, 1)
	if !pi.IPv4.Addr.Equal(expectedAddr) {
		t.Errorf("expected addr %v, got %v", expectedAddr, pi.IPv4.Addr)
	}
}

func TestParsePktInfo_IPV6_PKTINFO(t *testing.T) {
	if ipv6PktInfo == 0 {
		t.Skip("IPV6_PKTINFO not available on this platform")
	}

	// struct in6_pktinfo: addr(16) + ifindex(4) = 20 bytes
	data := make([]byte, 20)
	addr := net.ParseIP("::1")
	copy(data[0:16], addr.To16())
	binary.NativeEndian.PutUint32(data[16:20], 3) // ifindex = 3

	oob := buildCmsg(t, int32(ipProtoIPv6), ipv6PktInfo, data)

	pi, err := ParsePktInfo(oob)
	if err != nil {
		t.Fatalf("ParsePktInfo returned error: %v", err)
	}
	if !pi.IsIPv6 {
		t.Error("expected IPv6 pktinfo")
	}
	if pi.IPv6.IfIndex != 3 {
		t.Errorf("expected ifindex 3, got %d", pi.IPv6.IfIndex)
	}
	if !pi.IPv6.Addr.Equal(net.IPv6loopback) {
		t.Errorf("expected ::1, got %v", pi.IPv6.Addr)
	}
}

func TestParsePktInfo_Empty(t *testing.T) {
	_, err := ParsePktInfo(nil)
	if err == nil {
		t.Error("expected error for nil oob")
	}
	_, err = ParsePktInfo([]byte{})
	if err == nil {
		t.Error("expected error for empty oob")
	}
}

func TestParsePktInfo_NoMatchingCmsg(t *testing.T) {
	data := make([]byte, 12)
	oob := buildCmsg(t, syscall.SOL_SOCKET, 0xFFFE, data)

	_, err := ParsePktInfo(oob)
	if err == nil {
		t.Error("expected error for non-pktinfo cmsg")
	}
}

func TestParsePktInfo_TruncatedIPv4(t *testing.T) {
	if ipPktInfo == 0 {
		t.Skip("IP_PKTINFO not available on this platform")
	}

	// Only 8 bytes — too short for in_pktinfo (needs 12).
	data := make([]byte, 8)
	oob := buildCmsg(t, int32(ipProtoIP), ipPktInfo, data)

	_, err := ParsePktInfo(oob)
	if err == nil {
		t.Error("expected error for truncated pktinfo")
	}
}

func TestParsePktInfo_TruncatedIPv6(t *testing.T) {
	if ipv6PktInfo == 0 {
		t.Skip("IPV6_PKTINFO not available on this platform")
	}

	// Only 10 bytes — too short for in6_pktinfo (needs 20).
	data := make([]byte, 10)
	oob := buildCmsg(t, int32(ipProtoIPv6), ipv6PktInfo, data)

	_, err := ParsePktInfo(oob)
	if err == nil {
		t.Error("expected error for truncated ipv6 pktinfo")
	}
}

