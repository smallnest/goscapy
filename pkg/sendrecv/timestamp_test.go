//go:build linux || darwin

package sendrecv

import (
	"encoding/binary"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestEnableTimestampingSoftware(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.EnableTimestamping(false); err != nil {
		t.Fatalf("EnableTimestamping(false): %v", err)
	}
}

func TestEnableTimestampingHardware(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Hardware timestamping may not be supported by the NIC but the
	// setsockopt should still succeed — the kernel degrades gracefully.
	if err := conn.EnableTimestamping(true); err != nil {
		t.Fatalf("EnableTimestamping(true): %v", err)
	}
}

func TestParseTimestampSO_TIMESTAMP(t *testing.T) {
	// Simulate an SO_TIMESTAMP control message containing a struct timeval.
	// struct timeval { tv_sec int64; tv_usec int64; } on macOS.
	sec := int64(1700000000)
	usec := int64(123456)

	// Build cmsg data: timeval payload
	tvData := make([]byte, 16)
	binary.NativeEndian.PutUint64(tvData[0:8], uint64(sec))
	binary.NativeEndian.PutUint64(tvData[8:16], uint64(usec))

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestamp, tvData)

	ts, ok := ParseTimestamp(oob)
	if !ok {
		t.Fatal("ParseTimestamp returned false")
	}
	if ts.Source != TimestampSoftware {
		t.Errorf("expected TimestampSoftware, got %d", ts.Source)
	}
	expected := time.Unix(sec, usec*1000)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestampSO_TIMESTAMPNS(t *testing.T) {
	if soTimestampNS == 0 {
		t.Skip("SO_TIMESTAMPNS not available on this platform")
	}

	sec := int64(1700000000)
	nsec := int64(987654321)

	tsData := make([]byte, 16)
	binary.NativeEndian.PutUint64(tsData[0:8], uint64(sec))
	binary.NativeEndian.PutUint64(tsData[8:16], uint64(nsec))

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestampNS, tsData)

	ts, ok := ParseTimestamp(oob)
	if !ok {
		t.Fatal("ParseTimestamp returned false")
	}
	if ts.Source != TimestampSoftware {
		t.Errorf("expected TimestampSoftware, got %d", ts.Source)
	}
	expected := time.Unix(sec, nsec)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestampSO_TIMESTAMPING_SoftwareOnly(t *testing.T) {
	if soTimestamping == 0 {
		t.Skip("SO_TIMESTAMPING not available on this platform")
	}

	sec := int64(1700000000)
	nsec := int64(500000000)

	// 3 × struct timespec (16 bytes each = 48 bytes)
	data := make([]byte, 48)
	// Index 0: software timestamp
	binary.NativeEndian.PutUint64(data[0:8], uint64(sec))
	binary.NativeEndian.PutUint64(data[8:16], uint64(nsec))
	// Index 1: hardware (zero = not available)
	// Index 2: hardware raw (zero)

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestamping, data)

	ts, ok := ParseTimestamp(oob)
	if !ok {
		t.Fatal("ParseTimestamp returned false")
	}
	if ts.Source != TimestampSoftware {
		t.Errorf("expected TimestampSoftware, got %d", ts.Source)
	}
	expected := time.Unix(sec, nsec)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestampSO_TIMESTAMPING_Hardware(t *testing.T) {
	if soTimestamping == 0 {
		t.Skip("SO_TIMESTAMPING not available on this platform")
	}

	swSec := int64(1700000000)
	swNsec := int64(100000000)
	hwSec := int64(1700000000)
	hwNsec := int64(200000000)

	data := make([]byte, 48)
	// Index 0: software
	binary.NativeEndian.PutUint64(data[0:8], uint64(swSec))
	binary.NativeEndian.PutUint64(data[8:16], uint64(swNsec))
	// Index 1: hardware (non-zero → should be preferred)
	binary.NativeEndian.PutUint64(data[16:24], uint64(hwSec))
	binary.NativeEndian.PutUint64(data[24:32], uint64(hwNsec))
	// Index 2: hardware raw (zero)

	oob := buildCmsg(t, syscall.SOL_SOCKET, soTimestamping, data)

	ts, ok := ParseTimestamp(oob)
	if !ok {
		t.Fatal("ParseTimestamp returned false")
	}
	if ts.Source != TimestampHardware {
		t.Errorf("expected TimestampHardware, got %d", ts.Source)
	}
	expected := time.Unix(hwSec, hwNsec)
	if !ts.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts.Time)
	}
}

func TestParseTimestampEmpty(t *testing.T) {
	_, ok := ParseTimestamp(nil)
	if ok {
		t.Error("expected false for nil oob")
	}
	_, ok = ParseTimestamp([]byte{})
	if ok {
		t.Error("expected false for empty oob")
	}
}

// buildCmsg constructs a single socket control message for testing.
func buildCmsg(t *testing.T, level, typ int32, data []byte) []byte {
	t.Helper()
	hdrSize := int(syscall.SizeofCmsghdr)
	dataLen := len(data)
	// Pad data to 8-byte alignment
	padded := dataLen
	if padded%8 != 0 {
		padded += 8 - padded%8
	}
	total := hdrSize + padded
	buf := make([]byte, total)

	// Write cmsghdr — layout varies by platform:
	//   macOS: {Len uint32, Level int32, Type int32}   = 12 bytes
	//   Linux: {Len uint64, Level int32, Type int32}   = 16 bytes (with padding)
	if hdrSize == 12 {
		binary.NativeEndian.PutUint32(buf[0:4], uint32(total)) // cmsg_len
		binary.NativeEndian.PutUint32(buf[4:8], uint32(level)) // cmsg_level
		binary.NativeEndian.PutUint32(buf[8:12], uint32(typ))  // cmsg_type
	} else {
		binary.NativeEndian.PutUint64(buf[0:8], uint64(total))  // cmsg_len
		binary.NativeEndian.PutUint32(buf[8:12], uint32(level)) // cmsg_level
		binary.NativeEndian.PutUint32(buf[12:16], uint32(typ))  // cmsg_type
	}
	copy(buf[hdrSize:], data)
	return buf
}
