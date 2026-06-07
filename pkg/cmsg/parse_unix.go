//go:build linux || darwin

package cmsg

import (
	"encoding/binary"
	"syscall"
	"time"
	"unsafe"
)

// parseTime converts seconds and nanoseconds into a time.Time.
func parseTime(sec, nsec int64) time.Time {
	return time.Unix(sec, nsec)
}

// parseTimespec reads a kernel struct timespec from buf at offset.
// Handles both 64-bit (sec=int64, nsec=int64, 16 bytes) and
// 32-bit (sec=int32, nsec=int32, 8 bytes) layouts.
func parseTimespec(buf []byte, offset int) (sec, nsec int64, ok bool) {
	tsSize := int(unsafe.Sizeof(syscall.Timespec{}))
	if offset+tsSize > len(buf) {
		return 0, 0, false
	}
	fieldSize := tsSize / 2
	switch fieldSize {
	case 8:
		sec = int64(binary.NativeEndian.Uint64(buf[offset : offset+8]))
		nsec = int64(binary.NativeEndian.Uint64(buf[offset+8 : offset+16]))
	default:
		sec = int64(binary.NativeEndian.Uint32(buf[offset : offset+4]))
		nsec = int64(binary.NativeEndian.Uint32(buf[offset+4 : offset+8]))
	}
	return sec, nsec, true
}

// parseTimeval reads a kernel struct timeval from buf at offset.
func parseTimeval(buf []byte, offset int) (sec, usec int64, ok bool) {
	tvSize := int(unsafe.Sizeof(syscall.Timeval{}))
	if offset+tvSize > len(buf) {
		return 0, 0, false
	}
	fieldSize := tvSize / 2
	switch fieldSize {
	case 8:
		sec = int64(binary.NativeEndian.Uint64(buf[offset : offset+8]))
		usec = int64(binary.NativeEndian.Uint64(buf[offset+8 : offset+16]))
	default:
		sec = int64(binary.NativeEndian.Uint32(buf[offset : offset+4]))
		usec = int64(binary.NativeEndian.Uint32(buf[offset+4 : offset+8]))
	}
	return sec, usec, true
}
