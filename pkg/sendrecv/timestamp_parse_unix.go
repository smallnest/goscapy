//go:build linux || darwin

package sendrecv

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
	fieldSize := tsSize / 2 // each field is half the struct
	switch fieldSize {
	case 8: // 64-bit
		sec = int64(binary.NativeEndian.Uint64(buf[offset : offset+8]))
		nsec = int64(binary.NativeEndian.Uint64(buf[offset+8 : offset+16]))
	default: // 32-bit (fieldSize == 4)
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
	case 8: // 64-bit
		sec = int64(binary.NativeEndian.Uint64(buf[offset : offset+8]))
		usec = int64(binary.NativeEndian.Uint64(buf[offset+8 : offset+16]))
	default: // 32-bit
		sec = int64(binary.NativeEndian.Uint32(buf[offset : offset+4]))
		usec = int64(binary.NativeEndian.Uint32(buf[offset+4 : offset+8]))
	}
	return sec, usec, true
}

// ParseTimestamp extracts a Timestamp from socket control messages returned
// by syscall.Recvmsg. It recognises:
//
//   - Linux SO_TIMESTAMPNS  (cmsg level SOL_SOCKET, type SO_TIMESTAMPNS)
//   - Linux SO_TIMESTAMPING  (cmsg level SOL_SOCKET, type SO_TIMESTAMPING)
//   - macOS/POSIX SO_TIMESTAMP (cmsg level SOL_SOCKET, type SO_TIMESTAMP)
//
// Returns the first recognised timestamp found. If no timestamp cmsg is
// present, it returns the zero value and false.
func ParseTimestamp(oob []byte) (Timestamp, bool) {
	cmsgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return Timestamp{}, false
	}

	for _, cmsg := range cmsgs {
		if cmsg.Header.Level != syscall.SOL_SOCKET {
			continue
		}

		switch cmsg.Header.Type {
		case soTimestampNS:
			sec, nsec, ok := parseTimespec(cmsg.Data, 0)
			if !ok {
				continue
			}
			return Timestamp{
				Time:   parseTime(sec, nsec),
				Source: TimestampSoftware,
			}, true

		case soTimestamping:
			// SO_TIMESTAMPING returns up to 3 struct timespec:
			//   [0] software   [1] hardware  [2] hardware raw
			tsSize := int(unsafe.Sizeof(syscall.Timespec{}))
			if len(cmsg.Data) >= tsSize*3 {
				// Check hardware timestamp (index 1) first.
				hwSec, hwNsec, ok := parseTimespec(cmsg.Data, tsSize*1)
				if ok && (hwSec != 0 || hwNsec != 0) {
					return Timestamp{
						Time:   parseTime(hwSec, hwNsec),
						Source: TimestampHardware,
					}, true
				}
				// Fall back to software timestamp (index 0).
				swSec, swNsec, ok := parseTimespec(cmsg.Data, 0)
				if ok {
					return Timestamp{
						Time:   parseTime(swSec, swNsec),
						Source: TimestampSoftware,
					}, true
				}
			} else if len(cmsg.Data) >= tsSize {
				swSec, swNsec, ok := parseTimespec(cmsg.Data, 0)
				if ok {
					return Timestamp{
						Time:   parseTime(swSec, swNsec),
						Source: TimestampSoftware,
					}, true
				}
			}

		case soTimestamp:
			sec, usec, ok := parseTimeval(cmsg.Data, 0)
			if !ok {
				continue
			}
			return Timestamp{
				Time:   parseTime(sec, usec*1000),
				Source: TimestampSoftware,
			}, true
		}
	}

	return Timestamp{}, false
}
