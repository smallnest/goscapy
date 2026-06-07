//go:build linux || darwin

package cmsg

import (
	"syscall"
	"unsafe"
)

// ParseTimestamping extracts a Timestamp from socket control messages returned
// by syscall.Recvmsg. It recognises:
//
//   - Linux SO_TIMESTAMPNS  (level SOL_SOCKET, type SO_TIMESTAMPNS)
//   - Linux SO_TIMESTAMPING  (level SOL_SOCKET, type SO_TIMESTAMPING)
//   - macOS/POSIX SO_TIMESTAMP (level SOL_SOCKET, type SO_TIMESTAMP)
//
// Returns the first recognised timestamp found. If no timestamp cmsg is
// present, it returns the zero value and ErrNotSupported.
func ParseTimestamping(oob []byte) (Timestamp, error) {
	cmsgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return Timestamp{}, err
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
			}, nil

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
					}, nil
				}
				// Fall back to software timestamp (index 0).
				swSec, swNsec, ok := parseTimespec(cmsg.Data, 0)
				if ok {
					return Timestamp{
						Time:   parseTime(swSec, swNsec),
						Source: TimestampSoftware,
					}, nil
				}
			} else if len(cmsg.Data) >= tsSize {
				swSec, swNsec, ok := parseTimespec(cmsg.Data, 0)
				if ok {
					return Timestamp{
						Time:   parseTime(swSec, swNsec),
						Source: TimestampSoftware,
					}, nil
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
			}, nil
		}
	}

	return Timestamp{}, ErrNotSupported
}
