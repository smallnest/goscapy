//go:build darwin

package sendrecv

import "syscall"

const (
	soTimestamp    = syscall.SO_TIMESTAMP
	soTimestampNS  = 0x1A // SO_TIMESTAMPNS is not in syscall; unused on darwin
	soTimestamping = 0    // unavailable on macOS
)
