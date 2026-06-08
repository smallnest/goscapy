//go:build linux

package sendrecv

import "golang.org/x/sys/unix"

const (
	soTimestamp    = unix.SO_TIMESTAMP
	soTimestampNS  = unix.SO_TIMESTAMPNS
	soTimestamping = unix.SO_TIMESTAMPING
)
