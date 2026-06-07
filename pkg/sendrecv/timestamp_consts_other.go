//go:build !linux && !darwin

package sendrecv

const (
	soTimestamp   = 0
	soTimestampNS = 0
	soTimestamping = 0
)
