package sendrecv

import "time"

// Timestamp represents a packet timestamp with its source.
type Timestamp struct {
	// Time is the kernel- or NIC-reported timestamp.
	Time time.Time
	// Source indicates where the timestamp was captured.
	Source TimestampSource
}

// TimestampSource describes where a packet timestamp originated.
type TimestampSource int

const (
	// TimestampSoftware indicates a kernel-generated software timestamp.
	TimestampSoftware TimestampSource = iota
	// TimestampHardware indicates a NIC-generated hardware timestamp.
	TimestampHardware
	// TimestampUnknown indicates the timestamp source could not be determined.
	TimestampUnknown
)
