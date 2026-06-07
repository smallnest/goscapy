//go:build !linux && !darwin

package sendrecv

// ParseTimestamp is not supported on this platform.
func ParseTimestamp(oob []byte) (Timestamp, bool) {
	return Timestamp{}, false
}
