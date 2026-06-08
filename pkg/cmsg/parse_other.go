//go:build !linux && !darwin

package cmsg

// ParseTimestamping is not supported on this platform.
func ParseTimestamping(oob []byte) (Timestamp, error) {
	return Timestamp{}, ErrNotSupported
}

// ParsePktInfo is not supported on this platform.
func ParsePktInfo(oob []byte) (PktInfo, error) {
	return PktInfo{}, ErrNotSupported
}
