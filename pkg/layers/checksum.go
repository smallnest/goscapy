package layers

import "encoding/binary"

// Checksum computes the 16-bit one's complement of the one's complement sum
// over the given bytes. Used by IP, ICMP, TCP, and UDP for header/data checksums.
// Returns the checksum in network byte order (big-endian).
func Checksum(b []byte) uint16 {
	sum := uint32(0)
	// Sum 16-bit words.
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	// If odd length, pad with trailing zero byte.
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	// Fold carries.
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// IPChecksum computes the IPv4 header checksum over the header bytes.
// The checksum field itself should be zeroed before calling this.
func IPChecksum(header []byte) uint16 {
	return Checksum(header)
}

// ICMPChecksum computes the ICMP checksum over the full message (header + payload).
func ICMPChecksum(msg []byte) uint16 {
	return Checksum(msg)
}