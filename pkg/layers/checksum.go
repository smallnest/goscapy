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

// TCPChecksum computes the TCP checksum over the TCP pseudo-header and segment.
// The pseudo-header is built from srcIP (4 bytes), dstIP (4 bytes), zero byte,
// protocol (1 byte, 6 for TCP), and TCP length (2 bytes).
// The segment's checksum field should be zeroed before calling this.
func TCPChecksum(srcIP, dstIP []byte, segment []byte) uint16 {
	return pseudoHeaderChecksum(srcIP, dstIP, 6, segment)
}

// UDPChecksum computes the UDP checksum over the UDP pseudo-header and datagram.
// The pseudo-header is built from srcIP (4 bytes), dstIP (4 bytes), zero byte,
// protocol (1 byte, 17 for UDP), and UDP length (2 bytes).
// The datagram's checksum field should be zeroed before calling this.
func UDPChecksum(srcIP, dstIP []byte, datagram []byte) uint16 {
	return pseudoHeaderChecksum(srcIP, dstIP, 17, datagram)
}

// pseudoHeaderChecksum builds the IPv4 pseudo-header and computes the checksum
// over the pseudo-header concatenated with the transport data.
func pseudoHeaderChecksum(srcIP, dstIP []byte, proto uint8, data []byte) uint16 {
	transportLen := uint16(len(data))
	// Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + proto(1) + length(2) = 12 bytes
	ph := make([]byte, 12)
	copy(ph[0:4], srcIP)
	copy(ph[4:8], dstIP)
	ph[8] = 0
	ph[9] = proto
	ph[10] = uint8(transportLen >> 8)
	ph[11] = uint8(transportLen)

	// Concatenate pseudo-header + data
	buf := make([]byte, 0, len(ph)+len(data))
	buf = append(buf, ph...)
	buf = append(buf, data...)

	return Checksum(buf)
}
