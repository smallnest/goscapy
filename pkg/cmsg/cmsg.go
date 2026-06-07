// Package cmsg parses socket control messages (ancillary data) returned by
// recvmsg. It provides safe helpers for extracting kernel
// timestamps (SCM_TIMESTAMPING, SO_TIMESTAMP, SO_TIMESTAMPNS) and packet
// information (IP_PKTINFO, IPV6_PKTINFO) from raw OOB byte slices, masking
// the details of 32/64-bit struct layouts across platforms.
//
// On unsupported platforms the parsing functions return ErrNotSupported.
package cmsg

import (
	"errors"
	"net"
	"time"
)

// ErrNotSupported is returned when a cmsg parsing function is called on a
// platform that does not implement the requested socket option.
var ErrNotSupported = errors.New("cmsg: not supported on this platform")

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
)

// Inet4PktInfo holds the parsed contents of an IPv4 IP_PKTINFO control message.
type Inet4PktInfo struct {
	// IfIndex is the interface index on which the packet arrived.
	IfIndex int
	// SpecDst is the destination address of the packet (the address the
	// packet was sent to), useful for determining which local address
	// received the packet on a multi-homed host.
	SpecDst net.IP
	// Addr is the source address header field. On received packets this is
	// typically the source address; on sent packets it can be used to set
	// the source IP.
	Addr net.IP
}

// Inet6PktInfo holds the parsed contents of an IPv6 IPV6_PKTINFO control message.
type Inet6PktInfo struct {
	// Addr is the destination address of the received packet.
	Addr net.IP
	// IfIndex is the interface index on which the packet arrived.
	IfIndex int
}

// PktInfo is a union type returned by ParsePktInfo. At most one of the
// IPv4 or IPv6 fields is set; the other remains zero-valued.
type PktInfo struct {
	// IPv4 is populated when an IP_PKTINFO control message is found.
	IPv4 Inet4PktInfo
	// IPv6 is populated when an IPV6_PKTINFO control message is found.
	IPv6 Inet6PktInfo
	// IsIPv6 is true when the IPV6 field (not IPv4) is populated.
	IsIPv6 bool
}
