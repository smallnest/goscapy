//go:build linux

package cmsg

import "golang.org/x/sys/unix"

const (
	soTimestamp    = unix.SO_TIMESTAMP
	soTimestampNS  = unix.SO_TIMESTAMPNS
	soTimestamping = unix.SO_TIMESTAMPING

	ipProtoIP   = unix.IPPROTO_IP
	ipProtoIPv6 = unix.IPPROTO_IPV6
	ipPktInfo   = unix.IP_PKTINFO
	ipv6PktInfo = unix.IPV6_PKTINFO
)
