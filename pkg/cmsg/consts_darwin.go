//go:build darwin

package cmsg

import "syscall"

const (
	soTimestamp    = syscall.SO_TIMESTAMP
	soTimestampNS  = 0x1A // SO_TIMESTAMPNS not in syscall; unused on darwin
	soTimestamping = 0    // unavailable on macOS

	ipProtoIP   = syscall.IPPROTO_IP
	ipProtoIPv6 = syscall.IPPROTO_IPV6
	ipPktInfo   = syscall.IP_PKTINFO
	ipv6PktInfo = 0 // IPV6_PKTINFO not available on darwin
)
