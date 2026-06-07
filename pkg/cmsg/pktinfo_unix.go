//go:build linux || darwin

package cmsg

import (
	"encoding/binary"
	"net"
	"syscall"
)

// ParsePktInfo extracts packet information from socket control messages
// returned by syscall.Recvmsg. It recognises:
//
//   - IP_PKTINFO  (level IPPROTO_IP, type IP_PKTINFO)
//   - IPV6_PKTINFO (level IPPROTO_IPV6, type IPV6_PKTINFO)
//
// Returns a PktInfo with the IPv4 or IPv6 field populated. If no pktinfo
// cmsg is present, it returns the zero value and ErrNotSupported.
//
// Platform notes:
//   - Linux amd64/arm64: struct in_pktinfo is 12 bytes (ifindex 4 + addr 4 + addr 4).
//   - Linux amd64/arm64: struct in6_pktinfo is 20 bytes (addr 16 + ifindex 4).
//   - macOS: IP_PKTINFO available; IPV6_PKTINFO not available.
func ParsePktInfo(oob []byte) (PktInfo, error) {
	cmsgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return PktInfo{}, err
	}

	for _, cmsg := range cmsgs {
		// IPv4 PKTINFO
		if cmsg.Header.Level == ipProtoIP && cmsg.Header.Type == ipPktInfo {
			pi, ok := parseInet4PktInfo(cmsg.Data)
			if ok {
				return PktInfo{IPv4: pi}, nil
			}
		}

		// IPv6 PKTINFO
		if cmsg.Header.Level == ipProtoIPv6 && cmsg.Header.Type == ipv6PktInfo {
			pi, ok := parseInet6PktInfo(cmsg.Data)
			if ok {
				return PktInfo{IPv6: pi, IsIPv6: true}, nil
			}
		}
	}

	return PktInfo{}, ErrNotSupported
}

// parseInet4PktInfo parses struct in_pktinfo from cmsg data.
//
//	Layout (Linux, both amd64 and arm64):
//	  struct in_pktinfo {
//	    unsigned int   ipi_ifindex;  // 4 bytes, offset 0
//	    struct in_addr ipi_spec_dst; // 4 bytes, offset 4
//	    struct in_addr ipi_addr;     // 4 bytes, offset 8
//	  };                             // total: 12 bytes
func parseInet4PktInfo(data []byte) (Inet4PktInfo, bool) {
	if len(data) < 12 {
		return Inet4PktInfo{}, false
	}
	ifindex := int(binary.NativeEndian.Uint32(data[0:4]))
	specDst := make(net.IP, 4)
	copy(specDst, data[4:8])
	addr := make(net.IP, 4)
	copy(addr, data[8:12])

	return Inet4PktInfo{
		IfIndex: ifindex,
		SpecDst: specDst,
		Addr:    addr,
	}, true
}

// parseInet6PktInfo parses struct in6_pktinfo from cmsg data.
//
//	Layout (Linux):
//	  struct in6_pktinfo {
//	    struct in6_addr ipi6_addr;   // 16 bytes, offset 0
//	    unsigned int    ipi6_ifindex; // 4 bytes, offset 16
//	  };                              // total: 20 bytes
func parseInet6PktInfo(data []byte) (Inet6PktInfo, bool) {
	if len(data) < 20 {
		return Inet6PktInfo{}, false
	}
	addr := make(net.IP, 16)
	copy(addr, data[0:16])
	ifindex := int(binary.NativeEndian.Uint32(data[16:20]))

	return Inet6PktInfo{
		Addr:    addr,
		IfIndex: ifindex,
	}, true
}
