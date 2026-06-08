//go:build linux

package sendrecv

import (
	"net"
	"syscall"
	"unsafe"
)

// setSockaddrInet4 sets the address family on Linux (no Len field).
func setSockaddrInet4(sa *syscall.RawSockaddrInet4) {
	sa.Family = syscall.AF_INET
}

// setSockaddrInet6 sets the address family on Linux (no Len field).
func setSockaddrInet6(sa *syscall.RawSockaddrInet6) {
	sa.Family = syscall.AF_INET6
}

// parseSockaddr extracts an IP string from a raw sockaddr pointer.
// On Linux, sa_family is a uint16 at offset 0.
func parseSockaddr(name *byte, namelen uint32) string {
	if name == nil || namelen < 2 {
		return ""
	}
	family := *(*uint16)(unsafe.Pointer(name))
	switch family {
	case syscall.AF_INET:
		if namelen < uint32(unsafe.Sizeof(syscall.RawSockaddrInet4{})) {
			return ""
		}
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(name))
		return net.IP(sa.Addr[:]).String()
	case syscall.AF_INET6:
		if namelen < uint32(unsafe.Sizeof(syscall.RawSockaddrInet6{})) {
			return ""
		}
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(name))
		return net.IP(sa.Addr[:]).String()
	}
	return ""
}
