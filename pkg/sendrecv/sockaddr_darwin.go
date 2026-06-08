//go:build darwin

package sendrecv

import (
	"net"
	"syscall"
	"unsafe"
)

// setSockaddrInet4 sets the address family and BSD-required Len field.
func setSockaddrInet4(sa *syscall.RawSockaddrInet4) {
	sa.Len = uint8(unsafe.Sizeof(*sa))
	sa.Family = syscall.AF_INET
}

// setSockaddrInet6 sets the address family and BSD-required Len field.
func setSockaddrInet6(sa *syscall.RawSockaddrInet6) {
	sa.Len = uint8(unsafe.Sizeof(*sa))
	sa.Family = syscall.AF_INET6
}

// parseSockaddr extracts an IP string from a raw sockaddr pointer.
// On macOS/BSD, sa_family is a uint8 at byte index 1 (after sa_len at byte 0).
func parseSockaddr(name *byte, namelen uint32) string {
	if name == nil || namelen < 2 {
		return ""
	}
	// BSD: byte 0 = sa_len, byte 1 = sa_family.
	family := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(name)) + 1))
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
