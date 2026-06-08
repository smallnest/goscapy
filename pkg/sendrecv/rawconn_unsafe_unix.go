//go:build linux || darwin

package sendrecv

import (
	"syscall"
	"unsafe"
)

// unsafe helpers for raw sockaddr/msghdr manipulation.
// These avoid allocating through reflection-based syscall wrappers.

// unsafePtrMsg returns a pointer to the Msghdr as a uintptr for syscalls.
func unsafePtrMsg(msg *syscall.Msghdr) uintptr {
	return uintptr(unsafe.Pointer(msg))
}

// unsafeSizeofRawSockaddrInet4 returns the size of RawSockaddrInet4.
func unsafeSizeofRawSockaddrInet4() uintptr {
	return unsafe.Sizeof(syscall.RawSockaddrInet4{})
}

// unsafeSizeofRawSockaddrInet6 returns the size of RawSockaddrInet6.
func unsafeSizeofRawSockaddrInet6() uintptr {
	return unsafe.Sizeof(syscall.RawSockaddrInet6{})
}

// copyRawSockaddr copies raw sockaddr bytes into a RawSockaddrAny via unsafe.
func copyRawSockaddr(dst *syscall.RawSockaddrAny, src unsafe.Pointer, len uint32) {
	copy((*[128]byte)(unsafe.Pointer(dst))[:len], (*[128]byte)(src)[:len])
}
