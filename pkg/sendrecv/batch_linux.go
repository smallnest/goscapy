//go:build linux

package sendrecv

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type mmsghdr struct {
	Hdr       syscall.Msghdr
	Len       uint32
	Pad_cgo_0 [4]byte
}

// SendBatch sends multiple raw socket payloads in a single system call.
func (c *BatchConn) SendBatch(msgs []BatchMsg) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	addrs := make([]syscall.RawSockaddrInet4, len(msgs))
	iovs := make([]syscall.Iovec, len(msgs))
	msgvec := make([]mmsghdr, len(msgs))

	for i := range msgs {
		ip := net.ParseIP(msgs[i].Dst)
		if ip == nil {
			return 0, fmt.Errorf("batch: invalid IP: %s", msgs[i].Dst)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return 0, fmt.Errorf("batch: only IPv4 is supported")
		}

		var addr [4]byte
		copy(addr[:], ip4)
		addrs[i] = syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
			Addr:   addr,
		}

		var base *byte
		if len(msgs[i].Data) > 0 {
			base = &msgs[i].Data[0]
		}
		iovs[i] = syscall.Iovec{
			Base: base,
			Len:  uint64(len(msgs[i].Data)),
		}

		msgvec[i].Hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
		msgvec[i].Hdr.Namelen = uint32(unsafe.Sizeof(addrs[i]))
		msgvec[i].Hdr.Iov = &iovs[i]
		msgvec[i].Hdr.Iovlen = 1
	}

	r1, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(c.fd),
		uintptr(unsafe.Pointer(&msgvec[0])),
		uintptr(len(msgvec)),
		0, // flags
		0, 0,
	)

	if errno != 0 {
		return 0, fmt.Errorf("batch: sendmmsg: %w", errno)
	}

	return int(r1), nil
}

// RecvBatch receives multiple raw socket payloads in a single system call.
func (c *BatchConn) RecvBatch(n int, timeout time.Duration) ([]BatchResult, error) {
	if n <= 0 {
		return nil, nil
	}

	buffers := make([][]byte, n)
	for i := range buffers {
		buffers[i] = make([]byte, 65536)
	}

	addrs := make([]syscall.RawSockaddrInet4, n)
	iovs := make([]syscall.Iovec, n)
	msgvec := make([]mmsghdr, n)

	for i := range n {
		iovs[i] = syscall.Iovec{
			Base: &buffers[i][0],
			Len:  uint64(len(buffers[i])),
		}
		msgvec[i].Hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
		msgvec[i].Hdr.Namelen = uint32(unsafe.Sizeof(addrs[i]))
		msgvec[i].Hdr.Iov = &iovs[i]
		msgvec[i].Hdr.Iovlen = 1
	}

	var timeoutTS *syscall.Timespec
	if timeout > 0 {
		ts := syscall.NsecToTimespec(timeout.Nanoseconds())
		timeoutTS = &ts
	}

	r1, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(c.fd),
		uintptr(unsafe.Pointer(&msgvec[0])),
		uintptr(n),
		0, // flags
		uintptr(unsafe.Pointer(timeoutTS)),
		0,
	)

	if errno != 0 {
		if errors.Is(errno, syscall.EAGAIN) || errors.Is(errno, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
		return nil, fmt.Errorf("batch: recvmmsg: %w", errno)
	}

	numRecv := int(r1)
	results := make([]BatchResult, numRecv)
	for i := range numRecv {
		packetLen := msgvec[i].Len
		data := make([]byte, packetLen)
		copy(data, buffers[i][:packetLen])

		srcIP := net.IP(addrs[i].Addr[:]).String()
		results[i] = BatchResult{
			Data: data,
			Src:  srcIP,
		}
	}

	return results, nil
}
