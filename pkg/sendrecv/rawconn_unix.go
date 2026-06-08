//go:build linux || darwin

package sendrecv

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// RecvmsgOOB receives one packet and its ancillary (OOB) data using recvmsg(2).
// It allocates data and OOB buffers internally (pooled for OOB).
// For zero-allocation receiving, use RecvmsgOOBInto.
//
// EnableTimestamping or setsockopt IP_PKTINFO/IPV6_PKTINFO must be called
// beforehand for the kernel to populate ancillary data.
func (c *RawConn) RecvmsgOOB(timeout time.Duration) (data []byte, oob []byte, src string, err error) {
	buf := make([]byte, 65536)
	oobBuf := getOOBBuf()
	defer putOOBBuf(oobBuf)

	n, oobn, src, err := c.RecvmsgOOBInto(buf, oobBuf, timeout)
	if err != nil {
		return nil, nil, "", err
	}

	// Copy OOB so it survives pool return.
	oobOut := make([]byte, oobn)
	copy(oobOut, oobBuf[:oobn])

	return buf[:n], oobOut, src, nil
}

// RecvmsgOOBInto receives one packet and its ancillary data into caller-provided
// buffers using recvmsg(2). Returns the number of data bytes read (n) and the
// number of OOB bytes read (oobn). The source IP is returned in src.
//
// This is the zero-allocation path — the caller owns both buffers.
// Use ParseTimestamp(oob[:oobn]) to extract timestamps from the OOB data.
func (c *RawConn) RecvmsgOOBInto(buf, oobBuf []byte, timeout time.Duration) (n int, oobn int, src string, err error) {
	if timeout > 0 {
		if err := waitRecv(c.fd, timeout); err != nil {
			return 0, 0, "", err
		}
	}

	// Prepare iovec for scatter read.
	var iov syscall.Iovec
	iov.Base = &buf[0]
	iov.SetLen(len(buf))

	// Prepare source address buffer.
	var rsa syscall.RawSockaddrAny

	// Prepare msghdr.
	var msg syscall.Msghdr
	msg.Name = (*byte)(unsafe.Pointer(&rsa))
	msg.Namelen = uint32(unsafe.Sizeof(rsa))
	msg.Iov = &iov
	msg.Iovlen = 1
	if len(oobBuf) > 0 {
		msg.Control = &oobBuf[0]
		msg.SetControllen(len(oobBuf))
	}

	rn, _, e := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(c.fd), uintptr(unsafePtrMsg(&msg)), syscall.MSG_DONTWAIT)
	if e != 0 {
		if isWouldBlock(e) {
			return 0, 0, "", fmt.Errorf("%w after %v", ErrTimeout, timeout)
		}
		return 0, 0, "", fmt.Errorf("sendrecv: recvmsg: %v", e)
	}

	// Extract source address from msg.Name.
	src = parseSockaddr(msg.Name, msg.Namelen)

	return int(rn), int(msg.Controllen), src, nil
}

// SendmsgOOB sends data with ancillary (OOB) data using sendmsg(2).
// The oob parameter contains pre-built control messages (e.g., IP_PKTINFO
// for source-address selection). Pass nil or empty oob for no ancillary data.
func (c *RawConn) SendmsgOOB(data []byte, oob []byte, dst string) error {
	ip := net.ParseIP(dst)
	if ip == nil {
		return fmt.Errorf("sendrecv: invalid destination IP: %s", dst)
	}

	var rsa syscall.RawSockaddrAny
	var rsalen uint32

	if ip4 := ip.To4(); ip4 != nil {
		var sa syscall.RawSockaddrInet4
		setSockaddrInet4(&sa)
		copy(sa.Addr[:], ip4)
		rsalen = uint32(unsafeSizeofRawSockaddrInet4())
		copyRawSockaddr(&rsa, unsafe.Pointer(&sa), rsalen)
	} else {
		ip6 := ip.To16()
		if ip6 == nil {
			return fmt.Errorf("sendrecv: invalid destination IP: %s", dst)
		}
		var sa syscall.RawSockaddrInet6
		setSockaddrInet6(&sa)
		copy(sa.Addr[:], ip6)
		rsalen = uint32(unsafeSizeofRawSockaddrInet6())
		copyRawSockaddr(&rsa, unsafe.Pointer(&sa), rsalen)
	}

	var iov syscall.Iovec
	iov.Base = &data[0]
	iov.SetLen(len(data))

	var msg syscall.Msghdr
	msg.Name = (*byte)(unsafe.Pointer(&rsa))
	msg.Namelen = rsalen
	msg.Iov = &iov
	msg.Iovlen = 1
	if len(oob) > 0 {
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}

	_, _, e := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(c.fd), uintptr(unsafePtrMsg(&msg)), 0)
	if e != 0 {
		return fmt.Errorf("sendrecv: sendmsg: %v", e)
	}
	return nil
}
