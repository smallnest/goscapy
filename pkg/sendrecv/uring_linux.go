//go:build linux

package sendrecv

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ioUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCpu  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        ioSqringOffsets
	CqOff        ioCqringOffsets
}

type ioSqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	Resv2       uint64
}

type ioCqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	Cqes        uint32
	Flags       uint32
	Resv1       uint32
	Resv2       uint64
}

type ioUringSqe struct {
	Opcode      uint8
	Flags       uint8
	Ioprio      uint16
	Fd          int32
	Off         uint64
	Addr        uint64
	Len         uint32
	RwFlags     uint32
	UserData    uint64
	BufIndex    uint16
	Personality uint16
	Pad2        [20]byte
}

type ioUringCqe struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

type ioUring struct {
	fd        int
	sqMmap    []byte
	sqesMmap  []byte
	cqMmap    []byte
	sqHead    *uint32
	sqTail    *uint32
	sqMask    uint32
	sqEntries uint32
	sqFlags   *uint32
	sqDropped *uint32
	sqArray   []uint32
	sqes      []ioUringSqe
	cqHead    *uint32
	cqTail    *uint32
	cqMask    uint32
	cqEntries uint32
	cqOverflow *uint32
	cqes      []ioUringCqe
}

type sendState struct {
	sa   syscall.RawSockaddrInet4
	iov  syscall.Iovec
	msg  syscall.Msghdr
	data []byte
}

type recvState struct {
	sa     syscall.RawSockaddrInet4
	iov    syscall.Iovec
	msg    syscall.Msghdr
	buffer []byte
}

// UringConn represents a raw socket connection utilizing io_uring.
type UringConn struct {
	fd           int
	uring        *ioUring
	counter      uint64
	pendingSends map[uint64]*sendState
	pendingRecvs map[uint64]*recvState
}

func setupUring(entries uint32) (*ioUring, error) {
	var params ioUringParams
	fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, uintptr(entries), uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup failed: %w", errno)
	}

	u := &ioUring{fd: int(fd)}

	// 1. Map SQ Ring
	sqRingSize := params.SqOff.Array + params.SqEntries*4
	sqMmap, err := unix.Mmap(int(fd), 0, int(sqRingSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(int(fd))
		return nil, fmt.Errorf("mmap SQ ring failed: %w", err)
	}
	u.sqMmap = sqMmap

	// 2. Map SQEs
	sqesSize := params.SqEntries * 64
	sqesMmap, err := unix.Mmap(int(fd), 0x10000000, int(sqesSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(sqMmap)
		unix.Close(int(fd))
		return nil, fmt.Errorf("mmap SQEs failed: %w", err)
	}
	u.sqesMmap = sqesMmap

	// 3. Map CQ Ring
	cqRingSize := params.CqOff.Cqes + params.CqEntries*16
	cqMmap, err := unix.Mmap(int(fd), 0x8000000, int(cqRingSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(sqesMmap)
		unix.Munmap(sqMmap)
		unix.Close(int(fd))
		return nil, fmt.Errorf("mmap CQ ring failed: %w", err)
	}
	u.cqMmap = cqMmap

	// Resolve SQ pointers
	u.sqHead = (*uint32)(unsafe.Pointer(&sqMmap[params.SqOff.Head]))
	u.sqTail = (*uint32)(unsafe.Pointer(&sqMmap[params.SqOff.Tail]))
	u.sqMask = *(*uint32)(unsafe.Pointer(&sqMmap[params.SqOff.RingMask]))
	u.sqEntries = *(*uint32)(unsafe.Pointer(&sqMmap[params.SqOff.RingEntries]))
	u.sqFlags = (*uint32)(unsafe.Pointer(&sqMmap[params.SqOff.Flags]))
	u.sqDropped = (*uint32)(unsafe.Pointer(&sqMmap[params.SqOff.Dropped]))

	// Resolve SQ Array slice
	arrayPtr := unsafe.Pointer(&sqMmap[params.SqOff.Array])
	u.sqArray = unsafe.Slice((*uint32)(arrayPtr), params.SqEntries)

	// Resolve SQEs slice
	u.sqes = unsafe.Slice((*ioUringSqe)(unsafe.Pointer(&sqesMmap[0])), params.SqEntries)

	// Resolve CQ pointers
	u.cqHead = (*uint32)(unsafe.Pointer(&cqMmap[params.CqOff.Head]))
	u.cqTail = (*uint32)(unsafe.Pointer(&cqMmap[params.CqOff.Tail]))
	u.cqMask = *(*uint32)(unsafe.Pointer(&cqMmap[params.CqOff.RingMask]))
	u.cqEntries = *(*uint32)(unsafe.Pointer(&cqMmap[params.CqOff.RingEntries]))
	u.cqOverflow = (*uint32)(unsafe.Pointer(&cqMmap[params.CqOff.Overflow]))

	// Resolve CQEs slice
	cqesPtr := unsafe.Pointer(&cqMmap[params.CqOff.Cqes])
	u.cqes = unsafe.Slice((*ioUringCqe)(cqesPtr), params.CqEntries)

	return u, nil
}

func (u *ioUring) close() {
	if u.cqMmap != nil {
		unix.Munmap(u.cqMmap)
	}
	if u.sqesMmap != nil {
		unix.Munmap(u.sqesMmap)
	}
	if u.sqMmap != nil {
		unix.Munmap(u.sqMmap)
	}
	if u.fd != 0 {
		unix.Close(u.fd)
	}
}

func (u *ioUring) getSqe() *ioUringSqe {
	tail := *u.sqTail
	next := tail + 1
	head := atomic.LoadUint32(u.sqHead)
	if next-head > u.sqEntries {
		return nil
	}
	index := tail & u.sqMask
	sqe := &u.sqes[index]
	*sqe = ioUringSqe{}
	return sqe
}

func (u *ioUring) submitSqe(sqe *ioUringSqe) {
	tail := *u.sqTail
	index := tail & u.sqMask
	u.sqArray[index] = index
	atomic.StoreUint32(u.sqTail, tail+1)
}

func (u *ioUring) enter(toSubmit uint32, minComplete uint32, flags uint32) (uint32, error) {
	r1, _, errno := unix.Syscall6(
		unix.SYS_IO_URING_ENTER,
		uintptr(u.fd),
		uintptr(toSubmit),
		uintptr(minComplete),
		uintptr(flags),
		0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return uint32(r1), nil
}

func (u *ioUring) peekCqe() *ioUringCqe {
	head := *u.cqHead
	tail := atomic.LoadUint32(u.cqTail)
	if head == tail {
		return nil
	}
	index := head & u.cqMask
	return &u.cqes[index]
}

func (u *ioUring) advanceCq() {
	head := *u.cqHead
	atomic.StoreUint32(u.cqHead, head+1)
}

// DialUringRaw creates a raw socket connection using io_uring.
func DialUringRaw(proto int) (*UringConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("uring: socket: %w", err)
	}

	uring, err := setupUring(256)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("uring: setup: %w", err)
	}

	return &UringConn{
		fd:           fd,
		uring:        uring,
		pendingSends: make(map[uint64]*sendState),
		pendingRecvs: make(map[uint64]*recvState),
	}, nil
}

// Send submits a send SQE, returns the operation ID.
func (c *UringConn) Send(data []byte, dst string) (uint64, error) {
	ip := net.ParseIP(dst)
	if ip == nil {
		return 0, fmt.Errorf("uring: invalid IP: %s", dst)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("uring: only IPv4 is supported")
	}

	var addr [4]byte
	copy(addr[:], ip4)
	sa := syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Addr:   addr,
	}

	state := &sendState{
		sa:   sa,
		data: make([]byte, len(data)),
	}
	copy(state.data, data)

	state.iov = syscall.Iovec{
		Base: &state.data[0],
		Len:  uint64(len(state.data)),
	}

	state.msg = syscall.Msghdr{
		Name:    (*byte)(unsafe.Pointer(&state.sa)),
		Namelen: uint32(unsafe.Sizeof(state.sa)),
		Iov:     &state.iov,
		Iovlen:  1,
	}

	sqe := c.uring.getSqe()
	if sqe == nil {
		return 0, fmt.Errorf("uring: submission queue full")
	}

	c.counter++
	opID := c.counter

	sqe.Opcode = 9 // IORING_OP_SENDMSG
	sqe.Fd = int32(c.fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(&state.msg)))
	sqe.Len = 1
	sqe.UserData = opID

	c.uring.submitSqe(sqe)

	_, err := c.uring.enter(1, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("uring: enter: %w", err)
	}

	c.pendingSends[opID] = state
	return opID, nil
}

// Recv waits for a receive CQE and returns the data.
func (c *UringConn) Recv(timeout time.Duration) ([]byte, string, error) {
	state := &recvState{
		buffer: make([]byte, 65536),
	}

	state.iov = syscall.Iovec{
		Base: &state.buffer[0],
		Len:  uint64(len(state.buffer)),
	}

	state.msg = syscall.Msghdr{
		Name:    (*byte)(unsafe.Pointer(&state.sa)),
		Namelen: uint32(unsafe.Sizeof(state.sa)),
		Iov:     &state.iov,
		Iovlen:  1,
	}

	sqe := c.uring.getSqe()
	if sqe == nil {
		return nil, "", fmt.Errorf("uring: submission queue full")
	}

	c.counter++
	opID := c.counter

	sqe.Opcode = 10 // IORING_OP_RECVMSG
	sqe.Fd = int32(c.fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(&state.msg)))
	sqe.Len = 1
	sqe.UserData = opID

	c.uring.submitSqe(sqe)

	_, err := c.uring.enter(1, 0, 0)
	if err != nil {
		return nil, "", fmt.Errorf("uring: enter: %w", err)
	}

	c.pendingRecvs[opID] = state
	defer delete(c.pendingRecvs, opID)

	deadline := time.Now().Add(timeout)
	for {
		cqe := c.uring.peekCqe()
		if cqe != nil {
			c.uring.advanceCq()
			if cqe.UserData == opID {
				if cqe.Res < 0 {
					return nil, "", fmt.Errorf("uring: recv failed: %w", syscall.Errno(-cqe.Res))
				}
				data := make([]byte, cqe.Res)
				copy(data, state.buffer[:cqe.Res])
				srcIP := net.IP(state.sa.Addr[:]).String()
				return data, srcIP, nil
			}
			if _, exists := c.pendingSends[cqe.UserData]; exists {
				delete(c.pendingSends, cqe.UserData)
			}
			continue
		}

		if time.Now().After(deadline) {
			return nil, "", ErrTimeout
		}
		time.Sleep(1 * time.Millisecond)
	}
}

// SendRecvBatch batch submits multiple send and receive SQEs, and batch waits for CQEs.
func (c *UringConn) SendRecvBatch(msgs []BatchMsg) ([]BatchResult, error) {
	n := len(msgs)
	if n == 0 {
		return nil, nil
	}

	sendStates := make([]*sendState, n)
	recvStates := make([]*recvState, n)
	sendOpIDs := make([]uint64, n)
	recvOpIDs := make([]uint64, n)

	defer func() {
		for _, opID := range recvOpIDs {
			delete(c.pendingRecvs, opID)
		}
		for _, opID := range sendOpIDs {
			delete(c.pendingSends, opID)
		}
	}()

	// 1. Submit all RECVMSG SQEs
	for i := range n {
		state := &recvState{
			buffer: make([]byte, 65536),
		}
		state.iov = syscall.Iovec{
			Base: &state.buffer[0],
			Len:  uint64(len(state.buffer)),
		}
		state.msg = syscall.Msghdr{
			Name:    (*byte)(unsafe.Pointer(&state.sa)),
			Namelen: uint32(unsafe.Sizeof(state.sa)),
			Iov:     &state.iov,
			Iovlen:  1,
		}

		sqe := c.uring.getSqe()
		if sqe == nil {
			return nil, fmt.Errorf("uring: submission queue full")
		}

		c.counter++
		opID := c.counter
		recvOpIDs[i] = opID
		recvStates[i] = state
		c.pendingRecvs[opID] = state

		sqe.Opcode = 10 // IORING_OP_RECVMSG
		sqe.Fd = int32(c.fd)
		sqe.Addr = uint64(uintptr(unsafe.Pointer(&state.msg)))
		sqe.Len = 1
		sqe.UserData = opID

		c.uring.submitSqe(sqe)
	}

	// 2. Submit all SENDMSG SQEs
	for i := range n {
		ip := net.ParseIP(msgs[i].Dst)
		if ip == nil {
			return nil, fmt.Errorf("uring: invalid IP: %s", msgs[i].Dst)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("uring: only IPv4 is supported")
		}

		var addr [4]byte
		copy(addr[:], ip4)
		sa := syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
			Addr:   addr,
		}

		state := &sendState{
			sa:   sa,
			data: make([]byte, len(msgs[i].Data)),
		}
		copy(state.data, msgs[i].Data)

		state.iov = syscall.Iovec{
			Base: &state.data[0],
			Len:  uint64(len(state.data)),
		}
		state.msg = syscall.Msghdr{
			Name:    (*byte)(unsafe.Pointer(&state.sa)),
			Namelen: uint32(unsafe.Sizeof(state.sa)),
			Iov:     &state.iov,
			Iovlen:  1,
		}

		sqe := c.uring.getSqe()
		if sqe == nil {
			return nil, fmt.Errorf("uring: submission queue full")
		}

		c.counter++
		opID := c.counter
		sendOpIDs[i] = opID
		sendStates[i] = state
		c.pendingSends[opID] = state

		sqe.Opcode = 9 // IORING_OP_SENDMSG
		sqe.Fd = int32(c.fd)
		sqe.Addr = uint64(uintptr(unsafe.Pointer(&state.msg)))
		sqe.Len = 1
		sqe.UserData = opID

		c.uring.submitSqe(sqe)
	}

	_, err := c.uring.enter(uint32(2*n), 0, 0)
	if err != nil {
		return nil, fmt.Errorf("uring: enter batch failed: %w", err)
	}

	resultsMap := make(map[uint64]BatchResult)
	completedRecvs := 0

	deadline := time.Now().Add(3 * time.Second)
	for completedRecvs < n {
		cqe := c.uring.peekCqe()
		if cqe != nil {
			c.uring.advanceCq()

			isRecv := false
			var matchingState *recvState
			for i, opID := range recvOpIDs {
				if cqe.UserData == opID {
					isRecv = true
					matchingState = recvStates[i]
					break
				}
			}

			if isRecv {
				if cqe.Res >= 0 {
					data := make([]byte, cqe.Res)
					copy(data, matchingState.buffer[:cqe.Res])
					srcIP := net.IP(matchingState.sa.Addr[:]).String()
					resultsMap[cqe.UserData] = BatchResult{
						Data: data,
						Src:  srcIP,
					}
				}
				completedRecvs++
			} else {
				delete(c.pendingSends, cqe.UserData)
			}
			continue
		}

		if time.Now().After(deadline) {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	results := make([]BatchResult, n)
	for i, opID := range recvOpIDs {
		results[i] = resultsMap[opID]
	}

	return results, nil
}

// Close closes the underlying raw socket and cleans up io_uring resources.
func (c *UringConn) Close() error {
	if c.uring != nil {
		c.uring.close()
	}
	if c.fd != 0 {
		syscall.Close(c.fd)
	}
	return nil
}
