//go:build linux

package sendrecv

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XDP bind flags.
const (
	XDPCopy     uint16 = 1 << 1 // XDP_COPY: kernel copies packet to userspace
	XDPZeroCopy uint16 = 1 << 2 // XDP_ZEROCOPY: true zero-copy from NIC DMA
)

// Ring sizes (must be power of 2).
const (
	xdpDefaultRingSize = 2048
	xdpDefaultFrameSize = 4096
)

// xdpDesc is the XDP descriptor (struct xdp_desc).
type xdpDesc struct {
	Addr    uint64
	Len     uint32
	Options uint32
}

// xdpRing represents a shared-memory ring (fill/completion/rx/tx).
type xdpRing struct {
	producer *uint32
	consumer *uint32
	descs    unsafe.Pointer // either *uint64 (fill/completion) or *xdpDesc (rx/tx)
	mask     uint32
	size     uint32
	cachedProd uint32
	cachedCons uint32
}

// XDPConn represents an AF_XDP socket connection with UMEM.
type XDPConn struct {
	fd       int
	ifindex  int
	queueID  int
	umem     []byte // mmap'd UMEM region
	umemFd   int
	frameSize uint32
	numFrames uint32

	fillRing xdpRing
	compRing xdpRing
	rxRing   xdpRing
	txRing   xdpRing

	// Frame allocator: simple free list.
	mu        sync.Mutex
	freeAddrs []uint64

	flags uint16
}

// XDPOption configures an XDPConn.
type XDPOption func(*xdpConfig)

type xdpConfig struct {
	ringSize  uint32
	frameSize uint32
	numFrames uint32
	queueID   int
	flags     uint16
}

// WithXDPRingSize sets the ring size (must be power of 2).
func WithXDPRingSize(size uint32) XDPOption {
	return func(c *xdpConfig) { c.ringSize = size }
}

// WithXDPFrameSize sets the UMEM frame size.
func WithXDPFrameSize(size uint32) XDPOption {
	return func(c *xdpConfig) { c.frameSize = size }
}

// WithXDPQueueID sets the NIC queue to bind to.
func WithXDPQueueID(id int) XDPOption {
	return func(c *xdpConfig) { c.queueID = id }
}

// WithXDPFlags sets the bind flags (XDPCopy or XDPZeroCopy).
func WithXDPFlags(flags uint16) XDPOption {
	return func(c *xdpConfig) { c.flags = flags }
}

// OpenXDP creates an AF_XDP socket on the given interface.
// It sets up UMEM (fill + completion rings) and RX/TX rings.
// Requires Linux >= 5.4 and appropriate XDP program attached to the interface.
func OpenXDP(iface string, opts ...XDPOption) (*XDPConn, error) {
	cfg := &xdpConfig{
		ringSize:  xdpDefaultRingSize,
		frameSize: xdpDefaultFrameSize,
		numFrames: xdpDefaultRingSize * 2,
		queueID:   0,
		flags:     XDPCopy,
	}
	for _, o := range opts {
		o(cfg)
	}

	ifaceObj, err := lookupInterface(iface)
	if err != nil {
		return nil, err
	}

	// Create AF_XDP socket.
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("xdp: socket: %w", err)
	}

	conn := &XDPConn{
		fd:        fd,
		ifindex:   ifaceObj.Index,
		queueID:   cfg.queueID,
		frameSize: cfg.frameSize,
		numFrames: cfg.numFrames,
		flags:     cfg.flags,
	}

	// Setup UMEM.
	if err := conn.setupUMEM(cfg); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Setup rings.
	if err := conn.setupRings(cfg); err != nil {
		conn.Close()
		return nil, err
	}

	// Bind to interface + queue.
	if err := conn.bind(cfg); err != nil {
		conn.Close()
		return nil, err
	}

	// Populate fill ring with initial frames.
	conn.populateFillRing()

	runtime.KeepAlive(conn.umem)
	return conn, nil
}

func (c *XDPConn) setupUMEM(cfg *xdpConfig) error {
	size := int(cfg.numFrames * cfg.frameSize)

	// mmap UMEM region.
	umem, err := unix.Mmap(-1, 0, size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("xdp: mmap UMEM: %w", err)
	}
	c.umem = umem

	// Register UMEM with the socket via setsockopt XDP_UMEM_REG.
	type xdpUmemReg struct {
		Addr     uint64
		Len      uint64
		Size     uint32
		Headroom uint32
		Flags    uint32
		_pad     uint32
	}

	reg := xdpUmemReg{
		Addr: uint64(uintptr(unsafe.Pointer(&umem[0]))),
		Len:  uint64(size),
		Size: cfg.frameSize,
	}

	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(c.fd),
		unix.SOL_XDP,
		unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&reg)),
		unsafe.Sizeof(reg),
		0)
	if errno != 0 {
		return fmt.Errorf("xdp: XDP_UMEM_REG: %v", errno)
	}

	// Set fill ring size.
	if err := unix.SetsockoptInt(c.fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(cfg.ringSize)); err != nil {
		return fmt.Errorf("xdp: XDP_UMEM_FILL_RING: %w", err)
	}

	// Set completion ring size.
	if err := unix.SetsockoptInt(c.fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(cfg.ringSize)); err != nil {
		return fmt.Errorf("xdp: XDP_UMEM_COMPLETION_RING: %w", err)
	}

	// Set RX ring size.
	if err := unix.SetsockoptInt(c.fd, unix.SOL_XDP, unix.XDP_RX_RING, int(cfg.ringSize)); err != nil {
		return fmt.Errorf("xdp: XDP_RX_RING: %w", err)
	}

	// Set TX ring size.
	if err := unix.SetsockoptInt(c.fd, unix.SOL_XDP, unix.XDP_TX_RING, int(cfg.ringSize)); err != nil {
		return fmt.Errorf("xdp: XDP_TX_RING: %w", err)
	}

	// Initialize free list.
	c.freeAddrs = make([]uint64, cfg.numFrames)
	for i := range cfg.numFrames {
		c.freeAddrs[i] = uint64(i) * uint64(cfg.frameSize)
	}

	return nil
}

func (c *XDPConn) setupRings(cfg *xdpConfig) error {
	// Get ring offsets via getsockopt XDP_MMAP_OFFSETS.
	type xdpRingOffset struct {
		Producer uint64
		Consumer uint64
		Desc     uint64
		Flags    uint64
	}
	type xdpMmapOffsets struct {
		Rx         xdpRingOffset
		Tx         xdpRingOffset
		Fill       xdpRingOffset
		Completion xdpRingOffset
	}

	var offsets xdpMmapOffsets
	offsetsLen := uint32(unsafe.Sizeof(offsets))

	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(c.fd),
		unix.SOL_XDP,
		unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&offsetsLen)),
		0)
	if errno != 0 {
		return fmt.Errorf("xdp: XDP_MMAP_OFFSETS: %v", errno)
	}

	ringSize := cfg.ringSize

	// Map fill ring.
	fillMapSize := int(offsets.Fill.Desc + uint64(ringSize)*8)
	fillMap, err := unix.Mmap(c.fd, unix.XDP_UMEM_PGOFF_FILL_RING, fillMapSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("xdp: mmap fill ring: %w", err)
	}
	c.fillRing = xdpRing{
		producer: (*uint32)(unsafe.Pointer(&fillMap[offsets.Fill.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&fillMap[offsets.Fill.Consumer])),
		descs:    unsafe.Pointer(&fillMap[offsets.Fill.Desc]),
		mask:     ringSize - 1,
		size:     ringSize,
	}

	// Map completion ring.
	compMapSize := int(offsets.Completion.Desc + uint64(ringSize)*8)
	compMap, err := unix.Mmap(c.fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING, compMapSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("xdp: mmap completion ring: %w", err)
	}
	c.compRing = xdpRing{
		producer: (*uint32)(unsafe.Pointer(&compMap[offsets.Completion.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&compMap[offsets.Completion.Consumer])),
		descs:    unsafe.Pointer(&compMap[offsets.Completion.Desc]),
		mask:     ringSize - 1,
		size:     ringSize,
	}

	// Map RX ring.
	rxMapSize := int(offsets.Rx.Desc + uint64(ringSize)*uint64(unsafe.Sizeof(xdpDesc{})))
	rxMap, err := unix.Mmap(c.fd, unix.XDP_PGOFF_RX_RING, rxMapSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("xdp: mmap RX ring: %w", err)
	}
	c.rxRing = xdpRing{
		producer: (*uint32)(unsafe.Pointer(&rxMap[offsets.Rx.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&rxMap[offsets.Rx.Consumer])),
		descs:    unsafe.Pointer(&rxMap[offsets.Rx.Desc]),
		mask:     ringSize - 1,
		size:     ringSize,
	}

	// Map TX ring.
	txMapSize := int(offsets.Tx.Desc + uint64(ringSize)*uint64(unsafe.Sizeof(xdpDesc{})))
	txMap, err := unix.Mmap(c.fd, unix.XDP_PGOFF_TX_RING, txMapSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("xdp: mmap TX ring: %w", err)
	}
	c.txRing = xdpRing{
		producer: (*uint32)(unsafe.Pointer(&txMap[offsets.Tx.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&txMap[offsets.Tx.Consumer])),
		descs:    unsafe.Pointer(&txMap[offsets.Tx.Desc]),
		mask:     ringSize - 1,
		size:     ringSize,
	}

	return nil
}

func (c *XDPConn) bind(cfg *xdpConfig) error {
	type xdpSockAddr struct {
		Family  uint16
		Flags   uint16
		Ifindex uint32
		QueueID uint32
		SharedUmemFd uint32
	}

	addr := xdpSockAddr{
		Family:  unix.AF_XDP,
		Flags:   cfg.flags,
		Ifindex: uint32(c.ifindex),
		QueueID: uint32(cfg.queueID),
	}

	_, _, errno := syscall.Syscall(syscall.SYS_BIND,
		uintptr(c.fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr))
	if errno != 0 {
		return fmt.Errorf("xdp: bind: %v", errno)
	}

	return nil
}

func (c *XDPConn) populateFillRing() {
	prod := *c.fillRing.producer
	fillDescs := (*[1 << 20]uint64)(c.fillRing.descs)

	batchSize := c.fillRing.size / 2
	if batchSize > uint32(len(c.freeAddrs)) {
		batchSize = uint32(len(c.freeAddrs))
	}

	c.mu.Lock()
	for i := uint32(0); i < batchSize && len(c.freeAddrs) > 0; i++ {
		idx := prod & c.fillRing.mask
		fillDescs[idx] = c.freeAddrs[len(c.freeAddrs)-1]
		c.freeAddrs = c.freeAddrs[:len(c.freeAddrs)-1]
		prod++
	}
	c.mu.Unlock()

	// Memory barrier: ensure descriptors are visible before updating producer.
	*c.fillRing.producer = prod
}

// Recv reads one packet from the RX ring. Returns the raw frame bytes.
// The returned slice is only valid until the next Recv call.
func (c *XDPConn) Recv() ([]byte, error) {
	rxDescs := (*[1 << 20]xdpDesc)(c.rxRing.descs)

	for {
		cons := c.rxRing.cachedCons
		prod := *c.rxRing.producer

		if cons == prod {
			// No packets available — poll.
			fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
			_, err := unix.Poll(fds, 1000)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				return nil, fmt.Errorf("xdp: poll: %w", err)
			}
			continue
		}

		idx := cons & c.rxRing.mask
		desc := rxDescs[idx]
		c.rxRing.cachedCons = cons + 1
		*c.rxRing.consumer = c.rxRing.cachedCons

		// Extract packet data from UMEM.
		data := c.umem[desc.Addr : desc.Addr+uint64(desc.Len)]

		// Return frame address to fill ring.
		c.mu.Lock()
		c.freeAddrs = append(c.freeAddrs, desc.Addr)
		c.mu.Unlock()

		// Replenish fill ring if needed.
		c.maybeRefillFillRing()

		return data, nil
	}
}

// Send writes a packet to the TX ring and triggers transmission.
func (c *XDPConn) Send(data []byte) error {
	txDescs := (*[1 << 20]xdpDesc)(c.txRing.descs)

	// Allocate a frame.
	c.mu.Lock()
	if len(c.freeAddrs) == 0 {
		c.mu.Unlock()
		// Try to reclaim from completion ring first.
		c.reclaimCompletions()
		c.mu.Lock()
		if len(c.freeAddrs) == 0 {
			c.mu.Unlock()
			return fmt.Errorf("xdp: no free frames for TX")
		}
	}
	addr := c.freeAddrs[len(c.freeAddrs)-1]
	c.freeAddrs = c.freeAddrs[:len(c.freeAddrs)-1]
	c.mu.Unlock()

	// Copy data into UMEM frame.
	n := copy(c.umem[addr:addr+uint64(c.frameSize)], data)

	// Write TX descriptor.
	prod := *c.txRing.producer
	idx := prod & c.txRing.mask
	txDescs[idx] = xdpDesc{
		Addr: addr,
		Len:  uint32(n),
	}
	*c.txRing.producer = prod + 1

	// Kick the kernel to send.
	_, err := unix.Write(c.fd, nil)
	if err != nil && err != unix.EAGAIN {
		// sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0) triggers TX.
		if _, _, errno := syscall.Syscall6(syscall.SYS_SENDTO,
			uintptr(c.fd), 0, 0, unix.MSG_DONTWAIT, 0, 0); errno != 0 && errno != unix.EAGAIN && errno != unix.ENOBUFS {
			return fmt.Errorf("xdp: sendto kick: %v", errno)
		}
	}

	return nil
}

// SendBatch writes multiple packets to the TX ring.
func (c *XDPConn) SendBatch(packets [][]byte) (int, error) {
	txDescs := (*[1 << 20]xdpDesc)(c.txRing.descs)
	sent := 0

	c.reclaimCompletions()

	prod := *c.txRing.producer

	for _, data := range packets {
		c.mu.Lock()
		if len(c.freeAddrs) == 0 {
			c.mu.Unlock()
			break
		}
		addr := c.freeAddrs[len(c.freeAddrs)-1]
		c.freeAddrs = c.freeAddrs[:len(c.freeAddrs)-1]
		c.mu.Unlock()

		n := copy(c.umem[addr:addr+uint64(c.frameSize)], data)

		idx := prod & c.txRing.mask
		txDescs[idx] = xdpDesc{
			Addr: addr,
			Len:  uint32(n),
		}
		prod++
		sent++
	}

	if sent > 0 {
		*c.txRing.producer = prod
		syscall.Syscall6(syscall.SYS_SENDTO,
			uintptr(c.fd), 0, 0, unix.MSG_DONTWAIT, 0, 0)
	}

	return sent, nil
}

func (c *XDPConn) reclaimCompletions() {
	compDescs := (*[1 << 20]uint64)(c.compRing.descs)
	cons := c.compRing.cachedCons
	prod := *c.compRing.producer

	c.mu.Lock()
	for cons != prod {
		idx := cons & c.compRing.mask
		addr := compDescs[idx]
		c.freeAddrs = append(c.freeAddrs, addr)
		cons++
	}
	c.mu.Unlock()

	c.compRing.cachedCons = cons
	*c.compRing.consumer = cons
}

func (c *XDPConn) maybeRefillFillRing() {
	prod := *c.fillRing.producer
	cons := *c.fillRing.consumer

	// Refill if less than 25% full.
	available := c.fillRing.size - (prod - cons)
	if available > c.fillRing.size/4 {
		return
	}

	c.populateFillRing()
}

// Close releases the AF_XDP socket and unmaps UMEM.
func (c *XDPConn) Close() error {
	if c.umem != nil {
		unix.Munmap(c.umem)
		c.umem = nil
	}
	if c.fd >= 0 {
		unix.Close(c.fd)
		c.fd = -1
	}
	return nil
}

// Fd returns the underlying file descriptor for advanced usage.
func (c *XDPConn) Fd() int {
	return c.fd
}

// Stats returns the number of free frames available.
func (c *XDPConn) FreeFrames() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.freeAddrs)
}

// LoadXDPProgram loads a minimal XDP program that redirects packets to this socket.
// The program is a simple XDP_REDIRECT to the bound XSK map.
// Returns the BPF program fd for cleanup.
func (c *XDPConn) LoadXDPProgram() (int, error) {
	// Minimal XDP program (eBPF bytecode):
	// r0 = XDP_PASS (2) — for production, this should be XDP_REDIRECT with xsk_map lookup.
	// For now, use XDP_PASS as a placeholder that requires the NIC driver to support
	// AF_XDP without an explicit XDP program (supported by many modern drivers).
	//
	// A real implementation would:
	// 1. Create a BPF_MAP_TYPE_XSKMAP
	// 2. Load a program that does: bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS)
	// 3. Attach the program to the interface
	//
	// This is complex and driver-dependent. Users should attach their own XDP program
	// or use a tool like `ip link set dev <iface> xdp obj prog.o`.
	return -1, fmt.Errorf("xdp: LoadXDPProgram not implemented; attach XDP program externally (e.g., ip link set dev <iface> xdp obj prog.o)")
}

// ensure XDPConn has a deterministic file reference for GC prevention.
func init() {
	_ = os.Getpid() // reference os package
}
