//go:build darwin

package sendrecv

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/smallnest/goscapy/pkg/packet"
)

// BPF ioctls — not defined in Go's syscall package for macOS.
// Verified by compiling against macOS system headers:
//
//	BIOCSETIF    = _IOW('B', 108, struct ifreq)  = 0x8020426C
//	BIOCSBLEN    = _IOWR('B', 102, u_int)        = 0xC0044266
//	BIOCIMMEDIATE = _IOW('B', 112, u_int)        = 0x80044270
//	BIOCPROMISC  = _IO('B', 105)                 = 0x20004269
//	BIOCFLUSH    = _IO('B', 104)                 = 0x20004268
const (
	_bIOCSETIF     = 0x8020426C
	_bIOCSBLEN     = 0xC0044266
	_bIOCIMMEDIATE = 0x80044270
	_bIOCPROMISC   = 0x20004269
	_bIOCFLUSH     = 0x20004268
)

// bpfHdr is the per-packet header returned by BPF reads on macOS.
// See /usr/include/net/bpf.h struct bpf_hdr.
// On 64-bit macOS, bh_tstamp is timeval32 (two int32), so the total is 20 bytes:
//
//	offset 0:  bh_tstamp  (8 bytes: tv_sec int32 + tv_usec int32)
//	offset 8:  bh_caplen  (4 bytes uint32)
//	offset 12: bh_datalen (4 bytes uint32)
//	offset 16: bh_hdrlen  (2 bytes uint16)
//	offset 18: padding    (2 bytes)
type bpfHdr struct {
	ts_sec  int32
	ts_usec int32
	caplen  uint32
	datalen uint32
	hdrlen  uint16
	_pad    uint16
}

var isLittleEndian bool

func init() {
	var i int16 = 1
	isLittleEndian = *(*byte)(unsafe.Pointer(&i)) == 1
}

func loopbackName() string { return "lo0" }

// --- L3 Send (AF_INET raw socket) ---

func sendL3(pkt *packet.Packet, iface string) error {
	rawBytes, err := buildL3(pkt)
	if err != nil {
		return fmt.Errorf("sendrecv: L3 build: %w", err)
	}

	// On Darwin raw sockets, ip_len and ip_off fields in the IPv4 header
	// must be in host byte order.
	if len(rawBytes) >= 20 {
		if isLittleEndian {
			rawBytes[2], rawBytes[3] = rawBytes[3], rawBytes[2]
			rawBytes[6], rawBytes[7] = rawBytes[7], rawBytes[6]
		}
	}

	dstIP, err := extractDstIP(pkt)
	if err != nil {
		return err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("sendrecv: socket: %w", err)
	}
	defer syscall.Close(fd)

	// Enable IP_HDRINCL so we provide the full IP header.
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("sendrecv: setsockopt IP_HDRINCL: %w", err)
	}

	addr := syscall.SockaddrInet4{Addr: dstIP}
	if err := syscall.Sendto(fd, rawBytes, 0, &addr); err != nil {
		return fmt.Errorf("sendrecv: sendto: %w", err)
	}

	runtime.KeepAlive(rawBytes)
	return nil
}

// --- L2 Send (BPF write) ---

func sendL2(pkt *packet.Packet, iface string) error {
	rawBytes, err := pkt.Build()
	if err != nil {
		return fmt.Errorf("sendrecv: L2 build: %w", err)
	}

	fd, _, err := openBPFDevice()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := bindBPF(fd, iface); err != nil {
		return err
	}

	if _, err := syscall.Write(fd, rawBytes); err != nil {
		return fmt.Errorf("sendrecv: BPF write: %w", err)
	}

	runtime.KeepAlive(rawBytes)
	return nil
}

// --- Receiver (BPF) ---

type bpfReceiver struct {
	fd    int
	buf   []byte
	iface string
	queue []*packet.Packet // packets parsed from last batch read but not yet returned
	dlt   uint32
}

func openReceiver(iface string) (Receiver, error) {
	fd, bufSize, err := openBPFDevice()
	if err != nil {
		return nil, err
	}

	if err := bindBPF(fd, iface); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Set immediate mode so reads return right away when a packet is available.
	if err := setImmediate(fd); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Set promiscuous mode to capture all packets on the interface.
	if err := setPromisc(fd); err != nil {
		// Non-fatal: we may still capture most traffic.
		_ = err
	}

	// Get Data Link Type (DLT).
	var dlt uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x4004426A, uintptr(unsafe.Pointer(&dlt))); errno != 0 {
		dlt = 1 // Default to DLT_EN10MB (Ethernet)
	}

	return &bpfReceiver{
		fd:    fd,
		buf:   make([]byte, bufSize),
		iface: iface,
		dlt:   dlt,
	}, nil
}

func ipStartFn(_ []byte) (string, error) {
	return "IP", nil
}

func ip6StartFn(_ []byte) (string, error) {
	return "IPv6", nil
}

func (r *bpfReceiver) Recv(timeout time.Duration) (*packet.Packet, error) {
	// Return a queued packet from a previous batch read if available.
	if len(r.queue) > 0 {
		pkt := r.queue[0]
		r.queue = r.queue[1:]
		return pkt, nil
	}

	// Use select to implement timeout.
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	var readFds syscall.FdSet
	// Darwin FdSet.Bits is [32]int32; use fd/32 and fd%32 for indexing.
	readFds.Bits[r.fd/32] |= 1 << (uint(r.fd) % 32)

	err := syscall.Select(r.fd+1, &readFds, nil, nil, &tv)
	if err != nil {
		return nil, fmt.Errorf("sendrecv: select: %w", err)
	}
	// Check if our fd is still set (Go's syscall.Select returns only error;
	// nil on both timeout and success, so check the bit to distinguish).
	if readFds.Bits[r.fd/32]&(1<<uint(r.fd%32)) == 0 {
		return nil, fmt.Errorf("%w after %v", ErrTimeout, timeout)
	}

	nRead, err := syscall.Read(r.fd, r.buf)
	if err != nil {
		return nil, fmt.Errorf("sendrecv: BPF read: %w", err)
	}
	if nRead == 0 {
		return nil, fmt.Errorf("sendrecv: BPF read returned 0 bytes")
	}

	// BPF returns batches of [bpf_hdr + packet_data, ...]. Parse all packets.
	data := r.buf[:nRead]
	hdrSize := int(unsafe.Sizeof(bpfHdr{}))

	for len(data) >= hdrSize {
		hdr := *(*bpfHdr)(unsafe.Pointer(&data[0]))
		pktStart := int(hdr.hdrlen)
		pktLen := int(hdr.caplen)
		totalLen := pktStart + pktLen

		if totalLen > len(data) {
			break // truncated batch, stop parsing
		}

		alignedLen := (totalLen + 3) &^ 3
		if alignedLen > len(data) {
			alignedLen = len(data)
		}

		// Copy the raw packet bytes so the shared r.buf can be reused safely.
		raw := make([]byte, pktLen)
		copy(raw, data[pktStart:pktStart+pktLen])

		var pkt *packet.Packet
		if r.dlt == 0 { // DLT_NULL (loopback)
			if len(raw) >= 4 {
				family := *(*uint32)(unsafe.Pointer(&raw[0]))
				if family == 2 { // PF_INET (IPv4)
					pkt, err = packet.Dissect(raw[4:], ipStartFn)
				} else if family == 30 { // PF_INET6 (IPv6)
					pkt, err = packet.Dissect(raw[4:], ip6StartFn)
				} else {
					data = data[alignedLen:]
					continue
				}
			} else {
				data = data[alignedLen:]
				continue
			}
		} else { // DLT_EN10MB (Ethernet)
			pkt, err = packet.Dissect(raw, ethernetStartFn)
		}

		if err != nil {
			// Skip malformed packets and continue to the next one.
			data = data[alignedLen:]
			continue
		}
		r.queue = append(r.queue, pkt)

		// BPF requires advancing by hdr.hdrlen (which includes alignment padding)
		// rounded up to the kernel's alignment boundary.
		data = data[alignedLen:]
	}

	// Return the first parsed packet, keep the rest in the queue.
	if len(r.queue) == 0 {
		return nil, fmt.Errorf("sendrecv: BPF read produced no valid packets")
	}
	pkt := r.queue[0]
	r.queue = r.queue[1:]
	return pkt, nil
}

func (r *bpfReceiver) RecvInto(buf []byte, timeout time.Duration) (*packet.Packet, int, error) {
	// Return a queued packet from a previous batch read if available.
	if len(r.queue) > 0 {
		pkt := r.queue[0]
		r.queue = r.queue[1:]
		return pkt, 0, nil
	}

	// Use select to implement timeout.
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	var readFds syscall.FdSet
	readFds.Bits[r.fd/32] |= 1 << (uint(r.fd) % 32)

	err := syscall.Select(r.fd+1, &readFds, nil, nil, &tv)
	if err != nil {
		return nil, 0, fmt.Errorf("sendrecv: select: %w", err)
	}
	if readFds.Bits[r.fd/32]&(1<<uint(r.fd%32)) == 0 {
		return nil, 0, fmt.Errorf("%w after %v", ErrTimeout, timeout)
	}

	// Read into the caller-provided buffer.
	readBuf := buf
	if len(readBuf) < int(unsafe.Sizeof(bpfHdr{}))+64 {
		readBuf = r.buf
	}
	nRead, err := syscall.Read(r.fd, readBuf)
	if err != nil {
		return nil, 0, fmt.Errorf("sendrecv: BPF read: %w", err)
	}
	if nRead == 0 {
		return nil, 0, fmt.Errorf("sendrecv: BPF read returned 0 bytes")
	}

	data := readBuf[:nRead]
	hdrSize := int(unsafe.Sizeof(bpfHdr{}))
	firstN := 0
	isFirst := true

	for len(data) >= hdrSize {
		hdr := *(*bpfHdr)(unsafe.Pointer(&data[0]))
		pktStart := int(hdr.hdrlen)
		pktLen := int(hdr.caplen)
		totalLen := pktStart + pktLen

		if totalLen > len(data) {
			break
		}

		alignedLen := (totalLen + 3) &^ 3
		if alignedLen > len(data) {
			alignedLen = len(data)
		}

		// The first packet can reference buf directly (caller will process it
		// before the next call). Subsequent packets in the batch must be copied
		// because they'll be returned on later calls when buf may be reused.
		var raw []byte
		if isFirst {
			raw = data[pktStart : pktStart+pktLen]
			firstN = pktLen
		} else {
			raw = make([]byte, pktLen)
			copy(raw, data[pktStart:pktStart+pktLen])
		}

		var pkt *packet.Packet
		if r.dlt == 0 { // DLT_NULL (loopback)
			if len(raw) >= 4 {
				family := *(*uint32)(unsafe.Pointer(&raw[0]))
				if family == 2 {
					pkt, err = packet.Dissect(raw[4:], ipStartFn)
				} else if family == 30 {
					pkt, err = packet.Dissect(raw[4:], ip6StartFn)
				} else {
					data = data[alignedLen:]
					continue
				}
			} else {
				data = data[alignedLen:]
				continue
			}
		} else {
			pkt, err = packet.Dissect(raw, ethernetStartFn)
		}

		if err != nil {
			data = data[alignedLen:]
			continue
		}
		r.queue = append(r.queue, pkt)
		isFirst = false
		data = data[alignedLen:]
	}

	if len(r.queue) == 0 {
		return nil, 0, fmt.Errorf("sendrecv: BPF read produced no valid packets")
	}
	pkt := r.queue[0]
	r.queue = r.queue[1:]
	return pkt, firstN, nil
}

func (r *bpfReceiver) Close() error {
	return syscall.Close(r.fd)
}

// --- BPF helpers ---

// openBPFDevice tries /dev/bpf0 .. /dev/bpf255 until one opens.
// Sets the buffer size and returns (fd, bufSize, error).
func openBPFDevice() (int, uint32, error) {
	bufSize := uint32(32768) // 32 KB buffer
	for i := range 256 {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := syscall.Open(path, syscall.O_RDWR, 0)
		if err != nil {
			continue
		}

		// Set buffer length.
		if err := setBlen(fd, bufSize); err != nil {
			syscall.Close(fd)
			continue
		}

		return fd, bufSize, nil
	}
	return -1, 0, fmt.Errorf("sendrecv: no available /dev/bpf* device")
}

func bindBPF(fd int, iface string) error {
	_iFace, err := lookupInterface(iface)
	if err != nil {
		return err
	}

	// ifreq for BIOCSETIF: sizeof(struct ifreq) = 32 on modern macOS.
	var ifr [32]byte
	copy(ifr[:], _iFace.Name)

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), _bIOCSETIF, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return fmt.Errorf("sendrecv: BIOCSETIF: %v", errno)
	}
	return nil
}

func setBlen(fd int, size uint32) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), _bIOCSBLEN, uintptr(unsafe.Pointer(&size))); errno != 0 {
		return fmt.Errorf("sendrecv: BIOCSBLEN: %v", errno)
	}
	return nil
}

func setImmediate(fd int) error {
	one := int32(1)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), _bIOCIMMEDIATE, uintptr(unsafe.Pointer(&one))); errno != 0 {
		return fmt.Errorf("sendrecv: BIOCIMMEDIATE: %v", errno)
	}
	return nil
}

func setPromisc(fd int) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), _bIOCPROMISC, 0); errno != 0 {
		return fmt.Errorf("sendrecv: BIOCPROMISC: %v", errno)
	}
	return nil
}

func flushBPF(fd int) {
	// BIOCFLUSH — ignore errors.
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), _bIOCFLUSH, 0)
}

// ensure bpfReceiver implements Receiver at compile time.
var _ Receiver = (*bpfReceiver)(nil)
