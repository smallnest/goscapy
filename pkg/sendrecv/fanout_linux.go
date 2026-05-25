//go:build linux

package sendrecv

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"github.com/smallnest/goscapy/pkg/packet"
	"golang.org/x/sys/unix"
)

// Fanout modes for PACKET_FANOUT.
const (
	FanoutHash     uint16 = 0 // PACKET_FANOUT_HASH: flow-based hash
	FanoutLB       uint16 = 1 // PACKET_FANOUT_LB: round-robin load balance
	FanoutCPU      uint16 = 2 // PACKET_FANOUT_CPU: per-CPU distribution
	FanoutRollover uint16 = 3 // PACKET_FANOUT_ROLLOVER: fill one socket then next
)

// FanoutReceiver distributes packets across N AF_PACKET sockets in a single
// fanout group for multi-core parallel capture.
type FanoutReceiver struct {
	mu      sync.Mutex
	fds     []int
	iface   string
	groupID uint16
	mode    uint16
	n       int
}

// FanoutOption configures a FanoutReceiver.
type FanoutOption func(*FanoutReceiver)

// WithFanoutMode sets the fanout distribution mode.
func WithFanoutMode(mode uint16) FanoutOption {
	return func(f *FanoutReceiver) { f.mode = mode }
}

// WithFanoutGroupID sets the fanout group ID. Defaults to pid-based.
func WithFanoutGroupID(id uint16) FanoutOption {
	return func(f *FanoutReceiver) { f.groupID = id }
}

// OpenFanoutReceiver creates N AF_PACKET sockets joined to the same fanout group
// on the given interface. The kernel distributes incoming packets across
// the sockets according to the fanout mode.
func OpenFanoutReceiver(iface string, n int, opts ...FanoutOption) (*FanoutReceiver, error) {
	if n <= 0 {
		n = runtime.NumCPU()
	}

	fr := &FanoutReceiver{
		iface:   iface,
		groupID: uint16(syscall.Getpid() & 0xffff),
		mode:    FanoutHash,
		n:       n,
	}
	for _, o := range opts {
		o(fr)
	}

	ifaceObj, err := lookupInterface(iface)
	if err != nil {
		return nil, err
	}

	for i := range n {
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(_ETH_P_ALL)))
		if err != nil {
			fr.closeAll()
			return nil, fmt.Errorf("sendrecv: fanout socket[%d]: %w", i, err)
		}
		fr.fds = append(fr.fds, fd)

		// Bind to the specific interface.
		addr := syscall.SockaddrLinklayer{
			Protocol: htons(_ETH_P_ALL),
			Ifindex:  ifaceObj.Index,
		}
		if err := syscall.Bind(fd, &addr); err != nil {
			fr.closeAll()
			return nil, fmt.Errorf("sendrecv: fanout bind[%d]: %w", i, err)
		}

		// Join the fanout group.
		// The fanout argument is: (group_id | (mode << 16))
		fanoutArg := int(fr.groupID) | (int(fr.mode) << 16)
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
			fr.closeAll()
			return nil, fmt.Errorf("sendrecv: fanout setsockopt[%d]: %w", i, err)
		}
	}

	return fr, nil
}

// RecvParallel starts N goroutines, each reading from its own socket in the
// fanout group and calling handler for each received packet. Blocks until
// Close is called. The handler may be called concurrently from multiple goroutines.
func (fr *FanoutReceiver) RecvParallel(handler func(*packet.Packet)) {
	fr.mu.Lock()
	fds := make([]int, len(fr.fds))
	copy(fds, fr.fds)
	fr.mu.Unlock()

	var wg sync.WaitGroup
	for _, fd := range fds {
		wg.Add(1)
		go func(sockFd int) {
			defer wg.Done()
			buf := make([]byte, 65536)
			for {
				n, _, err := syscall.Recvfrom(sockFd, buf, 0)
				if err != nil {
					return // socket closed or error
				}
				if n == 0 {
					continue
				}

				pkt, err := packet.Dissect(buf[:n], ethernetStartFn)
				if err != nil {
					continue
				}
				handler(pkt)
			}
		}(fd)
	}
	wg.Wait()
}

// Close releases all sockets in the fanout group.
func (fr *FanoutReceiver) Close() error {
	return fr.closeAll()
}

// NumSockets returns the number of sockets in the fanout group.
func (fr *FanoutReceiver) NumSockets() int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return len(fr.fds)
}

func (fr *FanoutReceiver) closeAll() error {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	var lastErr error
	for _, fd := range fr.fds {
		if err := syscall.Close(fd); err != nil {
			lastErr = err
		}
	}
	fr.fds = nil
	return lastErr
}
