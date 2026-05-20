//go:build linux

package sendrecv

import (
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/smallnest/goscapy/pkg/packet"
	"golang.org/x/sys/unix"
)

// PacketMMAP represents a packet capture interface utilizing TPACKET_V3 MMAP ring buffer.
type PacketMMAP struct {
	fd                int
	ringMmap          []byte
	blockSize         uint32
	blockNum          uint32
	currentBlockIndex uint32
	pendingPackets    []*packet.Packet
}

// PacketMMAPStats stores packet capture statistics.
type PacketMMAPStats struct {
	Received uint64
	Dropped  uint64
	Freeze   uint64
}

func getBlockStatus(bd *unix.TpacketBlockDesc) uint32 {
	return *(*uint32)(unsafe.Pointer(&bd.Hdr[0]))
}

func setBlockStatus(bd *unix.TpacketBlockDesc, status uint32) {
	*(*uint32)(unsafe.Pointer(&bd.Hdr[0])) = status
}

func getBlockNumPkts(bd *unix.TpacketBlockDesc) uint32 {
	return *(*uint32)(unsafe.Pointer(&bd.Hdr[4]))
}

func getBlockOffsetToFirstPkt(bd *unix.TpacketBlockDesc) uint32 {
	return *(*uint32)(unsafe.Pointer(&bd.Hdr[8]))
}

// NewPacketMMAP creates a new PacketMMAP interface on the specified interface.
func NewPacketMMAP(iface string) (*PacketMMAP, error) {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("packet-mmap: interface %s not found: %w", iface, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("packet-mmap: socket: %w", err)
	}

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifaceObj.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("packet-mmap: bind: %w", err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, int(unix.TPACKET_V3)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("packet-mmap: set PACKET_VERSION: %w", err)
	}

	req := unix.TpacketReq3{
		Block_size:     65536,
		Block_nr:       32,
		Frame_size:     2048,
		Frame_nr:       1024,
		Retire_blk_tov: 20,
	}
	if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("packet-mmap: setsockopt PACKET_RX_RING: %w", err)
	}

	ringSize := int(req.Block_size * req.Block_nr)
	ringMmap, err := unix.Mmap(fd, 0, ringSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("packet-mmap: mmap failed: %w", err)
	}

	return &PacketMMAP{
		fd:        fd,
		ringMmap:  ringMmap,
		blockSize: req.Block_size,
		blockNum:  req.Block_nr,
	}, nil
}

// Recv reads the next packet from the ring buffer.
func (m *PacketMMAP) Recv(timeout time.Duration) (*packet.Packet, error) {
	if len(m.pendingPackets) > 0 {
		pkt := m.pendingPackets[0]
		m.pendingPackets = m.pendingPackets[1:]
		return pkt, nil
	}

	deadline := time.Now().Add(timeout)
	for {
		blockOffset := int(m.currentBlockIndex) * int(m.blockSize)
		bd := (*unix.TpacketBlockDesc)(unsafe.Pointer(&m.ringMmap[blockOffset]))

		status := getBlockStatus(bd)
		if status&unix.TP_STATUS_USER != 0 {
			numPkts := getBlockNumPkts(bd)
			offset := getBlockOffsetToFirstPkt(bd)

			for i := uint32(0); i < numPkts; i++ {
				pktHdrOffset := blockOffset + int(offset)
				hdr := (*unix.Tpacket3Hdr)(unsafe.Pointer(&m.ringMmap[pktHdrOffset]))

				macOffset := pktHdrOffset + int(hdr.Mac)
				if macOffset+int(hdr.Snaplen) <= len(m.ringMmap) {
					pktData := make([]byte, hdr.Snaplen)
					copy(pktData, m.ringMmap[macOffset:macOffset+int(hdr.Snaplen)])

					pkt, err := packet.Dissect(pktData, ethernetStartFn)
					if err == nil {
						m.pendingPackets = append(m.pendingPackets, pkt)
					}
				}

				offset += hdr.Next_offset
			}

			setBlockStatus(bd, unix.TP_STATUS_KERNEL)
			m.currentBlockIndex = (m.currentBlockIndex + 1) % m.blockNum

			if len(m.pendingPackets) > 0 {
				pkt := m.pendingPackets[0]
				m.pendingPackets = m.pendingPackets[1:]
				return pkt, nil
			}
			continue
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ErrTimeout
		}

		fds := []unix.PollFd{{Fd: int32(m.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, int(remaining.Milliseconds()))
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("packet-mmap: poll failed: %w", err)
		}
	}
}

// RecvBatch reads up to n packets from the ring buffer.
func (m *PacketMMAP) RecvBatch(n int, timeout time.Duration) ([]*packet.Packet, error) {
	if n <= 0 {
		return nil, nil
	}

	results := make([]*packet.Packet, 0, n)
	deadline := time.Now().Add(timeout)

	for len(results) < n {
		for len(m.pendingPackets) > 0 && len(results) < n {
			results = append(results, m.pendingPackets[0])
			m.pendingPackets = m.pendingPackets[1:]
		}

		if len(results) >= n {
			break
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		pkt, err := m.Recv(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				break
			}
			return nil, err
		}
		results = append(results, pkt)
	}

	return results, nil
}

// Stats returns the dropped/received statistics.
func (m *PacketMMAP) Stats() PacketMMAPStats {
	stats, err := unix.GetsockoptTpacketStatsV3(m.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return PacketMMAPStats{}
	}
	return PacketMMAPStats{
		Received: uint64(stats.Packets),
		Dropped:  uint64(stats.Drops),
		Freeze:   uint64(stats.Freeze_q_cnt),
	}
}

// Close releases resources.
func (m *PacketMMAP) Close() error {
	if m.ringMmap != nil {
		unix.Munmap(m.ringMmap)
		m.ringMmap = nil
	}
	if m.fd != 0 {
		unix.Close(m.fd)
		m.fd = 0
	}
	return nil
}
