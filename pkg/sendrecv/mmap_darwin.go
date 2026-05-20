//go:build darwin

package sendrecv

import (
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// PacketMMAP represents a packet capture interface utilizing TPACKET_V3 MMAP ring buffer.
type PacketMMAP struct{}

// PacketMMAPStats stores packet capture statistics.
type PacketMMAPStats struct {
	Received uint64
	Dropped  uint64
	Freeze   uint64
}

// NewPacketMMAP returns ErrNotSupported on macOS.
func NewPacketMMAP(iface string) (*PacketMMAP, error) {
	return nil, ErrNotSupported
}

// Recv returns ErrNotSupported on macOS.
func (m *PacketMMAP) Recv(timeout time.Duration) (*packet.Packet, error) {
	return nil, ErrNotSupported
}

// RecvBatch returns ErrNotSupported on macOS.
func (m *PacketMMAP) RecvBatch(n int, timeout time.Duration) ([]*packet.Packet, error) {
	return nil, ErrNotSupported
}

// Stats returns empty statistics on macOS.
func (m *PacketMMAP) Stats() PacketMMAPStats {
	return PacketMMAPStats{}
}

// Close closes the interface.
func (m *PacketMMAP) Close() error {
	return nil
}
