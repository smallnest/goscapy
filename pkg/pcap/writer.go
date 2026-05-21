package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// Writer writes packets to a pcap file.
type Writer struct {
	w        io.Writer
	linkType uint32
	snapLen  uint32
	written  bool
}

// NewWriter creates a pcap Writer with the given link type and snap length.
// If snapLen is 0, it defaults to 65535.
func NewWriter(w io.Writer, linkType uint32, snapLen uint32) (*Writer, error) {
	if snapLen == 0 {
		snapLen = 65535
	}
	wr := &Writer{
		w:        w,
		linkType: linkType,
		snapLen:  snapLen,
	}
	if err := wr.writeGlobalHeader(); err != nil {
		return nil, err
	}
	return wr, nil
}

func (wr *Writer) writeGlobalHeader() error {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(hdr[4:6], 2) // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4) // version minor
	// thiszone(4) + sigfigs(4) = 0
	binary.LittleEndian.PutUint32(hdr[16:20], wr.snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], wr.linkType)

	_, err := wr.w.Write(hdr[:])
	return err
}

// WritePacket writes a raw packet with the given timestamp.
func (wr *Writer) WritePacket(data []byte, ts time.Time) error {
	captureLen := uint32(len(data))
	if captureLen > wr.snapLen {
		captureLen = wr.snapLen
	}

	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000)) // microseconds
	binary.LittleEndian.PutUint32(hdr[8:12], captureLen)
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(data))) // original length

	if _, err := wr.w.Write(hdr[:]); err != nil {
		return fmt.Errorf("pcap: write packet header: %w", err)
	}
	if _, err := wr.w.Write(data[:captureLen]); err != nil {
		return fmt.Errorf("pcap: write packet data: %w", err)
	}
	wr.written = true
	return nil
}

// WriteRecord writes a PacketRecord to the file.
func (wr *Writer) WriteRecord(rec *PacketRecord) error {
	return wr.WritePacket(rec.Data, rec.Timestamp)
}

// WritePkt builds and writes a structured packet with the current time.
func (wr *Writer) WritePkt(pkt *packet.Packet) error {
	data, err := pkt.Build()
	if err != nil {
		return fmt.Errorf("pcap: build packet: %w", err)
	}
	return wr.WritePacket(data, time.Now())
}
