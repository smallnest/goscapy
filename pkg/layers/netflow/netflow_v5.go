package netflow

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// NetflowV5 header constants.
const (
	NetflowV5Version uint16 = 5
	NetflowV5HeaderLen      = 24
	NetflowV5RecordLen      = 48
)

// NewNetflowV5 creates a Netflow V5 header layer.
// The flow records are passed separately as payload.
func NewNetflowV5() *packet.Layer {
	return packet.NewLayer("NetflowV5", []fields.Field{
		fields.NewShortField("version", NetflowV5Version),
		fields.NewShortField("count", 0),
		fields.NewIntField("sys_uptime", 0),
		fields.NewIntField("unix_secs", 0),
		fields.NewIntField("unix_nsecs", 0),
		fields.NewIntField("flow_sequence", 0),
		fields.NewByteField("engine_type", 0),
		fields.NewByteField("engine_id", 0),
		fields.NewShortField("sampling_interval", 0),
	})
}

// NetflowV5Record represents a single Netflow V5 flow record (48 bytes).
type NetflowV5Record struct {
	SrcAddr   net.IP
	DstAddr   net.IP
	NextHop   net.IP
	Input     uint16
	Output    uint16
	Packets   uint32
	Bytes     uint32
	First     uint32
	Last      uint32
	SrcPort   uint16
	DstPort   uint16
	Pad1      uint8
	Flags     uint8
	Proto     uint8
	Tos       uint8
	SrcAS     uint16
	DstAS     uint16
	SrcMask   uint8
	DstMask   uint8
	Pad2      uint16
}

// PackNetflowV5Record serializes a single V5 flow record to 48 bytes.
func PackNetflowV5Record(r NetflowV5Record) []byte {
	buf := make([]byte, NetflowV5RecordLen)
	off := 0

	putIPv4(buf[off:], r.SrcAddr)
	off += 4
	putIPv4(buf[off:], r.DstAddr)
	off += 4
	putIPv4(buf[off:], r.NextHop)
	off += 4
	binary.BigEndian.PutUint16(buf[off:], r.Input)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], r.Output)
	off += 2
	binary.BigEndian.PutUint32(buf[off:], r.Packets)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], r.Bytes)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], r.First)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], r.Last)
	off += 4
	binary.BigEndian.PutUint16(buf[off:], r.SrcPort)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], r.DstPort)
	off += 2
	buf[off] = r.Pad1
	off++
	buf[off] = r.Flags
	off++
	buf[off] = r.Proto
	off++
	buf[off] = r.Tos
	off++
	binary.BigEndian.PutUint16(buf[off:], r.SrcAS)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], r.DstAS)
	off += 2
	buf[off] = r.SrcMask
	off++
	buf[off] = r.DstMask
	off++
	binary.BigEndian.PutUint16(buf[off:], r.Pad2)

	return buf
}

// UnpackNetflowV5Record deserializes a single V5 flow record.
func UnpackNetflowV5Record(data []byte) (NetflowV5Record, error) {
	if len(data) < NetflowV5RecordLen {
		return NetflowV5Record{}, fmt.Errorf("netflow: V5 record needs %d bytes, got %d", NetflowV5RecordLen, len(data))
	}
	r := NetflowV5Record{
		SrcAddr: net.IP(copy4(data[0:4])),
		DstAddr: net.IP(copy4(data[4:8])),
		NextHop: net.IP(copy4(data[8:12])),
		Input:   binary.BigEndian.Uint16(data[12:14]),
		Output:  binary.BigEndian.Uint16(data[14:16]),
		Packets: binary.BigEndian.Uint32(data[16:20]),
		Bytes:   binary.BigEndian.Uint32(data[20:24]),
		First:   binary.BigEndian.Uint32(data[24:28]),
		Last:    binary.BigEndian.Uint32(data[28:32]),
		SrcPort: binary.BigEndian.Uint16(data[32:34]),
		DstPort: binary.BigEndian.Uint16(data[34:36]),
		Pad1:    data[36],
		Flags:   data[37],
		Proto:   data[38],
		Tos:     data[39],
		SrcAS:   binary.BigEndian.Uint16(data[40:42]),
		DstAS:   binary.BigEndian.Uint16(data[42:44]),
		SrcMask: data[44],
		DstMask: data[45],
		Pad2:    binary.BigEndian.Uint16(data[46:48]),
	}
	return r, nil
}

// ParseNetflowV5Records parses all flow records from the payload after the header.
func ParseNetflowV5Records(payload []byte, count uint16) ([]NetflowV5Record, error) {
	if len(payload) < int(count)*NetflowV5RecordLen {
		return nil, fmt.Errorf("netflow: V5 payload %d bytes, need %d for %d records",
			len(payload), int(count)*NetflowV5RecordLen, count)
	}
	records := make([]NetflowV5Record, count)
	for i := range count {
		rec, err := UnpackNetflowV5Record(payload[i*NetflowV5RecordLen:])
		if err != nil {
			return records[:i], err
		}
		records[i] = rec
	}
	return records, nil
}

// PackNetflowV5Records serializes multiple flow records.
func PackNetflowV5Records(records []NetflowV5Record) []byte {
	buf := make([]byte, len(records)*NetflowV5RecordLen)
	for i, r := range records {
		copy(buf[i*NetflowV5RecordLen:], PackNetflowV5Record(r))
	}
	return buf
}

func copy4(b []byte) []byte {
	v := make([]byte, 4)
	copy(v, b)
	return v
}

// putIPv4 writes a 4-byte IPv4 address into dst, zeroing if nil/invalid.
func putIPv4(dst []byte, ip net.IP) {
	if v := ip.To4(); v != nil {
		copy(dst, v)
	}
}
