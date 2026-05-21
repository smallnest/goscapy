// Package pcap provides pure-Go reading and writing of pcap and pcapng
// capture files without depending on libpcap.
package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
)

// Link-layer type constants (subset of tcpdump.org link types).
const (
	LinkTypeNull     uint32 = 0   // BSD loopback (4-byte AF header)
	LinkTypeEthernet uint32 = 1   // Ethernet (DLT_EN10MB)
	LinkTypeRaw      uint32 = 101 // Raw IP (no link-layer header)
	LinkTypeIPv4     uint32 = 228 // Raw IPv4
	LinkTypeIPv6     uint32 = 229 // Raw IPv6
)

// pcap file magic numbers.
const (
	magicMicroseconds    = 0xA1B2C3D4
	magicNanoseconds     = 0xA1B23C4D
	magicMicrosecondsBig = 0xD4C3B2A1
	magicNanosecondsBig  = 0x4D3CB2A1
)

// pcapng block types.
const (
	blockTypeSHB = 0x0A0D0D0A // Section Header Block
	blockTypeIDB = 0x00000001 // Interface Description Block
	blockTypeEPB = 0x00000006 // Enhanced Packet Block
	blockTypeSPB = 0x00000003 // Simple Packet Block
)

// PacketRecord represents a single captured packet with metadata.
type PacketRecord struct {
	Timestamp time.Time
	CaptureLen uint32
	OrigLen    uint32
	Data       []byte
	LinkType   uint32
}

// Packet dissects the raw capture data and returns a structured packet.
func (r *PacketRecord) Packet() (*packet.Packet, error) {
	startFn := linkTypeStartFn(r.LinkType)
	data := r.Data
	if r.LinkType == LinkTypeNull && len(data) >= 4 {
		data = data[4:]
	}
	return packet.Dissect(data, startFn)
}

// Reader reads packets from a pcap or pcapng file.
type Reader struct {
	r          io.Reader
	byteOrder  binary.ByteOrder
	linkType   uint32
	snapLen    uint32
	nanoPrecis bool
	isPcapng   bool

	// pcapng state
	interfaces []pcapngInterface
}

type pcapngInterface struct {
	linkType uint32
	snapLen  uint32
}

// NewReader creates a Reader from an io.Reader. It auto-detects pcap vs pcapng
// format from the magic number / block type.
func NewReader(r io.Reader) (*Reader, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("pcap: read magic: %w", err)
	}

	m := binary.LittleEndian.Uint32(magic[:])
	switch m {
	case magicMicroseconds:
		return newPcapReader(r, binary.LittleEndian, false)
	case magicNanoseconds:
		return newPcapReader(r, binary.LittleEndian, true)
	case magicMicrosecondsBig:
		return newPcapReader(r, binary.BigEndian, false)
	case magicNanosecondsBig:
		return newPcapReader(r, binary.BigEndian, true)
	case blockTypeSHB:
		return newPcapngReader(r, magic[:])
	}

	// Check big-endian SHB.
	mBig := binary.BigEndian.Uint32(magic[:])
	if mBig == blockTypeSHB {
		return newPcapngReader(r, magic[:])
	}

	return nil, fmt.Errorf("pcap: unrecognized file format (magic: %08x)", m)
}

// LinkType returns the primary link-layer type of the capture.
func (rd *Reader) LinkType() uint32 { return rd.linkType }

// ReadPacket reads the next packet record from the capture file.
// Returns io.EOF when no more packets are available.
func (rd *Reader) ReadPacket() (*PacketRecord, error) {
	if rd.isPcapng {
		return rd.readPcapngPacket()
	}
	return rd.readPcapPacket()
}

// Packets returns a channel that yields all packets from the capture.
// The channel is closed when EOF is reached or an error occurs.
// If errp is non-nil, the final error (other than io.EOF) is stored there.
func (rd *Reader) Packets(errp *error) <-chan *PacketRecord {
	ch := make(chan *PacketRecord, 64)
	go func() {
		defer close(ch)
		for {
			rec, err := rd.ReadPacket()
			if err != nil {
				if err != io.EOF && errp != nil {
					*errp = err
				}
				return
			}
			ch <- rec
		}
	}()
	return ch
}

// --- pcap format ---

func newPcapReader(r io.Reader, order binary.ByteOrder, nano bool) (*Reader, error) {
	// Read remaining global header (24 bytes total, 4 already consumed for magic).
	var hdr [20]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("pcap: read global header: %w", err)
	}

	// version_major(2) + version_minor(2) + thiszone(4) + sigfigs(4) + snaplen(4) + network(4)
	snapLen := order.Uint32(hdr[12:16])
	linkType := order.Uint32(hdr[16:20])

	return &Reader{
		r:          r,
		byteOrder:  order,
		linkType:   linkType,
		snapLen:    snapLen,
		nanoPrecis: nano,
	}, nil
}

func (rd *Reader) readPcapPacket() (*PacketRecord, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return nil, err
	}

	tsSec := rd.byteOrder.Uint32(hdr[0:4])
	tsFrac := rd.byteOrder.Uint32(hdr[4:8])
	captureLen := rd.byteOrder.Uint32(hdr[8:12])
	origLen := rd.byteOrder.Uint32(hdr[12:16])

	if captureLen > 0x100000 {
		return nil, fmt.Errorf("pcap: suspiciously large capture length %d", captureLen)
	}

	data := make([]byte, captureLen)
	if _, err := io.ReadFull(rd.r, data); err != nil {
		return nil, fmt.Errorf("pcap: read packet data: %w", err)
	}

	var ts time.Time
	if rd.nanoPrecis {
		ts = time.Unix(int64(tsSec), int64(tsFrac))
	} else {
		ts = time.Unix(int64(tsSec), int64(tsFrac)*1000)
	}

	return &PacketRecord{
		Timestamp:  ts,
		CaptureLen: captureLen,
		OrigLen:    origLen,
		Data:       data,
		LinkType:   rd.linkType,
	}, nil
}

// --- pcapng format ---

func newPcapngReader(r io.Reader, firstBytes []byte) (*Reader, error) {
	rd := &Reader{
		r:        r,
		isPcapng: true,
	}

	// Parse Section Header Block. We already read the first 4 bytes (block type).
	// Read byte order magic + rest of SHB.
	var shbHeader [8]byte // block total length (4) + byte order magic (4)
	if _, err := io.ReadFull(r, shbHeader[:]); err != nil {
		return nil, fmt.Errorf("pcap: read SHB header: %w", err)
	}

	blockLen := binary.LittleEndian.Uint32(shbHeader[0:4])
	bom := binary.LittleEndian.Uint32(shbHeader[4:8])

	if bom == 0x1A2B3C4D {
		rd.byteOrder = binary.LittleEndian
	} else if bom == 0x4D3C2B1A {
		rd.byteOrder = binary.BigEndian
		blockLen = binary.BigEndian.Uint32(shbHeader[0:4])
	} else {
		return nil, fmt.Errorf("pcap: invalid pcapng byte order magic: %08x", bom)
	}

	// Skip the rest of SHB (version + section length + options + trailing length).
	// We already read: block_type(4) + block_total_length(4) + byte_order_magic(4) = 12 bytes.
	remaining := int(blockLen) - 12
	if remaining > 0 {
		if _, err := io.ReadFull(r, make([]byte, remaining)); err != nil {
			return nil, fmt.Errorf("pcap: skip SHB body: %w", err)
		}
	}

	_ = firstBytes // already consumed

	// Eagerly parse IDB blocks that follow the SHB so LinkType() works
	// before the first ReadPacket call.
	if err := rd.parsePcapngMetadata(); err != nil {
		return nil, err
	}

	return rd, nil
}

// parsePcapngMetadata reads blocks until it encounters a non-metadata block
// (i.e., not SHB/IDB). It uses a peekReader to avoid consuming packet data.
func (rd *Reader) parsePcapngMetadata() error {
	pr := &peekReader{r: rd.r}

	for {
		var blockHeader [8]byte
		if _, err := io.ReadFull(pr, blockHeader[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				rd.r = pr
				return nil
			}
			return err
		}

		blockType := rd.byteOrder.Uint32(blockHeader[0:4])
		blockLen := rd.byteOrder.Uint32(blockHeader[4:8])

		if blockLen < 12 {
			// Push back header and let readPcapngPacket handle it.
			pr.pushBack(blockHeader[:])
			rd.r = pr
			return nil
		}

		// If this is not a metadata block, push it back.
		if blockType != blockTypeSHB && blockType != blockTypeIDB {
			pr.pushBack(blockHeader[:])
			rd.r = pr
			return nil
		}

		bodyLen := int(blockLen) - 12
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(pr, body); err != nil {
			return fmt.Errorf("pcap: read IDB body: %w", err)
		}

		var trailing [4]byte
		if _, err := io.ReadFull(pr, trailing[:]); err != nil {
			return fmt.Errorf("pcap: read IDB trailing: %w", err)
		}

		if blockType == blockTypeIDB {
			if len(body) < 8 {
				return fmt.Errorf("pcap: IDB too short")
			}
			lt := rd.byteOrder.Uint32(body[0:4]) & 0xFFFF
			snap := rd.byteOrder.Uint32(body[4:8])
			rd.interfaces = append(rd.interfaces, pcapngInterface{
				linkType: lt,
				snapLen:  snap,
			})
			if rd.linkType == 0 {
				rd.linkType = lt
			}
		}
	}
}

// peekReader wraps an io.Reader and allows pushing back unread data.
type peekReader struct {
	r    io.Reader
	buf  []byte
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}

func (p *peekReader) pushBack(data []byte) {
	p.buf = append(data, p.buf...)
}

func (rd *Reader) readPcapngPacket() (*PacketRecord, error) {
	for {
		var blockHeader [8]byte
		if _, err := io.ReadFull(rd.r, blockHeader[:]); err != nil {
			return nil, err
		}

		blockType := rd.byteOrder.Uint32(blockHeader[0:4])
		blockLen := rd.byteOrder.Uint32(blockHeader[4:8])

		if blockLen < 12 {
			return nil, fmt.Errorf("pcap: invalid block length %d", blockLen)
		}

		// Body length = blockLen - 12 (block_type + block_total_length + trailing block_total_length)
		bodyLen := int(blockLen) - 12
		if bodyLen < 0 {
			return nil, fmt.Errorf("pcap: block body length underflow")
		}

		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(rd.r, body); err != nil {
			return nil, fmt.Errorf("pcap: read block body: %w", err)
		}

		// Read trailing block total length.
		var trailing [4]byte
		if _, err := io.ReadFull(rd.r, trailing[:]); err != nil {
			return nil, fmt.Errorf("pcap: read trailing length: %w", err)
		}

		switch blockType {
		case blockTypeSHB:
			// Another section — re-parse (skip for now).
			rd.interfaces = nil
			continue

		case blockTypeIDB:
			if len(body) < 8 {
				return nil, fmt.Errorf("pcap: IDB too short")
			}
			lt := rd.byteOrder.Uint32(body[0:4]) // LinkType (2 bytes) is in lower 16 bits
			lt = lt & 0xFFFF
			snap := rd.byteOrder.Uint32(body[4:8])
			rd.interfaces = append(rd.interfaces, pcapngInterface{
				linkType: lt,
				snapLen:  snap,
			})
			if rd.linkType == 0 {
				rd.linkType = lt
			}
			continue

		case blockTypeEPB:
			if len(body) < 20 {
				return nil, fmt.Errorf("pcap: EPB too short")
			}
			ifaceID := rd.byteOrder.Uint32(body[0:4])
			tsHigh := rd.byteOrder.Uint32(body[4:8])
			tsLow := rd.byteOrder.Uint32(body[8:12])
			captureLen := rd.byteOrder.Uint32(body[12:16])
			origLen := rd.byteOrder.Uint32(body[16:20])

			if int(captureLen) > len(body)-20 {
				return nil, fmt.Errorf("pcap: EPB capture length %d exceeds body", captureLen)
			}

			data := make([]byte, captureLen)
			copy(data, body[20:20+captureLen])

			// Timestamp is in interface-specific resolution (default: microseconds).
			ts64 := (uint64(tsHigh) << 32) | uint64(tsLow)
			ts := time.Unix(int64(ts64/1000000), int64((ts64%1000000)*1000))

			linkType := rd.linkType
			if int(ifaceID) < len(rd.interfaces) {
				linkType = rd.interfaces[ifaceID].linkType
			}

			return &PacketRecord{
				Timestamp:  ts,
				CaptureLen: captureLen,
				OrigLen:    origLen,
				Data:       data,
				LinkType:   linkType,
			}, nil

		case blockTypeSPB:
			if len(body) < 4 {
				return nil, fmt.Errorf("pcap: SPB too short")
			}
			origLen := rd.byteOrder.Uint32(body[0:4])
			data := body[4:]
			linkType := rd.linkType
			if len(rd.interfaces) > 0 {
				linkType = rd.interfaces[0].linkType
			}
			return &PacketRecord{
				Timestamp:  time.Time{},
				CaptureLen: uint32(len(data)),
				OrigLen:    origLen,
				Data:       data,
				LinkType:   linkType,
			}, nil

		default:
			// Skip unknown block types.
			continue
		}
	}
}

// --- Link type to startFn mapping ---

func linkTypeStartFn(lt uint32) func([]byte) (string, error) {
	switch lt {
	case LinkTypeEthernet:
		return func(_ []byte) (string, error) { return "Ethernet", nil }
	case LinkTypeRaw, LinkTypeIPv4:
		return func(b []byte) (string, error) {
			if len(b) > 0 && (b[0]>>4) == 6 {
				return "IPv6", nil
			}
			return "IP", nil
		}
	case LinkTypeIPv6:
		return func(_ []byte) (string, error) { return "IPv6", nil }
	case LinkTypeNull:
		return func(_ []byte) (string, error) { return "IP", nil }
	default:
		return func(_ []byte) (string, error) { return "Ethernet", nil }
	}
}
