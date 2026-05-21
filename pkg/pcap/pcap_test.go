package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestWriterReaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	// Write 3 packets.
	w, err := NewWriter(&buf, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	packets := [][]byte{
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x01},
		{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x02},
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x03},
	}
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	for i, pkt := range packets {
		if err := w.WritePacket(pkt, ts.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("WritePacket[%d]: %v", i, err)
		}
	}

	// Read back.
	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	if r.LinkType() != LinkTypeEthernet {
		t.Errorf("LinkType: expected %d, got %d", LinkTypeEthernet, r.LinkType())
	}

	for i := range 3 {
		rec, err := r.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket[%d]: %v", i, err)
		}
		if !bytes.Equal(rec.Data, packets[i]) {
			t.Errorf("packet[%d] data mismatch", i)
		}
		expectedTs := ts.Add(time.Duration(i) * time.Second)
		if rec.Timestamp.Unix() != expectedTs.Unix() {
			t.Errorf("packet[%d] timestamp: expected %v, got %v", i, expectedTs, rec.Timestamp)
		}
	}

	// Should get EOF.
	_, err = r.ReadPacket()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestReaderBigEndian(t *testing.T) {
	var buf bytes.Buffer

	// Write a big-endian pcap manually.
	var hdr [24]byte
	binary.BigEndian.PutUint32(hdr[0:4], magicMicrosecondsBig) // LE representation of BE magic
	// Actually for big-endian, the magic bytes on disk are D4 C3 B2 A1.
	// When read as LE uint32, that's 0xA1B2C3D4... no wait.
	// magicMicrosecondsBig = 0xD4C3B2A1 — this is the LE uint32 representation
	// of the bytes [D4, C3, B2, A1] which is what a BE pcap file starts with.
	// Actually let me think about this more carefully.
	// A big-endian pcap file has bytes: A1 B2 C3 D4 (the magic in BE).
	// Read as LE uint32: D4C3B2A1 = magicMicrosecondsBig. ✓

	// For the test, write bytes directly in BE pcap format.
	binary.BigEndian.PutUint32(hdr[0:4], magicMicroseconds) // 0xA1B2C3D4 in BE
	binary.BigEndian.PutUint16(hdr[4:6], 2)
	binary.BigEndian.PutUint16(hdr[6:8], 4)
	binary.BigEndian.PutUint32(hdr[16:20], 65535)
	binary.BigEndian.PutUint32(hdr[20:24], LinkTypeEthernet)
	buf.Write(hdr[:])

	// Write one packet record in BE.
	pktData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	var pktHdr [16]byte
	binary.BigEndian.PutUint32(pktHdr[0:4], 1700000000) // ts_sec
	binary.BigEndian.PutUint32(pktHdr[4:8], 500000)     // ts_usec
	binary.BigEndian.PutUint32(pktHdr[8:12], uint32(len(pktData)))
	binary.BigEndian.PutUint32(pktHdr[12:16], uint32(len(pktData)))
	buf.Write(pktHdr[:])
	buf.Write(pktData)

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	rec, err := r.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(rec.Data, pktData) {
		t.Errorf("data mismatch: %v", rec.Data)
	}
	if rec.Timestamp.Unix() != 1700000000 {
		t.Errorf("timestamp: expected 1700000000, got %d", rec.Timestamp.Unix())
	}
}

func TestReaderNanosecond(t *testing.T) {
	var buf bytes.Buffer

	// Write a nanosecond-precision pcap.
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], magicNanoseconds)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], LinkTypeEthernet)
	buf.Write(hdr[:])

	pktData := []byte{0xde, 0xad}
	var pktHdr [16]byte
	binary.LittleEndian.PutUint32(pktHdr[0:4], 1700000000)
	binary.LittleEndian.PutUint32(pktHdr[4:8], 123456789) // nanoseconds
	binary.LittleEndian.PutUint32(pktHdr[8:12], uint32(len(pktData)))
	binary.LittleEndian.PutUint32(pktHdr[12:16], uint32(len(pktData)))
	buf.Write(pktHdr[:])
	buf.Write(pktData)

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	rec, err := r.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if rec.Timestamp.Nanosecond() != 123456789 {
		t.Errorf("nanosecond: expected 123456789, got %d", rec.Timestamp.Nanosecond())
	}
}

func TestPcapngReader(t *testing.T) {
	var buf bytes.Buffer

	order := binary.LittleEndian

	// Write SHB.
	writePcapngBlock(&buf, order, blockTypeSHB, func(b *bytes.Buffer) {
		order.PutUint32(scratch4(b), 0x1A2B3C4D) // BOM
		order.PutUint16(scratch2(b), 1)           // version major
		order.PutUint16(scratch2(b), 0)           // version minor
		order.PutUint64(scratch8(b), 0xFFFFFFFFFFFFFFFF) // section length (unknown)
	})

	// Write IDB (Ethernet, snaplen=65535).
	writePcapngBlock(&buf, order, blockTypeIDB, func(b *bytes.Buffer) {
		order.PutUint16(scratch2(b), uint16(LinkTypeEthernet)) // link type
		order.PutUint16(scratch2(b), 0)                       // reserved
		order.PutUint32(scratch4(b), 65535)                    // snap len
	})

	// Write EPB with a small packet.
	pktData := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00}
	ts := uint64(1700000000) * 1000000 // microseconds
	writePcapngBlock(&buf, order, blockTypeEPB, func(b *bytes.Buffer) {
		order.PutUint32(scratch4(b), 0)                 // interface ID
		order.PutUint32(scratch4(b), uint32(ts>>32))    // timestamp high
		order.PutUint32(scratch4(b), uint32(ts&0xFFFFFFFF)) // timestamp low
		order.PutUint32(scratch4(b), uint32(len(pktData)))  // captured len
		order.PutUint32(scratch4(b), uint32(len(pktData)))  // original len
		b.Write(pktData)
		// Pad to 4 bytes.
		if pad := len(pktData) % 4; pad != 0 {
			b.Write(make([]byte, 4-pad))
		}
	})

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	if r.LinkType() != LinkTypeEthernet {
		t.Errorf("LinkType: expected %d, got %d", LinkTypeEthernet, r.LinkType())
	}

	rec, err := r.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(rec.Data, pktData) {
		t.Errorf("data mismatch: got %x", rec.Data)
	}
	if rec.Timestamp.Unix() != 1700000000 {
		t.Errorf("timestamp: expected 1700000000, got %d", rec.Timestamp.Unix())
	}
}

func TestPacketsChannel(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}

	ts := time.Now()
	for i := range 5 {
		w.WritePacket([]byte{byte(i), 0x01, 0x02}, ts.Add(time.Duration(i)*time.Millisecond))
	}

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	var readErr error
	count := 0
	for rec := range r.Packets(&readErr) {
		if rec.Data[0] != byte(count) {
			t.Errorf("packet %d: first byte %d != %d", count, rec.Data[0], count)
		}
		count++
	}
	if readErr != nil {
		t.Errorf("Packets error: %v", readErr)
	}
	if count != 5 {
		t.Errorf("expected 5 packets, got %d", count)
	}
}

func TestWriterSnapLen(t *testing.T) {
	var buf bytes.Buffer
	snapLen := uint32(10)
	w, err := NewWriter(&buf, LinkTypeEthernet, snapLen)
	if err != nil {
		t.Fatal(err)
	}

	// Write a packet larger than snapLen.
	bigPkt := make([]byte, 100)
	for i := range bigPkt {
		bigPkt[i] = byte(i)
	}
	w.WritePacket(bigPkt, time.Now())

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	rec, err := r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	// CaptureLen should be truncated to snapLen.
	if rec.CaptureLen != snapLen {
		t.Errorf("CaptureLen: expected %d, got %d", snapLen, rec.CaptureLen)
	}
	// OrigLen should be the full original size.
	if rec.OrigLen != 100 {
		t.Errorf("OrigLen: expected 100, got %d", rec.OrigLen)
	}
}

func TestPacketRecordDissect(t *testing.T) {
	// Build a real Ethernet/IP/TCP packet.
	eth := layers.NewEthernet()
	eth.Set("src", "00:11:22:33:44:55")
	eth.Set("dst", "ff:ff:ff:ff:ff:ff")
	eth.Set("type", uint16(0x0800))

	ip := layers.NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")
	ip.Set("proto", layers.IPProtoTCP)

	tcp := layers.NewTCPWith(80, 12345, layers.TCPSyn|layers.TCPAck)

	pkt := packet.NewFrom(eth, ip, tcp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	rec := &PacketRecord{
		Data:     raw,
		LinkType: LinkTypeEthernet,
	}

	dissected, err := rec.Packet()
	if err != nil {
		t.Fatalf("Packet() dissect failed: %v", err)
	}

	if !dissected.HasLayer("TCP") {
		t.Error("dissected packet missing TCP layer")
	}
	tcpLayer := dissected.GetLayer("TCP")
	sport, _ := tcpLayer.Get("sport")
	if sport.(uint16) != 80 {
		t.Errorf("sport: expected 80, got %v", sport)
	}
}

func TestInvalidMagic(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	_, err := NewReader(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

// --- helpers for building pcapng blocks ---

func writePcapngBlock(buf *bytes.Buffer, order binary.ByteOrder, blockType uint32, bodyFn func(*bytes.Buffer)) {
	var body bytes.Buffer
	bodyFn(&body)

	// Block total length = type(4) + length(4) + body + trailing_length(4)
	totalLen := uint32(12 + body.Len())

	var header [8]byte
	order.PutUint32(header[0:4], blockType)
	order.PutUint32(header[4:8], totalLen)
	buf.Write(header[:])
	buf.Write(body.Bytes())

	var trail [4]byte
	order.PutUint32(trail[:], totalLen)
	buf.Write(trail[:])
}

func scratch4(b *bytes.Buffer) []byte {
	s := [4]byte{}
	b.Write(s[:])
	return b.Bytes()[b.Len()-4:]
}

func scratch2(b *bytes.Buffer) []byte {
	s := [2]byte{}
	b.Write(s[:])
	return b.Bytes()[b.Len()-2:]
}

func scratch8(b *bytes.Buffer) []byte {
	s := [8]byte{}
	b.Write(s[:])
	return b.Bytes()[b.Len()-8:]
}
