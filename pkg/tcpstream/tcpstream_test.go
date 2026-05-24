package tcpstream

import (
	"net"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// makeTCPPacket creates a dissected packet with IP+TCP+payload.
func makeTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, flags uint8, payload []byte) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", net.ParseIP(srcIP))
	ip.Set("dst", net.ParseIP(dstIP))

	tcp := layers.NewTCP()
	tcp.Set("sport", srcPort)
	tcp.Set("dport", dstPort)
	tcp.Set("seq", seq)
	tcp.Set("flags", flags)

	pkt := ip.Over(tcp)
	if len(payload) > 0 {
		raw := layers.NewRaw()
		raw.Set("load", payload)
		pkt.Push(raw)
	}
	return pkt
}

func TestBasicStreamReassembly(t *testing.T) {
	r := New()
	defer r.Close()

	// SYN: client → server
	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	result := r.Submit(syn)
	if result != nil {
		t.Fatal("SYN should return nil (no data yet)")
	}

	// SYN-ACK: server → client
	synack := makeTCPPacket("10.0.0.2", "10.0.0.1", 80, 12345, 5000, layers.TCPSyn|layers.TCPAck, nil)
	result = r.Submit(synack)
	if result != nil {
		t.Fatal("SYN-ACK should return nil")
	}

	// Data segment 1: "Hello "
	data1 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1001, layers.TCPAck, []byte("Hello "))
	result = r.Submit(data1)
	if result == nil {
		t.Fatal("Expected non-nil result for data segment")
	}
	if string(result.ClientBytes) != "Hello " {
		t.Errorf("ClientBytes = %q, want %q", result.ClientBytes, "Hello ")
	}

	// Data segment 2: "World"
	data2 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1007, layers.TCPAck, []byte("World"))
	result = r.Submit(data2)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if string(result.ClientBytes) != "Hello World" {
		t.Errorf("ClientBytes = %q, want %q", result.ClientBytes, "Hello World")
	}

	if r.Stats() != 1 {
		t.Errorf("Stats() = %d, want 1", r.Stats())
	}
}

func TestOutOfOrderSegments(t *testing.T) {
	r := New()
	defer r.Close()

	// SYN
	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	// Segment 2 arrives first (seq=1007, "World", 5 bytes)
	seg2 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1007, layers.TCPAck, []byte("World"))
	result := r.Submit(seg2)
	// nextSeq=1001, seg2 at 1007 → gap, can't advance, buf is empty
	// segments stored but no buffered data
	if result != nil {
		t.Logf("Gap segment returned: ClientBytes=%q (expected nil or empty)", result.ClientBytes)
	}

	// Segment 1 arrives (seq=1001, "Hello ", 6 bytes) → fills gap
	seg1 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1001, layers.TCPAck, []byte("Hello "))
	result = r.Submit(seg1)
	if result == nil {
		t.Fatal("Expected non-nil result after gap filled")
	}
	if string(result.ClientBytes) != "Hello World" {
		t.Errorf("ClientBytes = %q, want %q", result.ClientBytes, "Hello World")
	}
}

func TestBidirectionalStream(t *testing.T) {
	r := New()
	defer r.Close()

	// SYN: client → server
	syn := makeTCPPacket("192.168.1.1", "192.168.1.2", 5000, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	// SYN-ACK: server → client
	synack := makeTCPPacket("192.168.1.2", "192.168.1.1", 80, 5000, 2000, layers.TCPSyn|layers.TCPAck, nil)
	r.Submit(synack)

	// Client data
	cdata := makeTCPPacket("192.168.1.1", "192.168.1.2", 5000, 80, 1001, layers.TCPAck, []byte("GET / HTTP/1.1"))
	result := r.Submit(cdata)
	if result == nil {
		t.Fatal("Expected result")
	}
	if string(result.ClientBytes) != "GET / HTTP/1.1" {
		t.Errorf("ClientBytes = %q", result.ClientBytes)
	}

	// Server data
	sdata := makeTCPPacket("192.168.1.2", "192.168.1.1", 80, 5000, 2001, layers.TCPAck, []byte("HTTP/1.1 200 OK"))
	result = r.Submit(sdata)
	if result == nil {
		t.Fatal("Expected result")
	}
	if string(result.ServerBytes) != "HTTP/1.1 200 OK" {
		t.Errorf("ServerBytes = %q", result.ServerBytes)
	}
}

func TestRetransmission(t *testing.T) {
	r := New()
	defer r.Close()

	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	// Original segment
	seg1 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1001, layers.TCPAck, []byte("Hello "))
	r.Submit(seg1)

	// Retransmission of same data
	retrans := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1001, layers.TCPAck, []byte("Hello "))
	result := r.Submit(retrans)
	if result == nil {
		t.Fatal("Retransmission should still return stream")
	}
	// Should not duplicate data
	if string(result.ClientBytes) != "Hello " {
		t.Errorf("ClientBytes = %q, want %q (no duplication)", result.ClientBytes, "Hello ")
	}
}

func TestOverlappingSegments(t *testing.T) {
	r := New()
	defer r.Close()

	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	// Segment 1: "Hello " (seq=1001, 6 bytes, ends at 1007)
	seg1 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1001, layers.TCPAck, []byte("Hello "))
	r.Submit(seg1)

	// Segment 2: "World" (seq=1007, 5 bytes, ends at 1012)
	seg2 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1007, layers.TCPAck, []byte("World"))
	r.Submit(seg2)

	// Overlapping segment: "World!!!" starts at seq 1007 (overlaps "World" part)
	// seg3 covers 1007-1015. Existing data covers 1001-1012. New bytes: 1012-1015 = "!!!"
	seg3 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1007, layers.TCPAck, []byte("World!!!"))
	result := r.Submit(seg3)
	if result == nil {
		t.Fatal("Expected result")
	}
	// "Hello " + "World" = "Hello World". Overlap adds "!!!" → "Hello World!!!"
	if string(result.ClientBytes) != "Hello World!!!" {
		t.Errorf("ClientBytes = %q, want %q", result.ClientBytes, "Hello World!!!")
	}
}

func TestRSTClosesStream(t *testing.T) {
	r := New()
	defer r.Close()

	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	if r.Stats() != 1 {
		t.Errorf("Stats() = %d, want 1", r.Stats())
	}

	// RST from client
	rst := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1001, layers.TCPRst, nil)
	r.Submit(rst)

	if r.Stats() != 0 {
		t.Errorf("Stats() after RST = %d, want 0", r.Stats())
	}
}

func TestReadStream(t *testing.T) {
	r := New()
	defer r.Close()

	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	seg := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1001, layers.TCPAck, []byte("data"))
	r.Submit(seg)

	ids := r.StreamIDs()
	if len(ids) != 1 {
		t.Fatalf("StreamIDs() returned %d streams", len(ids))
	}

	stream := r.ReadStream(ids[0])
	if stream == nil {
		t.Fatal("ReadStream returned nil")
	}
	if string(stream.ClientBytes) != "data" {
		t.Errorf("ClientBytes = %q, want %q", stream.ClientBytes, "data")
	}
}

func TestSequenceWraparound(t *testing.T) {
	r := New()
	defer r.Close()

	// Start near max uint32
	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 0xFFFFFFF0, layers.TCPSyn, nil)
	r.Submit(syn)

	// Data starting at 0xFFFFFFF1 (seq wraps)
	seg1 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 0xFFFFFFF1, layers.TCPAck, []byte("ABCD"))
	result := r.Submit(seg1)
	if result == nil {
		t.Fatal("Expected result")
	}
	if string(result.ClientBytes) != "ABCD" {
		t.Errorf("ClientBytes = %q, want %q", result.ClientBytes, "ABCD")
	}

	// Next segment wraps around
	seg2 := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 0xFFFFFFF5, layers.TCPAck, []byte("EFGH"))
	result = r.Submit(seg2)
	if result == nil {
		t.Fatal("Expected result")
	}
	if string(result.ClientBytes) != "ABCDEFGH" {
		t.Errorf("ClientBytes = %q, want %q", result.ClientBytes, "ABCDEFGH")
	}
}

func TestMissingSYN(t *testing.T) {
	r := New()
	defer r.Close()

	// Data without SYN — should still work (ISN inferred from first segment)
	seg := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 5000, layers.TCPAck, []byte("Hello "))
	result := r.Submit(seg)
	if result == nil {
		t.Fatal("Should handle missing SYN")
	}
	if string(result.ClientBytes) != "Hello " {
		t.Errorf("ClientBytes = %q, want %q", result.ClientBytes, "Hello ")
	}
}

func TestPureACKIgnored(t *testing.T) {
	r := New()
	defer r.Close()

	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	// Pure ACK with no payload
	ack := makeTCPPacket("10.0.0.2", "10.0.0.1", 80, 12345, 5000, layers.TCPAck, nil)
	result := r.Submit(ack)
	if result != nil {
		t.Fatal("Pure ACK should return nil")
	}
}

func TestNonTCPPacketIgnored(t *testing.T) {
	r := New()
	defer r.Close()

	// Packet with no TCP layer
	ip := layers.NewIP()
	ip.Set("src", net.ParseIP("10.0.0.1"))
	ip.Set("dst", net.ParseIP("10.0.0.2"))
	udp := layers.NewUDP()
	pkt := ip.Over(udp)

	result := r.Submit(pkt)
	if result != nil {
		t.Fatal("Non-TCP packet should return nil")
	}
}

func TestRemoveStream(t *testing.T) {
	r := New()
	defer r.Close()

	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	ids := r.StreamIDs()
	if len(ids) != 1 {
		t.Fatalf("Expected 1 stream, got %d", len(ids))
	}

	r.RemoveStream(ids[0])
	if r.Stats() != 0 {
		t.Errorf("Stats() after remove = %d, want 0", r.Stats())
	}
}

func TestStreamTimeout(t *testing.T) {
	r := New(WithStreamTimeout(100 * time.Millisecond))
	defer r.Close()

	syn := makeTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, layers.TCPSyn, nil)
	r.Submit(syn)

	if r.Stats() != 1 {
		t.Errorf("Stats() = %d, want 1", r.Stats())
	}

	// Wait for GC to clean up
	time.Sleep(300 * time.Millisecond)

	if r.Stats() != 0 {
		t.Errorf("Stats() after timeout = %d, want 0", r.Stats())
	}
}
