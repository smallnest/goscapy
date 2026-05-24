// Package tcpstream implements TCP stream reassembly.
//
// It tracks TCP sessions by (src_ip, src_port, dst_ip, dst_port), reassembles
// segments in sequence-number order, handles overlaps and retransmissions,
// and exposes bidirectional byte streams for application-layer analysis.
package tcpstream

import (
	"net"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

const (
	defaultStreamTimeout = 120 * time.Second
	defaultMaxStreams    = 4096
	maxStreamBytes      = 16 * 1024 * 1024 // 16 MB per direction
)

// StreamKey identifies one half of a TCP conversation (one direction).
type StreamKey struct {
	SrcIP   [16]byte // supports both IPv4 (first 4 bytes) and IPv6
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
}

// StreamID identifies a full TCP conversation (both directions).
// The canonical form has the smaller (IP, port) tuple first.
type StreamID struct {
	A, B StreamKey
}

// normalizeStreamID returns a canonical StreamID for a pair of endpoints.
func normalizeStreamID(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) StreamID {
	a := makeKey(srcIP, srcPort, dstIP, dstPort)
	b := makeKey(dstIP, dstPort, srcIP, srcPort)
	if lessKey(a, b) {
		return StreamID{A: a, B: b}
	}
	return StreamID{A: b, B: a}
}

func makeKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) StreamKey {
	k := StreamKey{SrcPort: srcPort, DstPort: dstPort}
	ip4 := srcIP.To4()
	if ip4 != nil {
		copy(k.SrcIP[:], ip4)
	} else {
		copy(k.SrcIP[:], srcIP.To16())
	}
	ip4 = dstIP.To4()
	if ip4 != nil {
		copy(k.DstIP[:], ip4)
	} else {
		copy(k.DstIP[:], dstIP.To16())
	}
	return k
}

func lessKey(a, b StreamKey) bool {
	for i := range a.SrcIP {
		if a.SrcIP[i] != b.SrcIP[i] {
			return a.SrcIP[i] < b.SrcIP[i]
		}
	}
	for i := range a.DstIP {
		if a.DstIP[i] != b.DstIP[i] {
			return a.DstIP[i] < b.DstIP[i]
		}
	}
	if a.SrcPort != b.SrcPort {
		return a.SrcPort < b.SrcPort
	}
	return a.DstPort < b.DstPort
}

// Direction indicates which half of the conversation.
type Direction int

const (
	DirUnknown Direction = iota
	DirClientToServer
	DirServerToClient
)

// segment is one TCP segment within a stream direction.
type segment struct {
	seq  uint32
	data []byte
}

// halfStream tracks one direction of a TCP conversation.
type halfStream struct {
	key      StreamKey
	segments []segment
	nextSeq  uint32 // expected next sequence number
	isn      uint32 // initial sequence number
	started  bool
	buf      []byte // reassembled bytes
	totalBuf int    // total bytes buffered (for DoS protection)
	lastSeen time.Time
	finished bool // FIN received
}

func newHalfStream(key StreamKey) *halfStream {
	return &halfStream{
		key:      key,
		segments: make([]segment, 0),
		lastSeen: time.Now(),
	}
}

// tcpStream holds both directions of a TCP conversation.
type tcpStream struct {
	id       StreamID
	client   *halfStream
	server   *halfStream
	lastSeen time.Time
}

// TCPStream is the public view of a reassembled TCP stream.
type TCPStream struct {
	ID          StreamID
	ClientBytes []byte // client → server bytes
	ServerBytes []byte // server → client bytes
	Direction   Direction
}

// Reassembler reassembles TCP segments into ordered byte streams.
type Reassembler struct {
	mu         sync.Mutex
	streams    map[StreamID]*tcpStream
	timeout    time.Duration
	maxStreams int
	stopGC     chan struct{}
	gcDone     chan struct{}
}

// Option configures a Reassembler.
type Option func(*Reassembler)

// WithStreamTimeout sets the stream expiration timeout (default 120s).
func WithStreamTimeout(d time.Duration) Option {
	return func(r *Reassembler) { r.timeout = d }
}

// WithMaxStreams sets the maximum concurrent streams (DoS protection).
func WithMaxStreams(n int) Option {
	return func(r *Reassembler) { r.maxStreams = n }
}

// New creates a TCP stream Reassembler with the given options.
// Call Close() to stop the background GC goroutine.
func New(opts ...Option) *Reassembler {
	r := &Reassembler{
		streams:    make(map[StreamID]*tcpStream),
		timeout:    defaultStreamTimeout,
		maxStreams: defaultMaxStreams,
		stopGC:     make(chan struct{}),
		gcDone:     make(chan struct{}),
	}
	for _, o := range opts {
		o(r)
	}
	go r.gc()
	return r
}

// Close stops the background garbage collector.
func (r *Reassembler) Close() {
	close(r.stopGC)
	<-r.gcDone
}

// Submit processes a packet containing a TCP segment.
// It returns a non-nil TCPStream when new data is available for a stream,
// or nil if the packet is not TCP or data was already seen (retransmission).
//
// The caller should pass dissected packets (containing both IP and TCP layers).
func (r *Reassembler) Submit(pkt *packet.Packet) *TCPStream {
	ipLayer := pkt.GetLayer("IP")
	if ipLayer == nil {
		// Also try IPv6
		ipLayer = pkt.GetLayer("IPv6")
	}
	if ipLayer == nil {
		return nil
	}

	tcpLayer := pkt.GetLayer("TCP")
	if tcpLayer == nil {
		return nil
	}

	srcIP := extractIP(ipLayer, "src")
	dstIP := extractIP(ipLayer, "dst")
	if srcIP == nil || dstIP == nil {
		return nil
	}

	sportVal, _ := tcpLayer.Get("sport")
	dportVal, _ := tcpLayer.Get("dport")
	seqVal, _ := tcpLayer.Get("seq")
	flagsVal, _ := tcpLayer.Get("flags")

	sport, _ := sportVal.(uint16)
	dport, _ := dportVal.(uint16)
	seq, _ := seqVal.(uint32)
	flags, _ := flagsVal.(uint8)

	// Extract TCP payload (bytes after TCP header).
	payload := extractTCPPayload(pkt, tcpLayer)
	isSyn := flags&layers.TCPSyn != 0
	isFin := flags&layers.TCPFin != 0
	isRst := flags&layers.TCPRst != 0

	// SYN with no payload: establish stream, set ISN.
	// SYN+ACK is also valid (server response).
	if isSyn && len(payload) == 0 && !isFin {
		return r.handleSyn(srcIP, sport, dstIP, dport, seq, isRst)
	}

	// RST: tear down stream
	if isRst {
		return r.handleRst(srcIP, sport, dstIP, dport)
	}

	// No payload and no FIN: just an ACK, skip
	if len(payload) == 0 && !isFin {
		return nil
	}

	return r.handleData(srcIP, sport, dstIP, dport, seq, payload, isFin)
}

// handleSyn processes a SYN segment to establish a new stream.
func (r *Reassembler) handleSyn(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, seq uint32, rst bool) *TCPStream {
	id := normalizeStreamID(srcIP, srcPort, dstIP, dstPort)
	key := makeKey(srcIP, srcPort, dstIP, dstPort)

	r.mu.Lock()
	defer r.mu.Unlock()

	s, exists := r.streams[id]
	if !exists {
		if len(r.streams) >= r.maxStreams {
			return nil
		}
		s = &tcpStream{
			id:     id,
			client: newHalfStream(key),
			server: newHalfStream(makeKey(dstIP, dstPort, srcIP, srcPort)),
		}
		r.streams[id] = s
	}

	hs := s.client
	if hs.key != key {
		hs = s.server
	}
	if !hs.started {
		hs.isn = seq
		hs.nextSeq = seq + 1
		hs.started = true
	}
	s.lastSeen = time.Now()

	return nil
}

// handleRst removes a stream on RST.
func (r *Reassembler) handleRst(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) *TCPStream {
	id := normalizeStreamID(srcIP, srcPort, dstIP, dstPort)

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.streams, id)
	return nil
}

// handleData processes a data segment and attempts reassembly.
func (r *Reassembler) handleData(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, seq uint32, payload []byte, fin bool) *TCPStream {
	id := normalizeStreamID(srcIP, srcPort, dstIP, dstPort)
	key := makeKey(srcIP, srcPort, dstIP, dstPort)

	r.mu.Lock()
	defer r.mu.Unlock()

	s, exists := r.streams[id]
	if !exists {
		if len(r.streams) >= r.maxStreams {
			return nil
		}
		s = &tcpStream{
			id:     id,
			client: newHalfStream(key),
			server: newHalfStream(makeKey(dstIP, dstPort, srcIP, srcPort)),
		}
		r.streams[id] = s
	}

	// Find which half-stream this belongs to.
	hs := s.client
	if hs.key != key {
		hs = s.server
	}

	// If not started (missed SYN), set ISN from first seen segment.
	if !hs.started {
		hs.isn = seq
		hs.nextSeq = seq
		hs.started = true
	}

	hs.lastSeen = time.Now()
	s.lastSeen = time.Now()

	// DoS protection: reject oversized streams.
	hs.totalBuf += len(payload)
	if hs.totalBuf > maxStreamBytes {
		delete(r.streams, id)
		return nil
	}

	// Handle FIN: mark stream as finished after this data.
	if fin {
		hs.finished = true
	}

	// Skip if entirely before nextSeq (old retransmission).
	if seqBefore(seq, hs.nextSeq) && seqBeforeEq(addSeq(seq, uint32(len(payload))), hs.nextSeq) {
		// Still return current stream state
		return r.snapshotStream(s, id)
	}

	// Store segment.
	hs.segments = append(hs.segments, segment{seq: seq, data: payload})

	// Try to advance nextSeq with contiguous data.
	r.advance(hs)

	return r.snapshotStream(s, id)
}

// advance tries to extend the reassembly buffer from contiguous segments.
func (r *Reassembler) advance(hs *halfStream) {
	for {
		found := false
		for i, seg := range hs.segments {
			if seg.seq == hs.nextSeq {
				// Exact match: append and advance.
				hs.buf = append(hs.buf, seg.data...)
				hs.nextSeq = addSeq(hs.nextSeq, uint32(len(seg.data)))
				hs.segments = append(hs.segments[:i], hs.segments[i+1:]...)
				found = true
				break
			}
			// Overlap: segment starts before nextSeq but extends past it.
			if seqBefore(seg.seq, hs.nextSeq) {
				end := addSeq(seg.seq, uint32(len(seg.data)))
				if seqBeforeEq(end, hs.nextSeq) {
					continue
				}
				overlap := subtractSeq(hs.nextSeq, seg.seq)
				if int(overlap) < len(seg.data) {
					trimmed := seg.data[overlap:]
					hs.buf = append(hs.buf, trimmed...)
					hs.nextSeq = addSeq(hs.nextSeq, uint32(len(trimmed)))
					hs.segments = append(hs.segments[:i], hs.segments[i+1:]...)
					found = true
					break
				}
			}
		}
		if !found {
			break
		}
	}
}

// snapshot returns a copy of the current reassembly buffer.
func (hs *halfStream) snapshot() []byte {
	if len(hs.buf) == 0 {
		return nil
	}
	cp := make([]byte, len(hs.buf))
	copy(cp, hs.buf)
	return cp
}

// snapshotStream creates a TCPStream snapshot from both directions.
func (r *Reassembler) snapshotStream(s *tcpStream, id StreamID) *TCPStream {
	// Only return if there's something to report.
	if len(s.client.buf) == 0 && len(s.server.buf) == 0 &&
		len(s.client.segments) == 0 && len(s.server.segments) == 0 &&
		!s.client.finished && !s.server.finished {
		return nil
	}
	return &TCPStream{
		ID:          id,
		ClientBytes: s.client.snapshot(),
		ServerBytes: s.server.snapshot(),
	}
}

// ReadStream returns the current reassembled data for a given stream ID.
// Returns nil if the stream doesn't exist.
func (r *Reassembler) ReadStream(id StreamID) *TCPStream {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, exists := r.streams[id]
	if !exists {
		return nil
	}
	return &TCPStream{
		ID:          id,
		ClientBytes: s.client.snapshot(),
		ServerBytes: s.server.snapshot(),
	}
}

// StreamIDs returns all active stream IDs.
func (r *Reassembler) StreamIDs() []StreamID {
	r.mu.Lock()
	defer r.mu.Unlock()

	ids := make([]StreamID, 0, len(r.streams))
	for id := range r.streams {
		ids = append(ids, id)
	}
	return ids
}

// RemoveStream removes a stream from the reassembler.
func (r *Reassembler) RemoveStream(id StreamID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.streams, id)
}

// Stats returns the number of active streams.
func (r *Reassembler) Stats() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams)
}

// gc periodically removes expired streams.
func (r *Reassembler) gc() {
	defer close(r.gcDone)
	ticker := time.NewTicker(r.timeout / 4)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopGC:
			return
		case <-ticker.C:
			r.sweep()
		}
	}
}

func (r *Reassembler) sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for id, s := range r.streams {
		if now.Sub(s.lastSeen) > r.timeout {
			delete(r.streams, id)
		}
	}
}

// extractIP extracts an IP address from a layer field.
func extractIP(layer *packet.Layer, field string) net.IP {
	v, err := layer.Get(field)
	if err != nil {
		return nil
	}
	switch ip := v.(type) {
	case net.IP:
		return ip
	case string:
		return net.ParseIP(ip)
	}
	return nil
}

// extractTCPPayload extracts the TCP payload bytes from a packet.
func extractTCPPayload(pkt *packet.Packet, tcpLayer *packet.Layer) []byte {
	// Find the Raw layer (TCP payload) or compute from packet bytes.
	for _, l := range pkt.Layers() {
		if l.Proto() == "Raw" {
			v, err := l.Get("load")
			if err != nil {
				continue
			}
			switch data := v.(type) {
			case []byte:
				return data
			case string:
				return []byte(data)
			}
		}
	}

	// Fallback: build the packet and extract TCP payload from wire bytes.
	raw, err := pkt.Build()
	if err != nil {
		return nil
	}

	// Find IP header end.
	ipLayer := pkt.GetLayer("IP")
	if ipLayer == nil {
		ipLayer = pkt.GetLayer("IPv6")
	}
	if ipLayer == nil {
		return nil
	}

	var ipHdrLen int
	if ipLayer.Proto() == "IP" {
		verihl, _ := ipLayer.Get("verihl")
		v, _ := verihl.(uint8)
		ipHdrLen = int(v&0x0F) * 4
	} else {
		// IPv6: fixed 40 bytes + extension headers
		ipHdrLen = 40
	}

	// Find TCP header length.
	dataofs, _ := tcpLayer.Get("dataofs")
	d, _ := dataofs.(uint8)
	tcpHdrLen := int(d>>4) * 4

	offset := ipHdrLen + tcpHdrLen
	if offset >= len(raw) {
		return nil
	}
	return raw[offset:]
}

// ---- TCP sequence number arithmetic (wraps at 2^32) ----

func addSeq(a, b uint32) uint32 { return a + b }

func subtractSeq(a, b uint32) uint32 { return a - b }

// seqBefore reports whether a is before b in sequence space (handles wraparound).
func seqBefore(a, b uint32) bool {
	return int32(a-b) < 0
}

// seqBeforeEq reports whether a is before or equal to b in sequence space.
func seqBeforeEq(a, b uint32) bool {
	return int32(a-b) <= 0
}
