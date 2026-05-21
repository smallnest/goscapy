// Package reassembly implements IP fragment reassembly.
//
// It aggregates IP fragments by (src, dst, id, proto) and produces
// reassembled packets once all fragments arrive or a timeout expires.
package reassembly

import (
	"net"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

const (
	maxReassembledSize = 65535
	defaultTimeout     = 30 * time.Second
	defaultMaxGroups   = 1024
)

// fragKey identifies a fragment group.
type fragKey struct {
	src   [4]byte
	dst   [4]byte
	id    uint16
	proto uint8
}

// fragment represents a single IP fragment.
type fragment struct {
	offset uint32 // byte offset (fragment offset * 8)
	length uint32
	data   []byte
	more   bool // MF flag
}

// fragGroup holds all fragments for a given key.
type fragGroup struct {
	frags      []fragment
	totalBytes uint32
	lastSeen   time.Time
	hasLast    bool   // received fragment with MF=0
	finalEnd   uint32 // end offset of the last fragment (offset+length)
}

// Reassembler reassembles IP fragments into complete packets.
type Reassembler struct {
	mu        sync.Mutex
	groups    map[fragKey]*fragGroup
	timeout   time.Duration
	maxGroups int
	stopGC    chan struct{}
	gcDone    chan struct{}
}

// Option configures a Reassembler.
type Option func(*Reassembler)

// WithTimeout sets the fragment group expiration timeout.
func WithTimeout(d time.Duration) Option {
	return func(r *Reassembler) { r.timeout = d }
}

// WithMaxGroups sets the maximum number of concurrent fragment groups (DoS protection).
func WithMaxGroups(n int) Option {
	return func(r *Reassembler) { r.maxGroups = n }
}

// New creates a Reassembler with the given options.
// Call Close() to stop the background GC goroutine.
func New(opts ...Option) *Reassembler {
	r := &Reassembler{
		groups:    make(map[fragKey]*fragGroup),
		timeout:   defaultTimeout,
		maxGroups: defaultMaxGroups,
		stopGC:    make(chan struct{}),
		gcDone:    make(chan struct{}),
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

// Submit processes an IP packet. If the packet is not fragmented, it is
// returned as-is. If it completes a fragment group, the reassembled packet
// is returned. Otherwise nil is returned (fragment stored, waiting for more).
func (r *Reassembler) Submit(pkt *packet.Packet) *packet.Packet {
	ipLayer := pkt.GetLayer("IP")
	if ipLayer == nil {
		return pkt
	}

	fragVal, _ := ipLayer.Get("frag")
	frag, _ := fragVal.(uint16)

	moreFragments := (layers.IPFlags(frag) & 0x01) != 0
	offset := layers.IPFragOffset(frag)

	// Not fragmented: return as-is.
	if !moreFragments && offset == 0 {
		return pkt
	}

	// Extract key fields.
	srcVal, _ := ipLayer.Get("src")
	dstVal, _ := ipLayer.Get("dst")
	idVal, _ := ipLayer.Get("id")
	protoVal, _ := ipLayer.Get("proto")

	var key fragKey
	switch v := srcVal.(type) {
	case net.IP:
		copy(key.src[:], v.To4())
	case string:
		copy(key.src[:], net.ParseIP(v).To4())
	}
	switch v := dstVal.(type) {
	case net.IP:
		copy(key.dst[:], v.To4())
	case string:
		copy(key.dst[:], net.ParseIP(v).To4())
	}
	key.id, _ = idVal.(uint16)
	key.proto, _ = protoVal.(uint8)

	// Extract payload (bytes after IP header).
	verihlVal, _ := ipLayer.Get("verihl")
	verihl, _ := verihlVal.(uint8)
	headerLen := int(verihl&0x0F) * 4
	if headerLen < 20 {
		headerLen = 20
	}

	raw, err := pkt.Build()
	if err != nil || len(raw) < headerLen {
		return nil
	}
	payload := raw[headerLen:]

	f := fragment{
		offset: uint32(offset) * 8, // convert to byte offset
		length: uint32(len(payload)),
		data:   make([]byte, len(payload)),
		more:   moreFragments,
	}
	copy(f.data, payload)

	r.mu.Lock()
	defer r.mu.Unlock()

	group, exists := r.groups[key]
	if !exists {
		if len(r.groups) >= r.maxGroups {
			return nil // DoS protection: drop
		}
		group = &fragGroup{}
		r.groups[key] = group
	}

	group.frags = append(group.frags, f)
	group.totalBytes += uint32(f.length)
	group.lastSeen = time.Now()

	if !f.more {
		group.hasLast = true
		group.finalEnd = f.offset + f.length
	}

	// DoS protection: reject oversized reassembly.
	if group.totalBytes > maxReassembledSize || group.finalEnd > maxReassembledSize {
		delete(r.groups, key)
		return nil
	}

	// Check if reassembly is complete.
	if !group.hasLast {
		return nil
	}

	result := r.tryReassemble(key, group)
	if result == nil {
		return nil
	}

	delete(r.groups, key)
	return r.buildReassembled(key, result)
}

// tryReassemble checks if all byte ranges [0, finalEnd) are covered.
// Returns the reassembled payload or nil if gaps remain.
func (r *Reassembler) tryReassemble(key fragKey, group *fragGroup) []byte {
	totalLen := int(group.finalEnd)
	if totalLen == 0 || totalLen > maxReassembledSize {
		return nil
	}

	// Build a coverage bitmap to detect gaps and overlaps.
	covered := make([]bool, totalLen)
	buf := make([]byte, totalLen)

	for _, f := range group.frags {
		start := int(f.offset)
		end := start + int(f.length)
		if end > totalLen {
			end = totalLen
		}
		copy(buf[start:end], f.data[:end-start])
		for i := start; i < end; i++ {
			covered[i] = true
		}
	}

	// Check for gaps.
	for i := range totalLen {
		if !covered[i] {
			return nil
		}
	}

	return buf
}

// buildReassembled constructs an IP packet with the reassembled payload.
func (r *Reassembler) buildReassembled(key fragKey, payload []byte) *packet.Packet {
	startFn := func(b []byte) (string, error) {
		switch key.proto {
		case layers.IPProtoTCP:
			return "TCP", nil
		case layers.IPProtoUDP:
			return "UDP", nil
		case layers.IPProtoICMP:
			return "ICMP", nil
		default:
			return "Raw", nil
		}
	}

	upperPkt, err := packet.Dissect(payload, startFn)
	if err != nil {
		// Can't dissect upper layer — return IP + raw payload as single-layer packet.
		ip := layers.NewIP()
		ip.Set("src", net.IP(key.src[:]).To4())
		ip.Set("dst", net.IP(key.dst[:]).To4())
		ip.Set("id", key.id)
		ip.Set("proto", key.proto)
		ip.Set("frag", uint16(0))
		ip.Set("len", uint16(20+len(payload)))
		return packet.NewFrom(ip)
	}

	// Build a synthetic IP header for the reassembled packet.
	ip := layers.NewIP()
	ip.Set("src", net.IP(key.src[:]).To4())
	ip.Set("dst", net.IP(key.dst[:]).To4())
	ip.Set("id", key.id)
	ip.Set("proto", key.proto)
	ip.Set("frag", uint16(0))
	ip.Set("len", uint16(20+len(payload)))

	allLayers := append([]*packet.Layer{ip}, upperPkt.Layers()...)
	return packet.NewFrom(allLayers...)
}

// gc periodically removes expired fragment groups.
func (r *Reassembler) gc() {
	defer close(r.gcDone)
	ticker := time.NewTicker(r.timeout / 2)
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
	for key, group := range r.groups {
		if now.Sub(group.lastSeen) > r.timeout {
			delete(r.groups, key)
		}
	}
}

// Stats returns the current number of active fragment groups.
func (r *Reassembler) Stats() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.groups)
}
