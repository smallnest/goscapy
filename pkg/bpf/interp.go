package bpf

import (
	"encoding/binary"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Run executes a classic BPF program against a packet (starting at the link
// layer) and returns the accept length: the number of bytes the filter accepts
// (0 means reject). It implements the subset of cBPF opcodes emitted by
// Compile, which is sufficient to interpret the programs this package produces.
//
// Run lets the same compiled filter be applied in pure Go (offline analysis)
// without attaching it to a kernel socket.
func Run(prog []sendrecv.BPFInstruction, pkt []byte) uint32 {
	var a, x uint32
	pc := 0
	for pc < len(prog) {
		in := prog[pc]
		switch in.Code {
		case opLDAbsW:
			v, ok := load(pkt, int(in.K), 4)
			if !ok {
				return 0
			}
			a = v
		case opLDAbsH:
			v, ok := load(pkt, int(in.K), 2)
			if !ok {
				return 0
			}
			a = v
		case opLDAbsB:
			v, ok := load(pkt, int(in.K), 1)
			if !ok {
				return 0
			}
			a = v
		case opLDIndH:
			v, ok := load(pkt, int(in.K)+int(x), 2)
			if !ok {
				return 0
			}
			a = v
		case opLDIndB:
			v, ok := load(pkt, int(in.K)+int(x), 1)
			if !ok {
				return 0
			}
			a = v
		case opLDXMsh:
			idx := int(in.K)
			if idx >= len(pkt) {
				return 0
			}
			x = 4 * uint32(pkt[idx]&0x0f)
		case opJEQK:
			pc++
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
			continue
		case opJSetK:
			pc++
			if a&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
			continue
		case opRetK:
			return in.K
		default:
			// Unknown opcode: reject conservatively.
			return 0
		}
		pc++
	}
	return 0
}

// Match reports whether the program accepts the packet (accept length > 0).
func Match(prog []sendrecv.BPFInstruction, pkt []byte) bool {
	return Run(prog, pkt) > 0
}

// MatchFunc compiles filter once and returns a predicate over raw packets,
// suitable for offline filtering pipelines. It returns ErrUnsupported (via the
// error) if the filter cannot be compiled.
func MatchFunc(filter string) (func(pkt []byte) bool, error) {
	prog, err := Compile(filter)
	if err != nil {
		return nil, err
	}
	if len(prog) == 0 {
		return func([]byte) bool { return true }, nil
	}
	return func(pkt []byte) bool { return Match(prog, pkt) }, nil
}

func load(pkt []byte, off, n int) (uint32, bool) {
	if off < 0 || off+n > len(pkt) {
		return 0, false
	}
	switch n {
	case 1:
		return uint32(pkt[off]), true
	case 2:
		return uint32(binary.BigEndian.Uint16(pkt[off:])), true
	case 4:
		return binary.BigEndian.Uint32(pkt[off:]), true
	}
	return 0, false
}
