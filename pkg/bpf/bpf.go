// Package bpf provides a pure-Go classic BPF (cBPF) assembler and interpreter.
//
// It compiles a useful subset of the libpcap/tcpdump filter language into the
// classic BPF instructions accepted by SO_ATTACH_FILTER (Linux) and BIOCSETF
// (BSD/macOS), removing goscapy's runtime dependency on an external tcpdump
// binary for the common filter cases. It also includes an interpreter (Run/
// Match) so the same programs can filter packets offline in pure Go.
//
// # Supported filter grammar (Ethernet / DLT_EN10MB link layer)
//
//	ip ip6 arp rarp            — EtherType match
//	tcp udp icmp               — IPv4 protocol match
//	host H | src host H | dst host H     — IPv4 address match
//	port P | src port P | dst port P     — TCP/UDP port match (IPv4)
//	tcp port P | udp port P              — protocol-restricted port match
//	( expr )                   — grouping
//	expr and expr | expr or expr | not expr   (also && || !)
//	implicit "and" between adjacent primitives
//
// Unsupported expressions return ErrUnsupported, letting callers fall back to
// an external compiler. The link layer is assumed to be Ethernet.
package bpf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// ErrUnsupported indicates the filter uses a construct this assembler does not
// implement. Callers may fall back to an external compiler (e.g. tcpdump).
var ErrUnsupported = errors.New("bpf: unsupported filter expression")

// acceptLen is the return value for matching packets: the number of bytes to
// accept. 262144 matches tcpdump's default and exceeds any real frame, so the
// whole packet is delivered.
const acceptLen = 262144

// Classic BPF opcodes (subset emitted/interpreted here).
const (
	opLDAbsW = 0x20 // A = u32 at [k]
	opLDAbsH = 0x28 // A = u16 at [k]
	opLDAbsB = 0x30 // A = u8  at [k]
	opLDIndH = 0x48 // A = u16 at [k+X]
	opLDIndB = 0x50 // A = u8  at [k+X]
	opLDXMsh = 0xb1 // X = 4*(pkt[k]&0xf)  (IP header length)
	opJEQK   = 0x15 // if A == k jt else jf
	opJSetK  = 0x45 // if A & k jt else jf
	opRetK   = 0x06 // return k
)

// Compile parses a filter expression and returns classic BPF instructions for
// an Ethernet link layer. It returns ErrUnsupported for grammar outside the
// documented subset.
func Compile(filter string) ([]sendrecv.BPFInstruction, error) {
	toks := tokenize(filter)
	if len(toks) == 0 {
		return nil, nil // empty filter = accept all
	}
	a := &assembler{labelPos: map[int]int{}}
	p := &parser{a: a, toks: toks}

	pred, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(toks) {
		return nil, fmt.Errorf("%w: unexpected token %q", ErrUnsupported, toks[p.pos])
	}

	tLabel := a.newLabel()
	fLabel := a.newLabel()
	pred(tLabel, fLabel)
	a.mark(tLabel)
	a.emit(opRetK, acceptLen)
	a.mark(fLabel)
	a.emit(opRetK, 0)

	return a.resolve()
}

// --- assembler ---

type asmInsn struct {
	code         uint16
	k            uint32
	jtLbl, jfLbl int // -1 when the literal jt/jf (0) should be used
}

type assembler struct {
	ins      []asmInsn
	labelPos map[int]int
	nextLbl  int
}

func (a *assembler) newLabel() int {
	l := a.nextLbl
	a.nextLbl++
	return l
}

func (a *assembler) mark(l int) { a.labelPos[l] = len(a.ins) }

func (a *assembler) emit(code uint16, k uint32) {
	a.ins = append(a.ins, asmInsn{code: code, k: k, jtLbl: -1, jfLbl: -1})
}

func (a *assembler) emitJump(code uint16, k uint32, jtLbl, jfLbl int) {
	a.ins = append(a.ins, asmInsn{code: code, k: k, jtLbl: jtLbl, jfLbl: jfLbl})
}

// matchOrFall emits a conditional jump that goes to tLbl on match and falls
// through to the next instruction otherwise.
func (a *assembler) matchOrFall(code uint16, k uint32, tLbl int) {
	cont := a.newLabel()
	a.emitJump(code, k, tLbl, cont)
	a.mark(cont)
}

// failOrFall emits a conditional jump that goes to fLbl on match and falls
// through otherwise (used for fragment/JSET-style guards).
func (a *assembler) failOrFall(code uint16, k uint32, fLbl int) {
	cont := a.newLabel()
	a.emitJump(code, k, fLbl, cont)
	a.mark(cont)
}

func (a *assembler) resolve() ([]sendrecv.BPFInstruction, error) {
	out := make([]sendrecv.BPFInstruction, len(a.ins))
	for i, in := range a.ins {
		bi := sendrecv.BPFInstruction{Code: in.code, K: in.k}
		if in.jtLbl >= 0 {
			off := a.labelPos[in.jtLbl] - (i + 1)
			if off < 0 || off > 255 {
				return nil, fmt.Errorf("bpf: jt offset %d out of range at insn %d", off, i)
			}
			bi.Jt = uint8(off)
		}
		if in.jfLbl >= 0 {
			off := a.labelPos[in.jfLbl] - (i + 1)
			if off < 0 || off > 255 {
				return nil, fmt.Errorf("bpf: jf offset %d out of range at insn %d", off, i)
			}
			bi.Jf = uint8(off)
		}
		out[i] = bi
	}
	return out, nil
}

// predicate emits instructions that jump to t on match and f on no-match.
type predicate func(t, f int)

// --- parser ---

type parser struct {
	a    *assembler
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) parseOr() (predicate, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" || p.peek() == "||" {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = p.a.orPred(left, right)
	}
	return left, nil
}

func (p *parser) parseAnd() (predicate, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == "and" || t == "&&" {
			p.next()
		} else if isPrimaryStart(t) {
			// implicit and between adjacent primitives
		} else {
			break
		}
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = p.a.andPred(left, right)
	}
	return left, nil
}

func (p *parser) parseNot() (predicate, error) {
	if p.peek() == "not" || p.peek() == "!" {
		p.next()
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return p.a.notPred(inner), nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (predicate, error) {
	if p.peek() == "(" {
		p.next()
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("%w: expected )", ErrUnsupported)
		}
		p.next()
		return e, nil
	}
	return p.parsePredicate()
}

// direction qualifiers for host/port predicates.
const (
	dirAny = iota
	dirSrc
	dirDst
)

func (p *parser) parsePredicate() (predicate, error) {
	dir := dirAny
	switch p.peek() {
	case "src":
		dir = dirSrc
		p.next()
	case "dst":
		dir = dirDst
		p.next()
	}

	tok := p.next()
	switch tok {
	case "host":
		ip := net.ParseIP(p.next()).To4()
		if ip == nil {
			return nil, fmt.Errorf("%w: host requires an IPv4 address", ErrUnsupported)
		}
		return p.a.hostPred(dir, ipToU32(ip)), nil
	case "port":
		n, err := parsePort(p.next())
		if err != nil {
			return nil, err
		}
		return p.a.portPred(dir, 0, n), nil
	case "ip", "ip6", "arp", "rarp":
		if dir != dirAny {
			return nil, fmt.Errorf("%w: direction qualifier on %q", ErrUnsupported, tok)
		}
		return p.a.etherTypePred(etherTypeFor(tok)), nil
	case "tcp", "udp", "icmp":
		proto := protoFor(tok)
		// "tcp port N" / "tcp src port N": protocol-restricted port match.
		if tok != "icmp" && (p.peek() == "port" || ((p.peek() == "src" || p.peek() == "dst") && p.peekAhead(1) == "port")) {
			d := dirAny
			if p.peek() == "src" {
				d = dirSrc
				p.next()
			} else if p.peek() == "dst" {
				d = dirDst
				p.next()
			}
			p.next() // consume "port"
			n, err := parsePort(p.next())
			if err != nil {
				return nil, err
			}
			return p.a.portPred(d, proto, n), nil
		}
		if dir != dirAny {
			return nil, fmt.Errorf("%w: direction qualifier on %q", ErrUnsupported, tok)
		}
		return p.a.ipProtoPred(proto), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, tok)
	}
}

func (p *parser) peekAhead(n int) string {
	if p.pos+n < len(p.toks) {
		return p.toks[p.pos+n]
	}
	return ""
}

// --- leaf predicate builders ---

// guardEtherType emits LDH[12]; if != etype goto f, else fall through.
func (a *assembler) guardEtherType(etype uint32, f int) {
	a.emit(opLDAbsH, 12)
	cont := a.newLabel()
	a.emitJump(opJEQK, etype, cont, f)
	a.mark(cont)
}

func (a *assembler) etherTypePred(etype uint32) predicate {
	return func(t, f int) {
		a.emit(opLDAbsH, 12)
		a.emitJump(opJEQK, etype, t, f)
	}
}

func (a *assembler) ipProtoPred(proto uint32) predicate {
	return func(t, f int) {
		a.guardEtherType(0x0800, f)
		a.emit(opLDAbsB, 23) // IPv4 protocol field
		a.emitJump(opJEQK, proto, t, f)
	}
}

func (a *assembler) hostPred(dir int, ip uint32) predicate {
	return func(t, f int) {
		a.guardEtherType(0x0800, f)
		switch dir {
		case dirSrc:
			a.emit(opLDAbsW, 26)
			a.emitJump(opJEQK, ip, t, f)
		case dirDst:
			a.emit(opLDAbsW, 30)
			a.emitJump(opJEQK, ip, t, f)
		default:
			a.emit(opLDAbsW, 26)
			a.matchOrFall(opJEQK, ip, t)
			a.emit(opLDAbsW, 30)
			a.emitJump(opJEQK, ip, t, f)
		}
	}
}

// portPred matches a TCP/UDP port. proto 0 means TCP or UDP; otherwise the
// specific IP protocol number. IPv4 only; fragmented packets do not match.
func (a *assembler) portPred(dir int, proto, port uint32) predicate {
	return func(t, f int) {
		a.guardEtherType(0x0800, f)
		a.emit(opLDAbsB, 23) // IPv4 protocol
		if proto == 0 {
			ok := a.newLabel()
			a.matchOrFall(opJEQK, 6, ok)  // TCP
			a.emitJump(opJEQK, 17, ok, f) // UDP, else fail
			a.mark(ok)
		} else {
			cont := a.newLabel()
			a.emitJump(opJEQK, proto, cont, f)
			a.mark(cont)
		}
		// Reject fragments (offset != 0): LDH[20]; JSET 0x1fff -> fail.
		a.emit(opLDAbsH, 20)
		a.failOrFall(opJSetK, 0x1fff, f)
		// X = IPv4 header length.
		a.emit(opLDXMsh, 14)
		switch dir {
		case dirSrc:
			a.emit(opLDIndH, 14)
			a.emitJump(opJEQK, port, t, f)
		case dirDst:
			a.emit(opLDIndH, 16)
			a.emitJump(opJEQK, port, t, f)
		default:
			a.emit(opLDIndH, 14)
			a.matchOrFall(opJEQK, port, t)
			a.emit(opLDIndH, 16)
			a.emitJump(opJEQK, port, t, f)
		}
	}
}

// --- combinators ---

func (a *assembler) andPred(p, q predicate) predicate {
	return func(t, f int) {
		mid := a.newLabel()
		p(mid, f)
		a.mark(mid)
		q(t, f)
	}
}

func (a *assembler) orPred(p, q predicate) predicate {
	return func(t, f int) {
		mid := a.newLabel()
		p(t, mid)
		a.mark(mid)
		q(t, f)
	}
}

func (a *assembler) notPred(p predicate) predicate {
	return func(t, f int) { p(f, t) }
}

// --- helpers ---

func tokenize(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	fields := strings.Fields(s)
	for i, f := range fields {
		// Lowercase keywords; IPs/numbers are unaffected by lowercasing.
		fields[i] = strings.ToLower(f)
	}
	return fields
}

func isPrimaryStart(t string) bool {
	switch t {
	case "src", "dst", "host", "port", "ip", "ip6", "arp", "rarp", "tcp", "udp", "icmp", "not", "!", "(":
		return true
	}
	return false
}

func etherTypeFor(tok string) uint32 {
	switch tok {
	case "ip":
		return 0x0800
	case "ip6":
		return 0x86dd
	case "arp":
		return 0x0806
	case "rarp":
		return 0x8035
	}
	return 0
}

func protoFor(tok string) uint32 {
	switch tok {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	}
	return 0
}

func parsePort(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid port %q", ErrUnsupported, s)
	}
	return uint32(n), nil
}

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
