// Package bpf provides a pure-Go classic BPF (cBPF) filter compiler.
//
// It compiles a useful subset of the libpcap/tcpdump filter language into BPF
// programs, removing goscapy's runtime dependency on an external tcpdump binary
// for the common filter cases. Assembly and execution are delegated to
// golang.org/x/net/bpf — an officially maintained implementation — while this
// package supplies the filter-string parser that x/net/bpf does not provide.
//
// Compile returns instructions in goscapy's sendrecv.BPFInstruction form
// (suitable for SO_ATTACH_FILTER / BIOCSETF), and Match/MatchFunc run the same
// program in pure Go via x/net/bpf's virtual machine for offline filtering.
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

	xbpf "golang.org/x/net/bpf"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// ErrUnsupported indicates the filter uses a construct this assembler does not
// implement. Callers may fall back to an external compiler (e.g. tcpdump).
var ErrUnsupported = errors.New("bpf: unsupported filter expression")

// acceptLen is the verdict value for matching packets: the number of bytes to
// accept. 262144 matches tcpdump's default and exceeds any real frame, so the
// whole packet is delivered.
const acceptLen = 262144

// CompileInstructions parses a filter expression and returns x/net/bpf typed
// instructions for an Ethernet link layer. It returns ErrUnsupported for
// grammar outside the documented subset. This is the building block used by
// Compile (which assembles to raw form) and MatchFunc (which builds a VM).
func CompileInstructions(filter string) ([]xbpf.Instruction, error) {
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
	a.emitRet(acceptLen)
	a.mark(fLabel)
	a.emitRet(0)

	return a.resolve()
}

// Compile parses a filter expression and returns classic BPF instructions in
// goscapy's sendrecv.BPFInstruction form (an alias for xbpf.RawInstruction),
// suitable for kernel attachment. It returns ErrUnsupported for grammar
// outside the documented subset.
func Compile(filter string) ([]sendrecv.BPFInstruction, error) {
	insts, err := CompileInstructions(filter)
	if err != nil {
		return nil, err
	}
	if len(insts) == 0 {
		return nil, nil
	}
	raw, err := xbpf.Assemble(insts)
	if err != nil {
		return nil, fmt.Errorf("bpf: assemble: %w", err)
	}
	return raw, nil
}

// --- assembler ---
//
// The assembler records typed x/net/bpf instructions, but defers jump targets
// to labels so forward skip counts can be computed once all instructions are
// emitted. Only forward jumps are produced (classic BPF forbids back-edges).

type asmInsn struct {
	// For non-jump instructions, inst holds the fully-formed instruction.
	inst xbpf.Instruction
	// For jumps, isJump is true and the fields below describe a JumpIf whose
	// SkipTrue/SkipFalse are resolved from jtLbl/jfLbl at resolve() time.
	isJump bool
	cond   xbpf.JumpTest
	val    uint32
	jtLbl  int // label to jump to when the condition is true
	jfLbl  int // label to jump to when the condition is false
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

// emitLoadAbs loads size bytes at a fixed packet offset into register A.
func (a *assembler) emitLoadAbs(off uint32, size int) {
	a.ins = append(a.ins, asmInsn{inst: xbpf.LoadAbsolute{Off: off, Size: size}})
}

// emitLoadInd loads size bytes at packet[X+off] into register A.
func (a *assembler) emitLoadInd(off uint32, size int) {
	a.ins = append(a.ins, asmInsn{inst: xbpf.LoadIndirect{Off: off, Size: size}})
}

// emitLoadMemShift sets X = 4*(packet[off]&0xf) (IPv4 header length).
func (a *assembler) emitLoadMemShift(off uint32) {
	a.ins = append(a.ins, asmInsn{inst: xbpf.LoadMemShift{Off: off}})
}

// emitRet appends a constant return (verdict) instruction.
func (a *assembler) emitRet(val uint32) {
	a.ins = append(a.ins, asmInsn{inst: xbpf.RetConstant{Val: val}})
}

// emitJump appends a conditional jump to jtLbl on match, jfLbl otherwise.
func (a *assembler) emitJump(cond xbpf.JumpTest, val uint32, jtLbl, jfLbl int) {
	a.ins = append(a.ins, asmInsn{isJump: true, cond: cond, val: val, jtLbl: jtLbl, jfLbl: jfLbl})
}

// matchOrFall emits a conditional jump that goes to tLbl on (A == val) and
// falls through to the next instruction otherwise.
func (a *assembler) matchOrFall(val uint32, tLbl int) {
	cont := a.newLabel()
	a.emitJump(xbpf.JumpEqual, val, tLbl, cont)
	a.mark(cont)
}

// failOrFall emits a conditional jump that goes to fLbl when (A & val) != 0 and
// falls through otherwise (used for fragment guards).
func (a *assembler) failOrFall(val uint32, fLbl int) {
	cont := a.newLabel()
	a.emitJump(xbpf.JumpBitsSet, val, fLbl, cont)
	a.mark(cont)
}

func (a *assembler) resolve() ([]xbpf.Instruction, error) {
	out := make([]xbpf.Instruction, len(a.ins))
	for i, in := range a.ins {
		if !in.isJump {
			out[i] = in.inst
			continue
		}
		st := a.labelPos[in.jtLbl] - (i + 1)
		sf := a.labelPos[in.jfLbl] - (i + 1)
		if st < 0 || st > 255 || sf < 0 || sf > 255 {
			return nil, fmt.Errorf("bpf: jump skip out of range at insn %d (st=%d sf=%d)", i, st, sf)
		}
		out[i] = xbpf.JumpIf{
			Cond:      in.cond,
			Val:       in.val,
			SkipTrue:  uint8(st),
			SkipFalse: uint8(sf),
		}
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

// guardEtherType emits LDH[12]; if A != etype goto f, else fall through.
func (a *assembler) guardEtherType(etype uint32, f int) {
	a.emitLoadAbs(12, 2)
	cont := a.newLabel()
	a.emitJump(xbpf.JumpEqual, etype, cont, f)
	a.mark(cont)
}

func (a *assembler) etherTypePred(etype uint32) predicate {
	return func(t, f int) {
		a.emitLoadAbs(12, 2)
		a.emitJump(xbpf.JumpEqual, etype, t, f)
	}
}

func (a *assembler) ipProtoPred(proto uint32) predicate {
	return func(t, f int) {
		a.guardEtherType(0x0800, f)
		a.emitLoadAbs(23, 1) // IPv4 protocol field
		a.emitJump(xbpf.JumpEqual, proto, t, f)
	}
}

func (a *assembler) hostPred(dir int, ip uint32) predicate {
	return func(t, f int) {
		a.guardEtherType(0x0800, f)
		switch dir {
		case dirSrc:
			a.emitLoadAbs(26, 4)
			a.emitJump(xbpf.JumpEqual, ip, t, f)
		case dirDst:
			a.emitLoadAbs(30, 4)
			a.emitJump(xbpf.JumpEqual, ip, t, f)
		default:
			a.emitLoadAbs(26, 4)
			a.matchOrFall(ip, t)
			a.emitLoadAbs(30, 4)
			a.emitJump(xbpf.JumpEqual, ip, t, f)
		}
	}
}

// portPred matches a TCP/UDP port. proto 0 means TCP or UDP; otherwise the
// specific IP protocol number. IPv4 only; fragmented packets do not match.
func (a *assembler) portPred(dir int, proto, port uint32) predicate {
	return func(t, f int) {
		a.guardEtherType(0x0800, f)
		a.emitLoadAbs(23, 1) // IPv4 protocol
		if proto == 0 {
			ok := a.newLabel()
			a.matchOrFall(6, ok)                  // TCP
			a.emitJump(xbpf.JumpEqual, 17, ok, f) // UDP, else fail
			a.mark(ok)
		} else {
			cont := a.newLabel()
			a.emitJump(xbpf.JumpEqual, proto, cont, f)
			a.mark(cont)
		}
		// Reject fragments (offset != 0): LDH[20]; if A & 0x1fff goto fail.
		a.emitLoadAbs(20, 2)
		a.failOrFall(0x1fff, f)
		// X = IPv4 header length.
		a.emitLoadMemShift(14)
		switch dir {
		case dirSrc:
			a.emitLoadInd(14, 2)
			a.emitJump(xbpf.JumpEqual, port, t, f)
		case dirDst:
			a.emitLoadInd(16, 2)
			a.emitJump(xbpf.JumpEqual, port, t, f)
		default:
			a.emitLoadInd(14, 2)
			a.matchOrFall(port, t)
			a.emitLoadInd(16, 2)
			a.emitJump(xbpf.JumpEqual, port, t, f)
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
