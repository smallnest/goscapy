package bpf

import (
	xbpf "golang.org/x/net/bpf"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Run executes a classic BPF program (in goscapy's sendrecv.BPFInstruction
// form) against a packet starting at the link layer, returning the accept
// length: the number of bytes the filter accepts (0 means reject). Execution
// is delegated to golang.org/x/net/bpf's virtual machine.
//
// Run lets the same compiled filter be applied in pure Go (offline analysis)
// without attaching it to a kernel socket. A program that fails to load
// returns 0 (reject).
func Run(prog []sendrecv.BPFInstruction, pkt []byte) uint32 {
	vm, err := newVM(prog)
	if err != nil {
		return 0
	}
	n, err := vm.Run(pkt)
	if err != nil || n < 0 {
		return 0
	}
	return uint32(n)
}

// Match reports whether the program accepts the packet (accept length > 0).
func Match(prog []sendrecv.BPFInstruction, pkt []byte) bool {
	return Run(prog, pkt) > 0
}

// MatchFunc compiles filter once and returns a predicate over raw packets,
// suitable for offline filtering pipelines. It returns ErrUnsupported (via the
// error) if the filter cannot be compiled. The returned predicate reuses a
// single VM instance and is safe for sequential use.
func MatchFunc(filter string) (func(pkt []byte) bool, error) {
	insts, err := CompileInstructions(filter)
	if err != nil {
		return nil, err
	}
	if len(insts) == 0 {
		return func([]byte) bool { return true }, nil
	}
	vm, err := xbpf.NewVM(insts)
	if err != nil {
		return nil, err
	}
	return func(pkt []byte) bool {
		n, err := vm.Run(pkt)
		return err == nil && n > 0
	}, nil
}

// newVM builds an x/net/bpf VM from raw goscapy instructions by round-tripping
// them through RawInstruction.Disassemble. Since BPFInstruction is an alias for
// xbpf.RawInstruction, each entry is used directly.
func newVM(prog []sendrecv.BPFInstruction) (*xbpf.VM, error) {
	insts := make([]xbpf.Instruction, len(prog))
	for i, in := range prog {
		insts[i] = in.Disassemble()
	}
	return xbpf.NewVM(insts)
}
