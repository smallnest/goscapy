//go:build darwin

package sendrecv

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// openFilteredReceiver opens a BPF receiver with an optional kernel-level BPF filter.
func openFilteredReceiver(iface string, instructions []BPFInstruction) (Receiver, error) {
	fd, bufSize, err := openBPFDevice()
	if err != nil {
		return nil, err
	}

	if err := bindBPF(fd, iface); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := setImmediate(fd); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Apply BPF filter before enabling promiscuous mode.
	if len(instructions) > 0 {
		if err := applyBpfFilter(fd, instructions); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("sendrecv: apply BPF filter: %w", err)
		}
	}

	if err := setPromisc(fd); err != nil {
		_ = err // non-fatal
	}

	flushBPF(fd)

	// Get Data Link Type (DLT) — needed by Recv to determine packet format.
	var dlt uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x4004426A, uintptr(unsafe.Pointer(&dlt))); errno != 0 {
		dlt = 1 // Default to DLT_EN10MB (Ethernet)
	}

	return &bpfReceiver{
		fd:    fd,
		buf:   make([]byte, bufSize),
		iface: iface,
		dlt:   dlt,
	}, nil
}

// applyBpfFilter attaches a classic BPF program to the BPF device via BIOCSETF.
func applyBpfFilter(fd int, instructions []BPFInstruction) error {
	insns := make([]syscall.BpfInsn, len(instructions))
	for i, inst := range instructions {
		insns[i] = syscall.BpfInsn{
			Code: inst.Code,
			Jt:   inst.Jt,
			Jf:   inst.Jf,
			K:    inst.K,
		}
	}

	prog := syscall.BpfProgram{
		Len:   uint32(len(insns)),
		Insns: &insns[0],
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.BIOCSETF,
		uintptr(unsafe.Pointer(&prog)),
	)
	runtime.KeepAlive(insns)

	if errno != 0 {
		return fmt.Errorf("BIOCSETF: %v", errno)
	}
	return nil
}
