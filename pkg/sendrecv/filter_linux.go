//go:build linux

package sendrecv

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// openFilteredReceiver opens an AF_PACKET receiver with an optional kernel-level BPF filter.
func openFilteredReceiver(iface string, instructions []BPFInstruction) (Receiver, error) {
	ifaceObj, err := lookupInterface(iface)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(_ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("sendrecv: AF_PACKET socket: %w", err)
	}

	// Apply BPF filter before binding.
	if len(instructions) > 0 {
		if err := applyPacketFilter(fd, instructions); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("sendrecv: apply BPF filter: %w", err)
		}
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(_ETH_P_ALL),
		Ifindex:  ifaceObj.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("sendrecv: AF_PACKET bind: %w", err)
	}

	return &afPacketReceiver{fd: fd, iface: iface}, nil
}

// applyPacketFilter attaches a classic BPF program to the AF_PACKET socket
// via SO_ATTACH_FILTER.
func applyPacketFilter(fd int, instructions []BPFInstruction) error {
	filters := make([]syscall.SockFilter, len(instructions))
	for i, inst := range instructions {
		filters[i] = syscall.SockFilter{
			Code: inst.Code,
			Jt:   inst.Jt,
			Jf:   inst.Jf,
			K:    inst.K,
		}
	}

	prog := syscall.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		syscall.SOL_SOCKET,
		syscall.SO_ATTACH_FILTER,
		uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Sizeof(prog)),
		0,
	)
	runtime.KeepAlive(filters)

	if errno != 0 {
		return fmt.Errorf("SO_ATTACH_FILTER: %v", errno)
	}
	return nil
}
