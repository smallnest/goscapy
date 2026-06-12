// Package sniff provides high-level packet capture (sniffing) with BPF filter support.
//
// The two primary APIs are:
//
//   - Sniff:     callback-based packet capture
//   - SniffChan: channel-based packet capture with a stop function
//
// Both accept a SniffConfig that specifies the interface, optional BPF filter,
// packet count limit, and total timeout.
//
// # BPF Filters
//
// Filters can be provided either as raw BPF instructions (zero dependencies)
// or as filter strings compiled at runtime via CompileFilter. CompileFilter
// first tries the built-in pure-Go BPF assembler (pkg/bpf), which covers the
// common filters (ip/ip6/arp, tcp/udp/icmp, host, port, src/dst, and/or/not)
// with no external dependencies, and only falls back to tcpdump (must be on
// PATH; may require root on macOS) for expressions outside that subset.
//
//	// Using a filter string (built-in assembler, no dependency for common cases):
//	Sniff(SniffConfig{Iface: "eth0", Filter: "tcp port 80"}, handler)
//
//	// Using pre-compiled instructions (no dependencies):
//	instructions := []sendrecv.BPFInstruction{
//	    {Code: 0x06, Jt: 0, Jf: 0, K: 0x0000FFFF}, // accept all
//	}
//	Sniff(SniffConfig{Iface: "eth0", Instructions: instructions}, handler)
//
// All functions require root privileges on most operating systems.
package sniff
