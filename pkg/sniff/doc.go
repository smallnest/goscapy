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
// or as filter strings compiled at runtime via CompileFilter (requires tcpdump
// on PATH; may require root on macOS).
//
//	// Using a filter string (requires tcpdump on PATH):
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
