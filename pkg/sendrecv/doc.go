// Package sendrecv provides Scapy-style raw socket send and receive operations.
//
// It bridges crafted packets (via packet.Build / packet.BuildFrom) to actual
// network interfaces using raw sockets, and parses captured bytes back into
// structured packets (via packet.Dissect).
//
// The public API mirrors Scapy's functions:
//
//   - Send    – L3 send (IP-level, OS handles L2 framing)
//   - Sendp   – L2 send (full Ethernet frame)
//   - Recv    – receive one packet from an interface
//   - SendRecv  – send at L3, then collect all responses until timeout
//   - SendRecv1 – like SendRecv but returns only the first response
//
// All functions require root privileges on most operating systems.
package sendrecv
