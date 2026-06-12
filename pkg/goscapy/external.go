package goscapy

import (
	"github.com/smallnest/goscapy/pkg/external"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/pcap"
)

// ToJSON returns the packet as a JSON document describing every layer and
// field. It is a convenience wrapper over packet.Packet.ToJSON.
func ToJSON(pkt *packet.Packet) ([]byte, error) { return pkt.ToJSON() }

// Wireshark writes the packets to a temporary Ethernet-link pcap and opens it
// in Wireshark (non-blocking), mirroring Scapy's wireshark(pkt). It returns the
// temp file path and requires the "wireshark" binary on PATH.
func Wireshark(pkts ...*packet.Packet) (string, error) {
	return external.Wireshark(pcap.LinkTypeEthernet, pkts...)
}

// Tcpdump runs tcpdump over the packets (Ethernet link) and returns its output,
// mirroring Scapy's tcpdump(pkt). Pass extra args like "-n" or "-vv".
func Tcpdump(args []string, pkts ...*packet.Packet) (string, error) {
	return external.Tcpdump(pcap.LinkTypeEthernet, args, pkts...)
}
