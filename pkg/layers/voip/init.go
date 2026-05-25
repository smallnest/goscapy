package voip

import (
	"github.com/smallnest/goscapy/pkg/packet"
)

func init() {
	// Register layer factories.
	packet.RegisterLayer("RTP", NewRTP)
	packet.RegisterLayer("RTCP", NewRTCP)
	packet.RegisterLayer("SIP", NewSIP)

	// Heuristics: SIP on UDP/TCP port 5060.
	packet.RegisterHeuristic("UDP", "dport", uint16(5060), "SIP")
	packet.RegisterHeuristic("UDP", "sport", uint16(5060), "SIP")
	packet.RegisterHeuristic("TCP", "dport", uint16(5060), "SIP")
	packet.RegisterHeuristic("TCP", "sport", uint16(5060), "SIP")

	// RTP/RTCP: dynamic ports, usually detected by payload heuristics or
	// SDP negotiation. Register common range 5004 as a hint.
	packet.RegisterHeuristic("UDP", "dport", uint16(5004), "RTP")
	packet.RegisterHeuristic("UDP", "sport", uint16(5004), "RTP")
	packet.RegisterHeuristic("UDP", "dport", uint16(5005), "RTCP")
	packet.RegisterHeuristic("UDP", "sport", uint16(5005), "RTCP")

	// Header size funcs.
	packet.RegisterHeaderSizeFunc("RTP", func(layer *packet.Layer) int {
		return RTPHeaderLen // minimum; actual size varies with CSRC + extension
	})
	packet.RegisterHeaderSizeFunc("RTCP", func(layer *packet.Layer) int {
		return RTCPHeaderLen
	})
}
