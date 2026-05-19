package gre

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("GRE", NewGRELayer)
	packet.RegisterKeyField("GRE", "proto")
	packet.RegisterNextLayer("GRE", uint64(0x0800), "IP")
	packet.RegisterNextLayer("GRE", uint64(0x6558), "Ethernet")
}