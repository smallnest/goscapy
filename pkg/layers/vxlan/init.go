package vxlan

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("VXLAN", NewVXLANLayer)
}