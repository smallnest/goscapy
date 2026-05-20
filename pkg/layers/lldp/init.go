package lldp

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("LLDP", NewLLDP)
}
