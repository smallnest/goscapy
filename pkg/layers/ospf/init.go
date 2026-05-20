package ospf

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("OSPF", NewOSPF)
}
