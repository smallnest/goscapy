package bgp

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("BGP", NewBGP)
}
