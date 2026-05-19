package dhcp

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("DHCP", NewDHCP)
}