package dns

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("DNS", NewDNS)
}