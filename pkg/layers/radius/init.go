package radius

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("RADIUS", NewRADIUS)
}
