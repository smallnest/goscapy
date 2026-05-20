package erspan

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("ERSPAN", NewERSPAN)
}
