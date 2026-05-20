package quic

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("QUIC", NewQUICLongHeader)
}
