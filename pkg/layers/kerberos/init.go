package kerberos

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("Kerberos", NewKerberos)
}
