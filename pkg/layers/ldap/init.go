package ldap

import "github.com/smallnest/goscapy/pkg/packet"

func init() {
	packet.RegisterLayer("LDAP", NewLDAP)
}
