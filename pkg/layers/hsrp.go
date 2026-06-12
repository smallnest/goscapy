package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// HSRPPort is the UDP port used by HSRP (Cisco Hot Standby Router Protocol).
const HSRPPort uint16 = 1985

// HSRP operation codes (RFC 2281).
const (
	HSRPOpHello  uint8 = 0
	HSRPOpCoup   uint8 = 1
	HSRPOpResign uint8 = 2
)

// HSRP states (RFC 2281).
const (
	HSRPStateInitial uint8 = 0
	HSRPStateLearn   uint8 = 1
	HSRPStateListen  uint8 = 2
	HSRPStateSpeak   uint8 = 4
	HSRPStateStandby uint8 = 8
	HSRPStateActive  uint8 = 16
)

// NewHSRP creates an HSRPv1 message (RFC 2281, carried over UDP port 1985).
// Wire format (20 bytes):
//
//	version(1) | opcode(1) | state(1) | hellotime(1) | holdtime(1) |
//	priority(1) | group(1) | reserved(1) | auth data(8) | virtual IP(4)
//
// The 8-byte auth data defaults to the conventional "cisco" padding.
func NewHSRP() *packet.Layer {
	return packet.NewLayer("HSRP", []fields.Field{
		fields.NewByteField("version", 0),
		fields.NewByteField("opcode", HSRPOpHello),
		fields.NewByteField("state", HSRPStateActive),
		fields.NewByteField("hellotime", 3),
		fields.NewByteField("holdtime", 10),
		fields.NewByteField("priority", 100),
		fields.NewByteField("group", 0),
		fields.NewByteField("reserved", 0),
		fields.NewStrFixedField("auth", 8, []byte("cisco\x00\x00\x00")),
		fields.NewIPField("virtualip", nil),
	})
}

// NewHSRPWith creates an HSRP Hello for the given group, priority, and virtual IP.
func NewHSRPWith(group, priority uint8, virtualIP string) *packet.Layer {
	l := NewHSRP()
	_ = l.Set("group", group)
	_ = l.Set("priority", priority)
	if virtualIP != "" {
		_ = l.Set("virtualip", virtualIP)
	} else {
		_ = l.Set("virtualip", "0.0.0.0")
	}
	return l
}
