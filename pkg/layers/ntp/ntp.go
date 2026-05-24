package ntp

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// NTP mode constants.
const (
	ModeReserved     uint8 = 0
	ModeSymActive    uint8 = 1
	ModeSymPassive   uint8 = 2
	ModeClient       uint8 = 3
	ModeServer       uint8 = 4
	ModeBroadcast    uint8 = 5
	ModeControl      uint8 = 6
	ModePrivate      uint8 = 7
)

// NTP leap indicator constants.
const (
	LINoWarning    uint8 = 0
	LI61Sec        uint8 = 1
	LI59Sec        uint8 = 2
	LIUnknown      uint8 = 3
)

// NTPEpochOffset is the difference between Unix epoch (1970) and NTP epoch (1900) in seconds.
const NTPEpochOffset = 2208988800

// NewNTP creates an NTP layer with sensible defaults.
// Default: LI=0, VN=4, Mode=3 (client), Stratum=0, Poll=4, Precision=0.
func NewNTP() *packet.Layer {
	return packet.NewLayer("NTP", []fields.Field{
		fields.NewByteField("lvm", 0x23),              // LI=0, VN=4, Mode=3 (client)
		fields.NewByteField("stratum", 0),              // unspecified
		fields.NewByteField("poll", 4),                 // log2 seconds (signed, stored as uint8)
		fields.NewByteField("precision", 0),            // log2 seconds (signed, stored as uint8)
		fields.NewIntField("rootdelay", 0),             // 16.16 fixed-point
		fields.NewIntField("rootdispersion", 0),        // 16.16 fixed-point
		fields.NewIntField("refid", 0),                 // reference identifier
		fields.NewLongField("reftimestamp", 0),         // reference timestamp (NTP 64-bit)
		fields.NewLongField("origtimestamp", 0),        // originate timestamp
		fields.NewLongField("recvtimestamp", 0),        // receive timestamp
		fields.NewLongField("xtimestamp", 0),           // transmit timestamp
	})
}

// LI extracts the leap indicator (2 bits) from the lvm byte.
func LI(lvm uint8) uint8 { return lvm >> 6 }

// VN extracts the version number (3 bits) from the lvm byte.
func VN(lvm uint8) uint8 { return (lvm >> 3) & 0x07 }

// Mode extracts the mode (3 bits) from the lvm byte.
func Mode(lvm uint8) uint8 { return lvm & 0x07 }

// SetLVM packs LI, VN, Mode into a single byte.
func SetLVM(li, vn, mode uint8) uint8 {
	return (li&0x03)<<6 | (vn&0x07)<<3 | (mode & 0x07)
}

func init() {
	packet.RegisterLayer("NTP", NewNTP)
}
