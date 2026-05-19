package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// DHCP message types (RFC 2131).
const (
	DHCPDISCOVER uint8 = 1
	DHCPOFFER    uint8 = 2
	DHCPREQUEST  uint8 = 3
	DHCPDECLINE  uint8 = 4
	DHCPACK      uint8 = 5
	DHCPNAK      uint8 = 6
	DHCPRELEASE  uint8 = 7
	DHCPINFORM   uint8 = 8
)

// DHCP option types (RFC 2132).
const (
	OptSubnetMask  uint8 = 1
	OptRouter      uint8 = 3
	OptDNS         uint8 = 6
	OptHostname    uint8 = 12
	OptDomain      uint8 = 15
	OptRequestedIP uint8 = 50
	OptLeaseTime   uint8 = 51
	OptMessageType uint8 = 53
	OptServerID    uint8 = 54
	OptParamList   uint8 = 55
	OptRenewal     uint8 = 58
	OptRebinding   uint8 = 59
	OptEnd         uint8 = 255
)

// BOOTP operation codes.
const (
	BOOTREQUEST uint8 = 1
	BOOTREPLY   uint8 = 2
)

// DHCP magic cookie (RFC 2131, section 3).
const MagicCookie uint32 = 0x63825363

// NewDHCP creates a DHCP message layer with default BOOTREQUEST header.
// Defaults: op=BOOTREQUEST, htype=1 (Ethernet), hlen=6, hops=0,
// xid=0, secs=0, flags=0, all IPs=0.0.0.0, chaddr=zeros, sname=zeros,
// file=zeros, cookie=MagicCookie, options=empty.
func NewDHCP() *packet.Layer {
	return packet.NewLayer("DHCP", []fields.Field{
		fields.NewByteField("op", BOOTREQUEST),
		fields.NewByteField("htype", 1),
		fields.NewByteField("hlen", 6),
		fields.NewByteField("hops", 0),
		fields.NewIntField("xid", 0),
		fields.NewShortField("secs", 0),
		fields.NewShortField("flags", 0),
		fields.NewIPField("ciaddr", net.IPv4zero),
		fields.NewIPField("yiaddr", net.IPv4zero),
		fields.NewIPField("siaddr", net.IPv4zero),
		fields.NewIPField("giaddr", net.IPv4zero),
		fields.NewStrFixedField("chaddr", 16, make([]byte, 16)),
		fields.NewStrFixedField("sname", 64, make([]byte, 64)),
		fields.NewStrFixedField("file", 128, make([]byte, 128)),
		fields.NewIntField("cookie", MagicCookie),
		fields.NewStrField("options", ""),
	})
}

// ---- Option parsing and building ----

// ParseDHCPOptions parses TLV-encoded DHCP options from raw bytes.
// The input should be the options data after the magic cookie.
// The DHCP End marker (type 255) is handled as a single-byte terminator
// per RFC 2132, which differs from the standard TLV type-length-value encoding.
func ParseDHCPOptions(data []byte) ([]fields.TLVOption, error) {
	// Strip trailing End marker (255) since it has no length byte in DHCP.
	if len(data) > 0 && data[len(data)-1] == OptEnd {
		data = data[:len(data)-1]
	}
	return fields.ParseTLV(data)
}

// BuildDHCPOptions serializes DHCP options to wire format.
// An End option (type=255) is automatically appended as a single byte
// per RFC 2132 (no length byte follows the End marker).
func BuildDHCPOptions(opts []fields.TLVOption) []byte {
	// Filter out any End(255) option — we append it as a raw byte below.
	filtered := make([]fields.TLVOption, 0, len(opts))
	for _, o := range opts {
		if o.Type != OptEnd {
			filtered = append(filtered, o)
		}
	}
	result := fields.BuildTLV(filtered)
	return append(result, OptEnd)
}

// GetDHCPOption returns the first option matching the given type, or nil.
func GetDHCPOption(opts []fields.TLVOption, typ uint8) *fields.TLVOption {
	return fields.GetTLV(opts, typ)
}

// GetMessageType extracts the DHCP Message Type (option 53) value.
// Returns 0 if not present.
func GetMessageType(opts []fields.TLVOption) uint8 {
	o := GetDHCPOption(opts, OptMessageType)
	if o == nil || len(o.Value) == 0 {
		return 0
	}
	return o.Value[0]
}

// MessageTypeString returns the human-readable name for a DHCP message type.
func MessageTypeString(mt uint8) string {
	switch mt {
	case DHCPDISCOVER:
		return "DHCPDISCOVER"
	case DHCPOFFER:
		return "DHCPOFFER"
	case DHCPREQUEST:
		return "DHCPREQUEST"
	case DHCPDECLINE:
		return "DHCPDECLINE"
	case DHCPACK:
		return "DHCPACK"
	case DHCPNAK:
		return "DHCPNAK"
	case DHCPRELEASE:
		return "DHCPRELEASE"
	case DHCPINFORM:
		return "DHCPINFORM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", mt)
	}
}

// ---- Convenience option constructors ----

// NewMessageTypeOption creates a DHCP Message Type option (53).
func NewMessageTypeOption(mt uint8) fields.TLVOption {
	return fields.TLVOption{Type: OptMessageType, Length: 1, Value: []byte{mt}}
}

// NewSubnetMaskOption creates a Subnet Mask option (1).
func NewSubnetMaskOption(mask string) fields.TLVOption {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		ip = net.IPv4zero
	}
	return fields.TLVOption{Type: OptSubnetMask, Length: 4, Value: []byte(ip)}
}

// NewRouterOption creates a Router option (3) with one or more router IPs.
func NewRouterOption(routers []string) fields.TLVOption {
	var val []byte
	for _, r := range routers {
		ip := net.ParseIP(r).To4()
		if ip != nil {
			val = append(val, []byte(ip)...)
		}
	}
	if len(val) == 0 {
		val = make([]byte, 4)
	}
	return fields.TLVOption{Type: OptRouter, Length: uint8(len(val)), Value: val}
}

// NewDNSOption creates a Domain Name Server option (6).
func NewDNSOption(servers []string) fields.TLVOption {
	var val []byte
	for _, s := range servers {
		ip := net.ParseIP(s).To4()
		if ip != nil {
			val = append(val, []byte(ip)...)
		}
	}
	if len(val) == 0 {
		val = make([]byte, 4)
	}
	return fields.TLVOption{Type: OptDNS, Length: uint8(len(val)), Value: val}
}

// NewHostnameOption creates a Host Name option (12).
func NewHostnameOption(name string) fields.TLVOption {
	return fields.TLVOption{Type: OptHostname, Length: uint8(len(name)), Value: []byte(name)}
}

// NewDomainOption creates a Domain Name option (15).
func NewDomainOption(domain string) fields.TLVOption {
	return fields.TLVOption{Type: OptDomain, Length: uint8(len(domain)), Value: []byte(domain)}
}

// NewRequestedIPOption creates a Requested IP Address option (50).
func NewRequestedIPOption(ip string) fields.TLVOption {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		parsed = net.IPv4zero
	}
	return fields.TLVOption{Type: OptRequestedIP, Length: 4, Value: []byte(parsed)}
}

// NewLeaseTimeOption creates an IP Address Lease Time option (51).
func NewLeaseTimeOption(seconds uint32) fields.TLVOption {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, seconds)
	return fields.TLVOption{Type: OptLeaseTime, Length: 4, Value: val}
}

// NewServerIDOption creates a Server Identifier option (54).
func NewServerIDOption(ip string) fields.TLVOption {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		parsed = net.IPv4zero
	}
	return fields.TLVOption{Type: OptServerID, Length: 4, Value: []byte(parsed)}
}

// NewParamListOption creates a Parameter Request List option (55).
func NewParamListOption(params []uint8) fields.TLVOption {
	return fields.TLVOption{Type: OptParamList, Length: uint8(len(params)), Value: params}
}

// NewRenewalOption creates a Renewal Time Value option (58).
func NewRenewalOption(seconds uint32) fields.TLVOption {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, seconds)
	return fields.TLVOption{Type: OptRenewal, Length: 4, Value: val}
}

// NewRebindingOption creates a Rebinding Time Value option (59).
func NewRebindingOption(seconds uint32) fields.TLVOption {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, seconds)
	return fields.TLVOption{Type: OptRebinding, Length: 4, Value: val}
}

// EndOption creates an End option (255).
func EndOption() fields.TLVOption {
	return fields.TLVOption{Type: OptEnd, Length: 0, Value: nil}
}