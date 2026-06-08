package packet

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/smallnest/goscapy/pkg/fields"
)

// Show returns a formatted multi-line display of all layers and their field
// values, similar to Scapy's pkt.show(). Each layer is printed with its
// protocol name as a header, followed by each field's name, type, and
// current value (with hex representation for numeric fields).
func (p *Packet) Show() string {
	if len(p.layers) == 0 {
		return ""
	}
	var b strings.Builder
	for i, l := range p.layers {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("###[ ")
		b.WriteString(l.Proto())
		b.WriteString(" ]###\n")
		l.writeFields(&b, "  ")
	}
	return b.String()
}

// Summary returns a one-line summary of the packet in the style of
// Scapy's pkt.summary(). For example:
//
//	"IP 192.168.1.1 > 10.0.0.1 TCP S 80 > 12345"
func (p *Packet) Summary() string {
	if len(p.layers) == 0 {
		return ""
	}

	var parts []string
	for _, l := range p.layers {
		s := layerSummary(l)
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " / ")
}

// ListLayers returns the names of all registered layer protocols,
// sorted alphabetically.
func ListLayers() []string {
	names := make([]string, 0, len(dissectRegistry.factories))
	for name := range dissectRegistry.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Describe returns a formatted description of the layer's fields, types,
// and default values, similar to Scapy's ls(proto).
func (l *Layer) Describe() string {
	var b strings.Builder
	b.WriteString(l.Proto())
	b.WriteString(":\n")
	l.writeFields(&b, "  ")
	return b.String()
}

// String returns a detailed one-line representation of the layer.
func (l *Layer) String() string {
	var parts []string
	for _, f := range l.fields {
		cf, isCond := f.(*fields.ConditionalField)
		name := f.Name()
		if isCond {
			if !cf.Active(l.values) {
				continue
			}
		}
		val, exists := l.values[name]
		if !exists {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", name, formatValue(val, f)))
	}
	return fmt.Sprintf("<%s %s>", l.Proto(), strings.Join(parts, " "))
}

// writeFields writes field name/type/value lines to the builder with the given indent.
func (l *Layer) writeFields(b *strings.Builder, indent string) {
	for _, f := range l.fields {
		cf, isCond := f.(*fields.ConditionalField)
		name := f.Name()
		if isCond {
			if !cf.Active(l.values) {
				continue
			}
		}
		val, exists := l.values[name]
		if !exists {
			continue
		}

		typeName := fieldType(f)
		display := formatValue(val, f)

		b.WriteString(indent)
		b.WriteString(name)
		b.WriteString(" = ")
		b.WriteString(display)
		if typeName != "" {
			b.WriteString("  (")
			b.WriteString(typeName)
			b.WriteByte(')')
		}
		b.WriteByte('\n')
	}
}

// layerSummary returns a one-line summary for a single layer.
func layerSummary(l *Layer) string {
	proto := l.Proto()
	switch proto {
	case "Ethernet":
		src, _ := l.Get("src")
		dst, _ := l.Get("dst")
		return fmt.Sprintf("Ether %s > %s", formatAddr(src), formatAddr(dst))
	case "IP":
		src, _ := l.Get("src")
		dst, _ := l.Get("dst")
		return fmt.Sprintf("IP %s > %s", formatAddr(src), formatAddr(dst))
	case "IPv6":
		src, _ := l.Get("src")
		dst, _ := l.Get("dst")
		return fmt.Sprintf("IPv6 %s > %s", formatAddr(src), formatAddr(dst))
	case "TCP":
		sport, _ := l.Get("sport")
		dport, _ := l.Get("dport")
		flags, _ := l.Get("flags")
		flagStr := tcpFlagStr(flags)
		return fmt.Sprintf("TCP %s %v > %v", flagStr, sport, dport)
	case "UDP":
		sport, _ := l.Get("sport")
		dport, _ := l.Get("dport")
		return fmt.Sprintf("UDP %v > %v", sport, dport)
	case "ICMP":
		typ, _ := l.Get("type")
		code, _ := l.Get("code")
		return fmt.Sprintf("ICMP type=%v code=%v", typ, code)
	case "ARP":
		op, _ := l.Get("op")
		psrc, _ := l.Get("psrc")
		pdst, _ := l.Get("pdst")
		return fmt.Sprintf("ARP op=%v %s > %s", op, formatAddr(psrc), formatAddr(pdst))
	case "DNS":
		qr, _ := l.Get("qr")
		if qr != nil {
			if v, ok := qr.(uint8); ok && v == 0 {
				return "DNS Q"
			}
		}
		return "DNS R"
	default:
		return proto
	}
}

// formatValue formats a field value for display.
func formatValue(val any, f fields.Field) string {
	switch v := val.(type) {
	case net.IP:
		return v.String()
	case net.HardwareAddr:
		return v.String()
	case []byte:
		if len(v) == 0 {
			return "''"
		}
		if len(v) > 32 {
			return fmt.Sprintf("%x...(len=%d)", v[:32], len(v))
		}
		return fmt.Sprintf("%x", v)
	case string:
		if v == "" {
			return "''"
		}
		return v
	case uint8:
		if isHexField(f) {
			return fmt.Sprintf("0x%02x", v)
		}
		return fmt.Sprintf("%d", v)
	case uint16:
		if isHexField(f) {
			return fmt.Sprintf("0x%04x", v)
		}
		return fmt.Sprintf("%d", v)
	case uint32:
		if isHexField(f) {
			return fmt.Sprintf("0x%08x", v)
		}
		return fmt.Sprintf("%d", v)
	case uint64:
		if isHexField(f) {
			return fmt.Sprintf("0x%016x", v)
		}
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// formatAddr formats an address for Summary output.
func formatAddr(val any) string {
	switch v := val.(type) {
	case net.IP:
		return v.String()
	case net.HardwareAddr:
		return v.String()
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

// isHexField returns true if the field type uses hex display.
func isHexField(f fields.Field) bool {
	switch f.(type) {
	case *fields.XByteField:
		return true
	default:
		// Check embedded XByteField in ConditionalField
		if cf, ok := f.(*fields.ConditionalField); ok {
			return isHexField(cf.Field)
		}
	}
	return false
}

// fieldType returns a short type name for a field.
func fieldType(f fields.Field) string {
	switch f.(type) {
	case *fields.ByteField:
		return "Byte"
	case *fields.XByteField:
		return "XByte"
	case *fields.ShortField:
		return "Short"
	case *fields.LEShortField:
		return "LEShort"
	case *fields.ThreeBytesField:
		return "3Bytes"
	case *fields.IntField:
		return "Int"
	case *fields.SignedIntField:
		return "SInt"
	case *fields.LEIntField:
		return "LEInt"
	case *fields.LongField:
		return "Long"
	case *fields.LELongField:
		return "LELong"
	case *fields.BitField:
		return "Bit"
	case *fields.MACField:
		return "MAC"
	case *fields.IPField:
		return "IP"
	case *fields.IPv6Field:
		return "IPv6"
	case *fields.StrField:
		return "Str"
	case *fields.StrLenField:
		return "StrLen"
	case *fields.StrFixedField:
		return "StrFixed"
	case *fields.PacketField:
		return "Packet"
	case *fields.ConditionalField:
		return "Cond"
	default:
		return ""
	}
}

// tcpFlagStr returns a string representation of TCP flags.
func tcpFlagStr(val any) string {
	v, ok := val.(uint8)
	if !ok {
		return ""
	}
	var flags []string
	if v&0x02 != 0 {
		flags = append(flags, "S")
	}
	if v&0x10 != 0 {
		flags = append(flags, "A")
	}
	if v&0x01 != 0 {
		flags = append(flags, "F")
	}
	if v&0x04 != 0 {
		flags = append(flags, "R")
	}
	if v&0x08 != 0 {
		flags = append(flags, "P")
	}
	if v&0x20 != 0 {
		flags = append(flags, "U")
	}
	return strings.Join(flags, "")
}
