package packet

import (
	"fmt"
	"sort"
	"strings"
)

// Hexdump returns a canonical hex+ASCII dump of data, in the style of
// Scapy's hexdump() and the classic `hexdump -C` / `xxd` layout:
//
//	0000  45 00 00 28 00 00 00 00  40 06 00 00 c0 a8 01 01  E..(....@.......
//	0010  0a 00 00 01                                       ....
//
// Each line shows a 4-digit hex offset, up to 16 bytes (split into two
// 8-byte groups), and the printable-ASCII rendering (non-printable bytes
// shown as '.').
func Hexdump(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var b strings.Builder
	const width = 16
	for off := 0; off < len(data); off += width {
		end := off + width
		if end > len(data) {
			end = len(data)
		}
		line := data[off:end]

		fmt.Fprintf(&b, "%04x  ", off)

		// Hex columns, with an extra space after the 8th byte.
		for i := 0; i < width; i++ {
			if i == 8 {
				b.WriteByte(' ')
			}
			if i < len(line) {
				fmt.Fprintf(&b, "%02x ", line[i])
			} else {
				b.WriteString("   ")
			}
		}

		// ASCII column.
		b.WriteByte(' ')
		for _, c := range line {
			if c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Hexdump builds the packet and returns a canonical hex+ASCII dump of the
// resulting wire bytes, like Scapy's hexdump(pkt). If the packet fails to
// build, the error text is returned instead.
func (p *Packet) Hexdump() string {
	data, err := p.Build()
	if err != nil {
		return fmt.Sprintf("<hexdump error: %v>", err)
	}
	return Hexdump(data)
}

// Show2 builds the packet, re-dissects the resulting wire bytes, and returns
// the Show() output of the rebuilt packet. This mirrors Scapy's pkt.show2(),
// which displays the packet "as it would appear on the wire" — with all
// auto-computed fields (lengths, checksums) filled in and the byte stream
// re-parsed from scratch.
//
// The first layer's protocol is used as the dissection entry point. If the
// packet cannot be built or re-dissected, the error text is returned.
func (p *Packet) Show2() string {
	if len(p.layers) == 0 {
		return ""
	}
	data, err := p.Build()
	if err != nil {
		return fmt.Sprintf("<show2 build error: %v>", err)
	}
	rebuilt, err := DissectByProto(data, p.layers[0].Proto())
	if err != nil {
		return fmt.Sprintf("<show2 dissect error: %v>", err)
	}
	return rebuilt.Show()
}

// Ls returns a description of a registered protocol's fields, types, and
// default values, similar to Scapy's ls("IP"). The protocol must have been
// registered via RegisterLayer. If proto is empty, Ls returns the sorted list
// of all registered protocol names (like Scapy's ls() with no argument).
func Ls(proto string) string {
	if proto == "" {
		names := ListLayers()
		return strings.Join(names, "\n")
	}
	factory, ok := dissectRegistry.factories[proto]
	if !ok {
		return fmt.Sprintf("<unknown protocol %q>", proto)
	}
	layer := factory()
	return layer.Describe()
}

// FieldNames returns the names of all fields defined for a registered protocol,
// in wire order. Returns nil if the protocol is unknown. This supports
// programmatic field introspection (Scapy's fields_desc iteration).
func FieldNames(proto string) []string {
	factory, ok := dissectRegistry.factories[proto]
	if !ok {
		return nil
	}
	layer := factory()
	names := make([]string, 0, len(layer.fields))
	for _, f := range layer.fields {
		names = append(names, f.Name())
	}
	return names
}

// RegisteredLayers returns the sorted names of all registered protocols.
// It is an alias for ListLayers kept for symmetry with FieldNames.
func RegisteredLayers() []string {
	names := ListLayers()
	sort.Strings(names)
	return names
}
