package goscapy

import "github.com/smallnest/goscapy/pkg/packet"

// Hexdump returns a canonical hex+ASCII dump of data, in the style of
// Scapy's hexdump(). It is a convenience alias for packet.Hexdump.
func Hexdump(data []byte) string { return packet.Hexdump(data) }

// Ls returns a description of a registered protocol's fields, types, and
// default values, like Scapy's ls("IP"). With an empty proto it lists all
// registered protocol names. It is a convenience alias for packet.Ls.
func Ls(proto string) string { return packet.Ls(proto) }

// FieldNames returns the wire-order field names of a registered protocol,
// or nil if unknown. It is a convenience alias for packet.FieldNames.
func FieldNames(proto string) []string { return packet.FieldNames(proto) }

// ListLayers returns the sorted names of all registered protocols, like
// Scapy's ls() with no argument.
func ListLayers() []string { return packet.ListLayers() }
