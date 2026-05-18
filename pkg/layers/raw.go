package layers

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// NewRaw creates a Raw payload layer for arbitrary data.
// This layer has no header structure — it simply wraps a byte payload.
func NewRaw() *packet.Layer {
	return packet.NewLayer("Raw", []fields.Field{
		fields.NewStrField("load", ""),
	})
}

// NewRawWith creates a Raw payload layer with the given data.
func NewRawWith(data []byte) *packet.Layer {
	l := NewRaw()
	l.Set("load", data)
	return l
}
