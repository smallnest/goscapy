package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// TCP option kind constants (IANA-assigned).
const (
	TCPOptEOL       uint8 = 0
	TCPOptNOP       uint8 = 1
	TCPOptMSS       uint8 = 2
	TCPOptWScale    uint8 = 3
	TCPOptSACKPerm  uint8 = 4
	TCPOptSACK      uint8 = 5
	TCPOptTimestamp uint8 = 8
)

// TCPOption represents a single TCP option in Kind-Length-Value format.
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// TCPOptMSSVal creates an MSS option with the given maximum segment size.
func TCPOptMSSVal(mss uint16) TCPOption {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, mss)
	return TCPOption{Kind: TCPOptMSS, Length: 4, Data: data}
}

// TCPOptWScaleVal creates a Window Scale option.
func TCPOptWScaleVal(shift uint8) TCPOption {
	return TCPOption{Kind: TCPOptWScale, Length: 3, Data: []byte{shift}}
}

// TCPOptSACKPermVal creates a SACK Permitted option.
func TCPOptSACKPermVal() TCPOption {
	return TCPOption{Kind: TCPOptSACKPerm, Length: 2}
}

// TCPOptTimestampVal creates a Timestamps option.
func TCPOptTimestampVal(tsVal, tsEcr uint32) TCPOption {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], tsVal)
	binary.BigEndian.PutUint32(data[4:8], tsEcr)
	return TCPOption{Kind: TCPOptTimestamp, Length: 10, Data: data}
}

// TCPOptNOPVal creates a NOP (no-operation) option used for alignment.
func TCPOptNOPVal() TCPOption {
	return TCPOption{Kind: TCPOptNOP, Length: 1}
}

// ParseTCPOptions parses raw option bytes into a slice of TCPOption.
func ParseTCPOptions(data []byte) []TCPOption {
	var opts []TCPOption
	for i := 0; i < len(data); {
		kind := data[i]
		if kind == TCPOptEOL {
			break
		}
		if kind == TCPOptNOP {
			opts = append(opts, TCPOption{Kind: TCPOptNOP, Length: 1})
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		length := data[i+1]
		if length < 2 || i+int(length) > len(data) {
			break
		}
		opt := TCPOption{Kind: kind, Length: length}
		if length > 2 {
			opt.Data = make([]byte, length-2)
			copy(opt.Data, data[i+2:i+int(length)])
		}
		opts = append(opts, opt)
		i += int(length)
	}
	return opts
}

// SerializeTCPOptions serializes a slice of TCPOption into wire-format bytes,
// padded to a 4-byte boundary with NOP/EOL.
func SerializeTCPOptions(opts []TCPOption) []byte {
	if len(opts) == 0 {
		return nil
	}
	var buf []byte
	for _, opt := range opts {
		if opt.Kind == TCPOptNOP {
			buf = append(buf, TCPOptNOP)
			continue
		}
		if opt.Kind == TCPOptEOL {
			buf = append(buf, TCPOptEOL)
			continue
		}
		buf = append(buf, opt.Kind, opt.Length)
		if opt.Length > 2 {
			buf = append(buf, opt.Data...)
		}
	}
	// Pad to 4-byte alignment.
	if pad := len(buf) % 4; pad != 0 {
		for range 4 - pad {
			buf = append(buf, TCPOptEOL)
		}
	}
	return buf
}

// tcpOptionsField is a custom field that serializes/deserializes []TCPOption.
// During Unpack (dissect path), it returns empty options — the PostParseHook
// fills in the real value. During Pack (build path), it serializes the options.
type tcpOptionsField struct {
	fields.Desc
}

func newTCPOptionsField() *tcpOptionsField {
	return &tcpOptionsField{
		Desc: fields.Desc{},
	}
}

func (f *tcpOptionsField) Name() string      { return "options" }
func (f *tcpOptionsField) FixedSize() int     { return 0 }
func (f *tcpOptionsField) DefaultVal() any    { return []TCPOption(nil) }

func (f *tcpOptionsField) Pack(val any) ([]byte, error) {
	if val == nil {
		return nil, nil
	}
	opts, ok := val.([]TCPOption)
	if !ok {
		return nil, fmt.Errorf("fields: options expects []TCPOption, got %T", val)
	}
	return SerializeTCPOptions(opts), nil
}

func (f *tcpOptionsField) Unpack(_ []byte) (any, int, error) {
	return []TCPOption(nil), 0, nil
}

// tcpPostParseHook parses TCP option bytes from the gap between fixed header
// fields (20 bytes) and the actual header size (from dataofs).
func tcpPostParseHook(layer *packet.Layer, extra []byte) error {
	opts := ParseTCPOptions(extra)
	layer.Set("options", opts)
	return nil
}
