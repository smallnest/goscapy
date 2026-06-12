package layers

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
)

// deferredBytesField is a variable-length byte field that consumes nothing
// during Unpack (dissect), leaving the real value to be filled in by a
// registered PostParseHook from the header gap the engine computes via a
// HeaderSizeFunc. During Pack (build) it serializes the stored bytes verbatim.
//
// This is the pattern the dissect engine requires for a trailing variable
// field whose length is derived from an earlier length field: if the field
// greedily consumed all remaining bytes during Unpack, the engine's
// "actualHeaderSize > consumed" gate would never fire and the PostParseHook
// would be skipped, leaving the field holding bytes that belong to upper
// layers. tcpOptionsField uses the same deferral.
type deferredBytesField struct {
	fields.Desc
	name string
}

// newDeferredBytesField creates a deferred variable-length byte field. Its
// value is a []byte/string filled in by a PostParseHook during dissection.
func newDeferredBytesField(name string) *deferredBytesField {
	return &deferredBytesField{name: name}
}

func (f *deferredBytesField) Name() string    { return f.name }
func (f *deferredBytesField) FixedSize() int  { return 0 }
func (f *deferredBytesField) DefaultVal() any { return "" }

func (f *deferredBytesField) Pack(val any) ([]byte, error) {
	switch v := val.(type) {
	case nil:
		return nil, nil
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("fields: %s expects string or []byte, got %T", f.name, val)
	}
}

func (f *deferredBytesField) Unpack(_ []byte) (any, int, error) {
	// Deferred: the registered PostParseHook fills in the real value.
	return "", 0, nil
}
