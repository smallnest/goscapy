package fields

import (
	"bytes"
	"testing"
)

func TestParseTLV_Basic(t *testing.T) {
	// Two options: type=1 val="ab", type=2 val="cdef"
	data := []byte{
		1, 2, 'a', 'b',
		2, 4, 'c', 'd', 'e', 'f',
	}
	opts, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 2 {
		t.Fatalf("got %d options, want 2", len(opts))
	}
	if opts[0].Type != 1 || opts[0].Length != 2 || string(opts[0].Value) != "ab" {
		t.Errorf("opt[0] = {%d, %d, %q}", opts[0].Type, opts[0].Length, opts[0].Value)
	}
	if opts[1].Type != 2 || opts[1].Length != 4 || string(opts[1].Value) != "cdef" {
		t.Errorf("opt[1] = {%d, %d, %q}", opts[1].Type, opts[1].Length, opts[1].Value)
	}
}

func TestParseTLV_EndOfOptions(t *testing.T) {
	// Type 0 terminates parsing.
	data := []byte{
		1, 2, 'a', 'b',
		0, // End marker
		3, 1, 'x', // Should be ignored
	}
	opts, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Fatalf("got %d options, want 1 (stopped at type 0)", len(opts))
	}
	if opts[0].Type != 1 {
		t.Errorf("opt type = %d, want 1", opts[0].Type)
	}
}

func TestParseTLV_EmptyInput(t *testing.T) {
	opts, err := ParseTLV([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 0 {
		t.Errorf("got %d options, want 0", len(opts))
	}
}

func TestParseTLV_OnlyEndMarker(t *testing.T) {
	opts, err := ParseTLV([]byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 0 {
		t.Errorf("got %d options, want 0", len(opts))
	}
}

func TestParseTLV_TruncatedLength(t *testing.T) {
	_, err := ParseTLV([]byte{1}) // type without length byte
	if err == nil {
		t.Fatal("expected error for truncated TLV")
	}
}

func TestParseTLV_TruncatedValue(t *testing.T) {
	_, err := ParseTLV([]byte{1, 5, 'a', 'b'}) // length=5 but only 2 bytes remain
	if err == nil {
		t.Fatal("expected error for truncated value")
	}
}

func TestParseTLV_ZeroLengthValue(t *testing.T) {
	data := []byte{1, 0, 2, 2, 'x', 'y'}
	opts, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 2 {
		t.Fatalf("got %d options, want 2", len(opts))
	}
	if len(opts[0].Value) != 0 {
		t.Errorf("opt[0] value length = %d, want 0", len(opts[0].Value))
	}
	if string(opts[1].Value) != "xy" {
		t.Errorf("opt[1] value = %q", opts[1].Value)
	}
}

func TestBuildTLV(t *testing.T) {
	opts := []TLVOption{
		{Type: 1, Length: 2, Value: []byte{'a', 'b'}},
		{Type: 2, Length: 0, Value: nil},
	}
	out := BuildTLV(opts)
	expected := []byte{1, 2, 'a', 'b', 2, 0}
	if !bytes.Equal(out, expected) {
		t.Errorf("BuildTLV = %v, want %v", out, expected)
	}
}

func TestBuildTLV_EmptyList(t *testing.T) {
	out := BuildTLV(nil)
	if len(out) != 0 {
		t.Errorf("got %d bytes, want 0", len(out))
	}
}

func TestParseAndBuild_RoundTrip(t *testing.T) {
	original := []TLVOption{
		{Type: 53, Length: 1, Value: []byte{1}},    // DHCP Message Type: DISCOVER
		{Type: 55, Length: 4, Value: []byte{1, 3, 6, 15}}, // Parameter Request List
		{Type: 50, Length: 4, Value: []byte{192, 168, 1, 100}}, // Requested IP
	}
	built := BuildTLV(original)
	parsed, err := ParseTLV(built)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != len(original) {
		t.Fatalf("round-trip: got %d options, want %d", len(parsed), len(original))
	}
	for i := range original {
		if parsed[i].Type != original[i].Type {
			t.Errorf("opt[%d].Type = %d, want %d", i, parsed[i].Type, original[i].Type)
		}
		if parsed[i].Length != original[i].Length {
			t.Errorf("opt[%d].Length = %d, want %d", i, parsed[i].Length, original[i].Length)
		}
		if !bytes.Equal(parsed[i].Value, original[i].Value) {
			t.Errorf("opt[%d].Value = %v, want %v", i, parsed[i].Value, original[i].Value)
		}
	}
}

func TestTLVOption_Nested(t *testing.T) {
	// NDP Prefix Information option contains nested TLV-like structure.
	// We test nesting by embedding TLVs inside a parent TLV's value.
	inner := BuildTLV([]TLVOption{
		{Type: 10, Length: 1, Value: []byte{0xAA}},
		{Type: 20, Length: 2, Value: []byte{0xBB, 0xCC}},
	})
	outer := TLVOption{Type: 3, Length: uint8(len(inner)), Value: inner}

	nested, err := outer.Nested()
	if err != nil {
		t.Fatal(err)
	}
	if len(nested) != 2 {
		t.Fatalf("got %d nested options, want 2", len(nested))
	}
	if nested[0].Type != 10 || nested[0].Value[0] != 0xAA {
		t.Errorf("nested[0] wrong")
	}
	if nested[1].Type != 20 || nested[1].Value[0] != 0xBB {
		t.Errorf("nested[1] wrong")
	}
}

func TestTLVOption_Nested_Empty(t *testing.T) {
	outer := TLVOption{Type: 3, Length: 0, Value: nil}
	nested, err := outer.Nested()
	if err != nil {
		t.Fatal(err)
	}
	if len(nested) != 0 {
		t.Errorf("got %d nested options, want 0", len(nested))
	}
}

func TestGetTLV(t *testing.T) {
	opts := []TLVOption{
		{Type: 53, Length: 1, Value: []byte{1}},
		{Type: 55, Length: 4, Value: []byte{1, 3, 6, 15}},
	}
	opt := GetTLV(opts, 53)
	if opt == nil || opt.Value[0] != 1 {
		t.Error("GetTLV(53) failed")
	}
	if GetTLV(opts, 99) != nil {
		t.Error("GetTLV(99) should be nil")
	}
}

func TestGetAllTLV(t *testing.T) {
	opts := []TLVOption{
		{Type: 1, Length: 1, Value: []byte{0xAA}},
		{Type: 2, Length: 1, Value: []byte{0xBB}},
		{Type: 1, Length: 1, Value: []byte{0xCC}},
	}
	all := GetAllTLV(opts, 1)
	if len(all) != 2 {
		t.Fatalf("got %d options with type 1, want 2", len(all))
	}
	if all[0].Value[0] != 0xAA || all[1].Value[0] != 0xCC {
		t.Error("GetAllTLV values wrong")
	}
	if len(GetAllTLV(opts, 99)) != 0 {
		t.Error("GetAllTLV(99) should be empty")
	}
}

func TestParseTLV_ValueIndependence(t *testing.T) {
	// Verify that modifying input bytes doesn't affect parsed options.
	data := []byte{1, 2, 'a', 'b'}
	opts, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	data[2] = 'x' // mutate input
	if opts[0].Value[0] != 'a' {
		t.Error("option value was mutated; want independent copy")
	}
}

func TestParseTLV_ManyOptions(t *testing.T) {
	var data []byte
	for i := range 100 {
		data = append(data, uint8(i+1), 3, 0xAA, 0xBB, 0xCC)
	}
	opts, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 100 {
		t.Fatalf("got %d options, want 100", len(opts))
	}
	for i, o := range opts {
		if o.Type != uint8(i+1) {
			t.Errorf("opt[%d].Type = %d, want %d", i, o.Type, i+1)
		}
	}
}

func TestParseTLV_MultipleEndMarkers(t *testing.T) {
	// First type=0 terminates, second ignored.
	data := []byte{1, 1, 'x', 0, 2, 1, 'y', 0}
	opts, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Fatalf("got %d options, want 1 (stopped at first type 0)", len(opts))
	}
}