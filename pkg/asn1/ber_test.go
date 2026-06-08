package asn1

import (
	"testing"
)

func TestBERLength(t *testing.T) {
	tests := []struct {
		length int
		want   []byte
	}{
		{0, []byte{0x00}},
		{5, []byte{0x05}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{256, []byte{0x82, 0x01, 0x00}},
	}
	for _, tt := range tests {
		got := BERLength(tt.length)
		if !equalBytes(got, tt.want) {
			t.Errorf("BERLength(%d) = %v, want %v", tt.length, got, tt.want)
		}
	}
}

func TestBERDecodeLength(t *testing.T) {
	tests := []struct {
		data     []byte
		wantLen  int
		wantCons int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0x81, 0x80}, 128, 2},
		{[]byte{0x82, 0x01, 0x00}, 256, 3},
	}
	for _, tt := range tests {
		l, c, err := BERDecodeLength(tt.data)
		if err != nil {
			t.Fatalf("BERDecodeLength(%v): %v", tt.data, err)
		}
		if l != tt.wantLen || c != tt.wantCons {
			t.Errorf("BERDecodeLength(%v) = (%d, %d), want (%d, %d)", tt.data, l, c, tt.wantLen, tt.wantCons)
		}
	}
}

func TestBERTLV(t *testing.T) {
	// Short form length.
	got := BERTLV(0x02, []byte{0x01})
	want := []byte{0x02, 0x01, 0x01}
	if !equalBytes(got, want) {
		t.Errorf("BERTLV = %v, want %v", got, want)
	}
}

func TestBERDecodeTLV(t *testing.T) {
	data := []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00}
	tag, val, consumed, err := BERDecodeTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if tag != 0x30 {
		t.Errorf("tag = 0x%02x, want 0x30", tag)
	}
	if consumed != 7 {
		t.Errorf("consumed = %d, want 7", consumed)
	}
	// Inner: Integer 1, Null.
	innerTag, innerVal, innerConsumed, err := BERDecodeTLV(val)
	if err != nil {
		t.Fatal(err)
	}
	if innerTag != TagInteger {
		t.Errorf("inner tag = 0x%02x, want 0x02", innerTag)
	}
	if len(innerVal) != 1 || innerVal[0] != 1 {
		t.Errorf("inner val = %v, want [1]", innerVal)
	}
	_ = innerConsumed
}

func TestBEREncodeInteger(t *testing.T) {
	tests := []struct {
		val  int
		want []byte
	}{
		{0, []byte{TagInteger, 0x01, 0x00}},
		{1, []byte{TagInteger, 0x01, 0x01}},
		{127, []byte{TagInteger, 0x01, 0x7f}},
		{128, []byte{TagInteger, 0x02, 0x00, 0x80}},
		{-1, []byte{TagInteger, 0x01, 0xff}},
		{-128, []byte{TagInteger, 0x01, 0x80}},
		{-129, []byte{TagInteger, 0x02, 0xff, 0x7f}},
	}
	for _, tt := range tests {
		got := BEREncodeInteger(tt.val)
		if !equalBytes(got, tt.want) {
			t.Errorf("BEREncodeInteger(%d) = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestBERDecodeInteger(t *testing.T) {
	tests := []struct {
		data []byte
		want int
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x7f}, 127},
		{[]byte{0x00, 0x80}, 128},
		{[]byte{0xff}, -1},
		{[]byte{0x80}, -128},
		{[]byte{0xff, 0x7f}, -129},
	}
	for _, tt := range tests {
		got, err := BERDecodeInteger(tt.data)
		if err != nil {
			t.Fatalf("BERDecodeInteger(%v): %v", tt.data, err)
		}
		if got != tt.want {
			t.Errorf("BERDecodeInteger(%v) = %d, want %d", tt.data, got, tt.want)
		}
	}
}

func TestBEREncodeBoolean(t *testing.T) {
	gotTrue := BEREncodeBoolean(true)
	wantTrue := []byte{TagBoolean, 0x01, 0xFF}
	if !equalBytes(gotTrue, wantTrue) {
		t.Errorf("BEREncodeBoolean(true) = %v, want %v", gotTrue, wantTrue)
	}

	gotFalse := BEREncodeBoolean(false)
	wantFalse := []byte{TagBoolean, 0x01, 0x00}
	if !equalBytes(gotFalse, wantFalse) {
		t.Errorf("BEREncodeBoolean(false) = %v, want %v", gotFalse, wantFalse)
	}
}

func TestBERDecodeBoolean(t *testing.T) {
	val, err := BERDecodeBoolean([]byte{0xFF})
	if err != nil || val != true {
		t.Errorf("BERDecodeBoolean([0xFF]) = %v, %v; want true, nil", val, err)
	}
	val, err = BERDecodeBoolean([]byte{0x00})
	if err != nil || val != false {
		t.Errorf("BERDecodeBoolean([0x00]) = %v, %v; want false, nil", val, err)
	}
}

func TestBEREncodeEnumerated(t *testing.T) {
	got := BEREncodeEnumerated(1)
	want := []byte{TagEnumerated, 0x01, 0x01}
	if !equalBytes(got, want) {
		t.Errorf("BEREncodeEnumerated(1) = %v, want %v", got, want)
	}
}

func TestBERDecodeEnumerated(t *testing.T) {
	got, err := BERDecodeEnumerated([]byte{0x01})
	if err != nil || got != 1 {
		t.Errorf("BERDecodeEnumerated([1]) = %d, %v; want 1, nil", got, err)
	}
}

func TestBEREncodeBitString(t *testing.T) {
	got := BEREncodeBitString([]byte{0xA0}, 0)
	want := []byte{TagBitString, 0x02, 0x00, 0xA0}
	if !equalBytes(got, want) {
		t.Errorf("BEREncodeBitString = %v, want %v", got, want)
	}
}

func TestBERDecodeBitString(t *testing.T) {
	data, unused, err := BERDecodeBitString([]byte{0x00, 0xA0})
	if err != nil {
		t.Fatal(err)
	}
	if unused != 0 || len(data) != 1 || data[0] != 0xA0 {
		t.Errorf("BERDecodeBitString = (%v, %d), want ([0xA0], 0)", data, unused)
	}
}

func TestBEREncodeNull(t *testing.T) {
	got := BEREncodeNull()
	want := []byte{TagNull, 0x00}
	if !equalBytes(got, want) {
		t.Errorf("BEREncodeNull() = %v, want %v", got, want)
	}
}

func TestBEREncodeOctetString(t *testing.T) {
	got := BEREncodeOctetString([]byte("hello"))
	want := []byte{TagOctetString, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if !equalBytes(got, want) {
		t.Errorf("BEREncodeOctetString = %v, want %v", got, want)
	}
}

func TestBEREncodeOID(t *testing.T) {
	got := BEREncodeOID("1.3.6.1")
	// 1.3 → 0x2B (1*40+3=43), 6 → 0x06, 1 → 0x01
	want := []byte{TagOID, 0x03, 0x2B, 0x06, 0x01}
	if !equalBytes(got, want) {
		t.Errorf("BEREncodeOID = %v, want %v", got, want)
	}
}

func TestBERDecodeOID(t *testing.T) {
	got := BERDecodeOID([]byte{0x2B, 0x06, 0x01})
	want := ".1.3.6.1"
	if got != want {
		t.Errorf("BERDecodeOID = %q, want %q", got, want)
	}
}

func TestBEREncodeGeneralizedTime(t *testing.T) {
	ts := []byte("20240101120000Z")
	got := BEREncodeGeneralizedTime(ts)
	want := append([]byte{TagGeneralizedTime, byte(len(ts))}, ts...)
	if !equalBytes(got, want) {
		t.Errorf("BEREncodeGeneralizedTime = %v, want %v", got, want)
	}
}

func TestBERDecodeOIDMalformed(t *testing.T) {
	// Unterminated OID sub-identifier: all bytes have continuation bit set.
	// Should not panic or loop forever; decodeOIDSubID caps at 5 iterations.
	got := BERDecodeOID([]byte{0x2B, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01})
	// Should still produce a result without panic.
	if got == "" {
		t.Error("expected non-empty OID from malformed input")
	}
}

func TestBERDecodeTLVErrors(t *testing.T) {
	_, _, _, err := BERDecodeTLV(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}

	_, _, _, err = BERDecodeTLV([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}

	// Truncated TLV: tag + length says 5 bytes but only 2 available.
	_, _, _, err = BERDecodeTLV([]byte{0x02, 0x05, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for truncated TLV")
	}
}

func TestBERDecodeIntegerEmpty(t *testing.T) {
	_, err := BERDecodeInteger(nil)
	if err == nil {
		t.Error("expected error for empty integer")
	}
}

func TestBERDecodeBitStringErrors(t *testing.T) {
	_, _, err := BERDecodeBitString(nil)
	if err == nil {
		t.Error("expected error for nil bit string")
	}

	_, _, err = BERDecodeBitString([]byte{0x08}) // unused bits > 7
	if err == nil {
		t.Error("expected error for invalid unused bits")
	}
}

func TestBERDecodeLengthErrors(t *testing.T) {
	_, _, err := BERDecodeLength(nil)
	if err == nil {
		t.Error("expected error for nil length")
	}

	_, _, err = BERDecodeLength([]byte{0x80}) // indefinite form
	if err == nil {
		t.Error("expected error for indefinite length")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
