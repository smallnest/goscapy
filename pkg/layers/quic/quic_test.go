package quic

import (
	"testing"
)

func TestVLQEncoding(t *testing.T) {
	tests := []struct {
		value uint64
		bytes int
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1073741823, 4},
		{1073741824, 8},
	}

	for _, tc := range tests {
		encoded := EncodeVLQ(tc.value)
		if len(encoded) != tc.bytes {
			t.Errorf("EncodeVLQ(%d): got %d bytes, want %d", tc.value, len(encoded), tc.bytes)
		}

		decoded, n := DecodeVLQ(encoded)
		if decoded != tc.value {
			t.Errorf("DecodeVLQ(EncodeVLQ(%d)): got %d", tc.value, decoded)
		}
		if n != tc.bytes {
			t.Errorf("DecodeVLQ consumed %d bytes, want %d", n, tc.bytes)
		}
	}
}

func TestCryptoFrameRoundTrip(t *testing.T) {
	frame := &CRYPTOFrame{
		Offset: 0,
		Data:   []byte{0x01, 0x02, 0x03, 0x04},
	}

	data := SerializeCryptoFrame(frame)

	parsed, consumed, err := ParseCryptoFrame(data)
	if err != nil {
		t.Fatalf("ParseCryptoFrame failed: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("consumed = %d, want %d", consumed, len(data))
	}
	if parsed.Offset != frame.Offset {
		t.Errorf("Offset = %d, want %d", parsed.Offset, frame.Offset)
	}
	if len(parsed.Data) != len(frame.Data) {
		t.Fatalf("Data len = %d, want %d", len(parsed.Data), len(frame.Data))
	}
	for i, b := range parsed.Data {
		if b != frame.Data[i] {
			t.Errorf("Data[%d] = %d, want %d", i, b, frame.Data[i])
		}
	}
}

func TestLongHeaderRoundTrip(t *testing.T) {
	h := &QUICLongHeader{
		FirstByte: 0xC3, // Long header, Initial, PN len = 3
		Version:   Version1,
		DCID:      []byte{0x01, 0x02, 0x03, 0x04},
		SCID:      []byte{0x05, 0x06},
		Token:     []byte{0xAA, 0xBB},
		Payload:   []byte{0x00, 0x01, 0x02}, // packet number + payload
	}

	data, err := SerializeLongHeader(h)
	if err != nil {
		t.Fatalf("SerializeLongHeader failed: %v", err)
	}

	parsed, err := ParseLongHeader(data)
	if err != nil {
		t.Fatalf("ParseLongHeader failed: %v", err)
	}

	if parsed.Version != h.Version {
		t.Errorf("Version = 0x%08x, want 0x%08x", parsed.Version, h.Version)
	}
	if len(parsed.DCID) != len(h.DCID) {
		t.Errorf("DCID len = %d, want %d", len(parsed.DCID), len(h.DCID))
	}
	if len(parsed.SCID) != len(h.SCID) {
		t.Errorf("SCID len = %d, want %d", len(parsed.SCID), len(h.SCID))
	}
	if len(parsed.Token) != len(h.Token) {
		t.Errorf("Token len = %d, want %d", len(parsed.Token), len(h.Token))
	}
}

func TestParseLongHeaderTooShort(t *testing.T) {
	_, err := ParseLongHeader([]byte{0xC0, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestParseLongHeaderNotLongHeader(t *testing.T) {
	_, err := ParseLongHeader([]byte{0x40, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for non-long-header first byte")
	}
}

func TestLayerCreation(t *testing.T) {
	layer := NewQUICLongHeader()
	if layer.Proto() != "QUIC" {
		t.Errorf("Proto = %q, want %q", layer.Proto(), "QUIC")
	}
}
