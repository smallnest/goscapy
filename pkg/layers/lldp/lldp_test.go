package lldp

import (
	"testing"
)

func TestNewLLDPDUDefaults(t *testing.T) {
	du := NewLLDPDU()

	if len(du.TLVs) != 4 {
		t.Fatalf("expected 4 TLVs (ChassisID, PortID, TTL, End), got %d", len(du.TLVs))
	}

	// Check mandatory TLV types
	if du.TLVs[0].Type != TLVChassisID {
		t.Errorf("TLV[0] type = %d, want %d (ChassisID)", du.TLVs[0].Type, TLVChassisID)
	}
	if du.TLVs[1].Type != TLVPortID {
		t.Errorf("TLV[1] type = %d, want %d (PortID)", du.TLVs[1].Type, TLVPortID)
	}
	if du.TLVs[2].Type != TLVTTL {
		t.Errorf("TLV[2] type = %d, want %d (TTL)", du.TLVs[2].Type, TLVTTL)
	}
	if du.TLVs[3].Type != TLVEnd {
		t.Errorf("TLV[3] type = %d, want %d (End)", du.TLVs[3].Type, TLVEnd)
	}

	// Check TTL value = 120
	ttl := du.TTL()
	if ttl != 120 {
		t.Errorf("TTL = %d, want 120", ttl)
	}
}

func TestSerializeParseRoundTrip(t *testing.T) {
	du := NewLLDPDU()

	data, err := du.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Serialize returned empty data")
	}

	parsed, err := ParseLLDPDU(data)
	if err != nil {
		t.Fatalf("ParseLLDPDU failed: %v", err)
	}

	if len(parsed.TLVs) != 4 {
		t.Fatalf("parsed TLV count = %d, want 4", len(parsed.TLVs))
	}

	// Verify round-trip
	reData, err := parsed.Serialize()
	if err != nil {
		t.Fatalf("re-Serialize failed: %v", err)
	}

	if len(data) != len(reData) {
		t.Errorf("round-trip length mismatch: %d vs %d", len(data), len(reData))
	}

	for i, tlv := range parsed.TLVs {
		if tlv.Type != du.TLVs[i].Type {
			t.Errorf("TLV[%d] type mismatch: %d vs %d", i, tlv.Type, du.TLVs[i].Type)
		}
	}
}

func TestTLVHeaderEncoding(t *testing.T) {
	// TLV header: Type (7 bits) | Length (9 bits)
	// Chassis ID TLV: type=1, value=[0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55] (7 bytes)
	// Header: (1 << 9) | 7 = 0x0200 | 0x0007 = 0x0207
	du := &LLDPDU{
		TLVs: []TLV{
			{Type: TLVChassisID, Value: []byte{0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
			{Type: TLVEnd, Value: nil},
		},
	}

	data, err := du.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// First TLV header should be 0x0207
	if data[0] != 0x02 || data[1] != 0x07 {
		t.Errorf("ChassisID TLV header = %02x %02x, want 02 07", data[0], data[1])
	}

	// End TLV header should be 0x0000
	endOff := len(data) - 2
	if data[endOff] != 0x00 || data[endOff+1] != 0x00 {
		t.Errorf("End TLV header = %02x %02x, want 00 00", data[endOff], data[endOff+1])
	}
}

func TestParseTruncated(t *testing.T) {
	// Too short for even a TLV header
	_, err := ParseLLDPDU([]byte{0x00})
	if err != nil {
		// Expected to fail or handle gracefully
		t.Logf("Parse with 1 byte returned: %v (expected)", err)
	}
}

func TestFindTLV(t *testing.T) {
	du := NewLLDPDU()

	chassis := du.ChassisID()
	if chassis == nil {
		t.Fatal("ChassisID() returned nil")
	}
	if chassis.Type != TLVChassisID {
		t.Errorf("ChassisID type = %d, want %d", chassis.Type, TLVChassisID)
	}

	port := du.PortID()
	if port == nil {
		t.Fatal("PortID() returned nil")
	}

	ttl := du.TTL()
	if ttl != 120 {
		t.Errorf("TTL = %d, want 120", ttl)
	}

	end := du.FindTLV(TLVEnd)
	if end == nil {
		t.Fatal("FindTLV(End) returned nil")
	}
}

func TestLayerIntegration(t *testing.T) {
	layer := NewLLDP()

	du := NewLLDPDU()
	err := BuildLLDP(du, layer)
	if err != nil {
		t.Fatalf("BuildLLDP failed: %v", err)
	}

	parsed, err := ParseLLDP(layer)
	if err != nil {
		t.Fatalf("ParseLLDP failed: %v", err)
	}

	if parsed.TTL() != 120 {
		t.Errorf("parsed TTL = %d, want 120", parsed.TTL())
	}
}
