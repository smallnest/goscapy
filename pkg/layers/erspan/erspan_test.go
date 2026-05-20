package erspan

import (
	"testing"
)

func TestNewERSPANDefaults(t *testing.T) {
	e := NewERSPANHeader()
	if e.Version != VersionIII {
		t.Errorf("Version = %d, want %d", e.Version, VersionIII)
	}
	if e.SessionID != 0 {
		t.Errorf("SessionID = %d, want 0", e.SessionID)
	}
	if e.Direction != DirIngress {
		t.Errorf("Direction = %d, want %d", e.Direction, DirIngress)
	}
}

func TestSerializeParseRoundTrip(t *testing.T) {
	e := &ERSPAN{
		Version:    VersionIII,
		VLAN:       100,
		COS:        5,
		BSO:        2,
		En:         1,
		T:          0,
		SessionID:  0x123,
		Timestamp:  0xAABBCCDD,
		SGT:        500,
		P:          1,
		FT:         0,
		Offset:     0,
		HardwareID: 0,
		Direction:  DirEgress,
		GRA:        0,
		OA:         0,
	}

	data, err := e.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(data) != HeaderSizeV3 {
		t.Fatalf("Serialize len = %d, want %d", len(data), HeaderSizeV3)
	}

	// Verify version is in the first nibble
	if (data[0]>>4)&0x0F != VersionIII {
		t.Errorf("version nibble = %d, want %d", (data[0]>>4)&0x0F, VersionIII)
	}

	parsed, err := ParseERSPAN(data)
	if err != nil {
		t.Fatalf("ParseERSPAN failed: %v", err)
	}

	if parsed.Version != e.Version {
		t.Errorf("Version: got %d, want %d", parsed.Version, e.Version)
	}
	if parsed.VLAN != e.VLAN {
		t.Errorf("VLAN: got %d, want %d", parsed.VLAN, e.VLAN)
	}
	if parsed.Timestamp != e.Timestamp {
		t.Errorf("Timestamp: got 0x%08x, want 0x%08x", parsed.Timestamp, e.Timestamp)
	}
	if parsed.SGT != e.SGT {
		t.Errorf("SGT: got %d, want %d", parsed.SGT, e.SGT)
	}
}

func TestParseTruncated(t *testing.T) {
	_, err := ParseERSPAN([]byte{0x30, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for truncated ERSPAN data")
	}
}

func TestLayerCreation(t *testing.T) {
	layer := NewERSPAN()
	if layer.Proto() != "ERSPAN" {
		t.Errorf("Proto = %q, want %q", layer.Proto(), "ERSPAN")
	}
}
