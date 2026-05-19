package packet

import (
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
)

func TestRegisterBuildHook(t *testing.T) {
	called := false
	hook := func(pkt *Packet, layerIdx int, upperBytes []byte) ([]byte, error) {
		called = true
		return nil, nil
	}

	// Register a hook for a test protocol.
	RegisterBuildHook("TestProto", hook)

	// Verify it can be looked up.
	h := lookupBuildHook("TestProto")
	if h == nil {
		t.Fatal("lookupBuildHook(TestProto) returned nil")
	}

	// Call it to verify it's the right hook.
	h(nil, 0, nil)
	if !called {
		t.Error("hook was not called")
	}

	// Non-existent protocol should return nil.
	if lookupBuildHook("NoSuchProto") != nil {
		t.Error("expected nil for unregistered protocol")
	}

	// Clean up to avoid polluting other tests.
	delete(buildHooks, "TestProto")
}

func TestSerializeFieldsBasic(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("a", 0),
		fields.NewShortField("b", 0),
	})

	l.Set("a", uint8(0x42))
	l.Set("b", uint16(0x1234))

	got, err := l.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{0x42, 0x12, 0x34}
	if len(got) != len(expected) {
		t.Fatalf("len = %d, want %d", len(got), len(expected))
	}
	for i, b := range got {
		if b != expected[i] {
			t.Errorf("byte %d = %#x, want %#x", i, b, expected[i])
		}
	}
}

func TestSerializeFieldsConditionalActive(t *testing.T) {
	inner := fields.NewByteField("opt", 0)
	cond := func(vals map[string]any) bool {
		return vals["hasOpt"] == uint8(1)
	}
	cf := fields.NewConditionalField(inner, cond)

	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("hasOpt", 0),
		cf,
	})

	// Inactive: opt should not be serialized.
	got, err := l.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("inactive conditional: len = %d, want 1", len(got))
	}

	// Active: opt should be serialized.
	l.Set("hasOpt", uint8(1))
	// Note: NewLayer skips conditional field defaults when inactive.
	// We need to manually add the value when activating.
	l.values["opt"] = uint8(0xFF)

	got, err = l.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("active conditional: len = %d, want 2", len(got))
	}
	if got[1] != 0xFF {
		t.Errorf("opt byte = %#x, want 0xFF", got[1])
	}
}

func TestBuildEmptyPacket(t *testing.T) {
	p := New()
	_, err := p.Build()
	if err == nil {
		t.Error("expected error for empty packet")
	}
}

func TestBuildFromOutOfRange(t *testing.T) {
	p := NewFrom(NewLayer("A", nil))
	_, err := p.BuildFrom(-1)
	if err == nil {
		t.Error("expected error for negative index")
	}
	_, err = p.BuildFrom(5)
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestBuildSingleLayer(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("x", 0x42),
	})
	p := NewFrom(l)

	got, err := p.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0] != 0x42 {
		t.Errorf("byte = %#x, want 0x42", got[0])
	}
}

func TestBuildMultipleLayers(t *testing.T) {
	l1 := NewLayer("L1", []fields.Field{
		fields.NewByteField("a", 0x11),
	})
	l2 := NewLayer("L2", []fields.Field{
		fields.NewByteField("b", 0x22),
	})
	l3 := NewLayer("L3", []fields.Field{
		fields.NewByteField("c", 0x33),
	})

	p := NewFrom(l1, l2, l3)
	got, err := p.Build()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{0x11, 0x22, 0x33}
	if len(got) != len(expected) {
		t.Fatalf("len = %d, want %d", len(got), len(expected))
	}
	for i, b := range got {
		if b != expected[i] {
			t.Errorf("byte %d = %#x, want %#x", i, b, expected[i])
		}
	}
}

func TestBuildFromSkipLayer(t *testing.T) {
	l1 := NewLayer("L1", []fields.Field{
		fields.NewByteField("a", 0x11),
	})
	l2 := NewLayer("L2", []fields.Field{
		fields.NewByteField("b", 0x22),
	})

	p := NewFrom(l1, l2)

	got, err := p.BuildFrom(1)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0] != 0x22 {
		t.Errorf("byte = %#x, want 0x22", got[0])
	}
}
