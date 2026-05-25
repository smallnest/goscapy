package packet

import (
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
)

func TestLayerDefaults(t *testing.T) {
	fds := []fields.Field{
		fields.NewByteField("ver", 4),
		fields.NewShortField("len", 20),
		fields.NewIPField("src", nil),
	}

	l := NewLayer("Test", fds)

	if l.Proto() != "Test" {
		t.Errorf("Proto = %q, want Test", l.Proto())
	}

	// defaults populated
	v, err := l.Get("ver")
	if err != nil {
		t.Fatal(err)
	}
	if v.(uint8) != 4 {
		t.Errorf("Get(ver) = %v, want 4", v)
	}

	v, err = l.Get("len")
	if err != nil {
		t.Fatal(err)
	}
	if v.(uint16) != 20 {
		t.Errorf("Get(len) = %v, want 20", v)
	}
}

func TestLayerGetSet(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("a", 0),
		fields.NewShortField("b", 0),
	})

	if err := l.Set("a", uint8(42)); err != nil {
		t.Fatal(err)
	}
	v, _ := l.Get("a")
	if v.(uint8) != 42 {
		t.Errorf("set/get = %v", v)
	}

	// setting wrong name
	if err := l.Set("noexist", 1); err == nil {
		t.Errorf("Set(%q, 1) = %v, want error", "noexist", err)
	}

	// getting wrong name
	_, err := l.Get("noexist")
	if err == nil {
		t.Errorf("Get(%q) = %v, want error", "noexist", err)
	}
}

func TestLayerGetByIndex(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("first", 1),
		fields.NewByteField("second", 2),
		fields.NewByteField("third", 3),
	})

	v, err := l.GetField(0)
	if err != nil {
		t.Fatal(err)
	}
	if v.(uint8) != 1 {
		t.Errorf("GetField(0) = %v", v)
	}

	v, _ = l.GetField(2)
	if v.(uint8) != 3 {
		t.Errorf("GetField(2) = %v", v)
	}

	_, err = l.GetField(-1)
	if err == nil {
		t.Fatal("expected error for negative index")
	}
	_, err = l.GetField(3)
	if err == nil {
		t.Fatal("expected error for out-of-range index")
	}
}

func TestLayerSetByIndex(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("x", 0),
	})

	if err := l.SetField(0, uint8(99)); err != nil {
		t.Fatal(err)
	}
	v, _ := l.Get("x")
	if v.(uint8) != 99 {
		t.Errorf("set by index = %v", v)
	}

	// SetField out-of-range must error, not silently return nil.
	if err := l.SetField(99, uint8(1)); err == nil {
		t.Fatal("expected error for out-of-range SetField")
	}
}

func TestLayerValues(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("a", 1),
	})

	l.Set("a", uint8(100))
	cp := l.Values()
	if cp["a"].(uint8) != 100 {
		t.Errorf("Values() = %v", cp)
	}

	// modifying copy shouldn't affect original
	cp["a"] = uint8(200)
	v, _ := l.Get("a")
	if v.(uint8) != 100 {
		t.Errorf("Values() copy mutation leaked to layer")
	}
}

func TestLayerFindField(t *testing.T) {
	f1 := fields.NewByteField("a", 0)
	f2 := fields.NewShortField("b", 0)
	l := NewLayer("Test", []fields.Field{f1, f2})

	if f := l.FindField("a"); f != f1 {
		t.Errorf("FindField(%q) = %v, want %v", "a", f, f1)
	}
	if f := l.FindField("b"); f != f2 {
		t.Errorf("FindField(%q) = %v, want %v", "b", f, f2)
	}
	if f := l.FindField("nope"); f != nil {
		t.Errorf("FindField(%q) = %v, want nil", "nope", f)
	}
}

func TestLayerFieldIndex(t *testing.T) {
	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("a", 0),
		fields.NewByteField("b", 0),
	})

	if idx := l.FieldIndex("a"); idx != 0 {
		t.Errorf("FieldIndex(%q) = %d, want 0", "a", idx)
	}
	if idx := l.FieldIndex("b"); idx != 1 {
		t.Errorf("FieldIndex(%q) = %d, want 1", "b", idx)
	}
	if idx := l.FieldIndex("c"); idx != -1 {
		t.Errorf("FieldIndex(c) = %d, want -1", idx)
	}
}

func TestLayerConditionalField(t *testing.T) {
	inner := fields.NewByteField("opt", 0)
	cond := func(vals map[string]any) bool {
		return vals["hasOpt"] == uint8(1)
	}
	cf := fields.NewConditionalField(inner, cond)

	l := NewLayer("Test", []fields.Field{
		fields.NewByteField("hasOpt", 0),
		cf,
	})

	// Initially inactive: opt should not be in values
	_, err := l.Get("opt")
	if err == nil {
		t.Fatal("expected opt to be absent when hasOpt=0")
	}
}

func TestStackedPacket(t *testing.T) {
	p := New()

	if p.Len() != 0 {
		t.Errorf("Len() = %d, want 0", p.Len())
	}
	if p.First() != nil {
		t.Error("First() = non-nil, want nil")
	}
	if p.Last() != nil {
		t.Error("Last() = non-nil, want nil")
	}

	eth := NewLayer("Ethernet", nil)
	ip := NewLayer("IP", nil)
	tcp := NewLayer("TCP", nil)

	p.Push(eth)
	p.Push(ip)
	p.Push(tcp)

	if p.Len() != 3 {
		t.Fatalf("len = %d, want 3", p.Len())
	}
	if p.First().Proto() != "Ethernet" {
		t.Errorf("first = %s", p.First().Proto())
	}
	if p.Last().Proto() != "TCP" {
		t.Errorf("last = %s", p.Last().Proto())
	}
}

func TestInsertLayer(t *testing.T) {
	p := New()
	ip := NewLayer("IP", nil)
	tcp := NewLayer("TCP", nil)

	p.Push(ip)
	p.Push(tcp)
	p.Insert(NewLayer("Ethernet", nil))

	if p.First().Proto() != "Ethernet" {
		t.Errorf("after Insert, first = %s, want Ethernet", p.First().Proto())
	}
	if p.Len() != 3 {
		t.Errorf("len = %d, want 3", p.Len())
	}
}

func TestGetLayerHasLayer(t *testing.T) {
	p := New()
	p.Push(NewLayer("Ethernet", nil))
	p.Push(NewLayer("IP", nil))
	p.Push(NewLayer("TCP", nil))

	if !p.HasLayer("IP") {
		t.Errorf("HasLayer(%q) = false, want true", "IP")
	}
	if p.HasLayer("UDP") {
		t.Errorf("HasLayer(%q) = true, want false", "UDP")
	}
	if p.GetLayer("TCP") == nil {
		t.Error("GetLayer(TCP) = nil, want non-nil")
	}
	if p.GetLayer("ARP") != nil {
		t.Error("GetLayer(ARP) = non-nil, want nil")
	}
}

func TestGetLayers(t *testing.T) {
	// Simulate a VXLAN-tunneled packet:
	// [Ethernet, IP, UDP, VXLAN, Ethernet, IP, UDP, Payload]
	p := New()
	p.Push(NewLayer("Ethernet", nil)) // outer
	p.Push(NewLayer("IP", nil))       // outer
	p.Push(NewLayer("UDP", nil))      // outer (VXLAN encapsulation)
	p.Push(NewLayer("VXLAN", nil))
	p.Push(NewLayer("Ethernet", nil)) // inner
	p.Push(NewLayer("IP", nil))       // inner
	p.Push(NewLayer("UDP", nil))      // inner (actual payload)
	p.Push(NewLayer("Raw", nil))

	// GetLayers for UDP — should return 2 layers.
	udpLayers := p.GetLayers("UDP")
	if len(udpLayers) != 2 {
		t.Fatalf("GetLayers(UDP) = %d layers, want 2", len(udpLayers))
	}

	// GetLayers for IP — should return 2 layers.
	ipLayers := p.GetLayers("IP")
	if len(ipLayers) != 2 {
		t.Fatalf("GetLayers(IP) = %d layers, want 2", len(ipLayers))
	}

	// GetLayers for Ethernet — should return 2 layers.
	ethLayers := p.GetLayers("Ethernet")
	if len(ethLayers) != 2 {
		t.Fatalf("GetLayers(Ethernet) = %d layers, want 2", len(ethLayers))
	}

	// GetLayers for VXLAN — should return 1 layer.
	vxlanLayers := p.GetLayers("VXLAN")
	if len(vxlanLayers) != 1 {
		t.Fatalf("GetLayers(VXLAN) = %d layers, want 1", len(vxlanLayers))
	}

	// GetLayers for non-existent protocol.
	arpLayers := p.GetLayers("ARP")
	if len(arpLayers) != 0 {
		t.Fatalf("GetLayers(ARP) = %d layers, want 0", len(arpLayers))
	}

	// Verify order: first UDP is outer, second is inner.
	// Outer UDP is at index 2, inner UDP is at index 6.
	if udpLayers[0] != p.Layers()[2] {
		t.Error("GetLayers(UDP)[0] should be outer UDP (index 2)")
	}
	if udpLayers[1] != p.Layers()[6] {
		t.Error("GetLayers(UDP)[1] should be inner UDP (index 6)")
	}

	// GetLayers for single-occurrence protocol.
	rawLayers := p.GetLayers("Raw")
	if len(rawLayers) != 1 {
		t.Fatalf("GetLayers(Raw) = %d layers, want 1", len(rawLayers))
	}
	if rawLayers[0].Proto() != "Raw" {
		t.Errorf("GetLayers(Raw)[0].Proto() = %s, want Raw", rawLayers[0].Proto())
	}
}

func TestGetNthLayer(t *testing.T) {
	// Same VXLAN-tunneled packet structure.
	p := New()
	p.Push(NewLayer("Ethernet", nil)) // outer
	p.Push(NewLayer("IP", nil))       // outer
	p.Push(NewLayer("UDP", nil))      // outer
	p.Push(NewLayer("VXLAN", nil))
	p.Push(NewLayer("Ethernet", nil)) // inner
	p.Push(NewLayer("IP", nil))       // inner
	p.Push(NewLayer("UDP", nil))      // inner
	p.Push(NewLayer("Raw", nil))

	// GetNthLayer("UDP", 0) == outer UDP
	outerUDP := p.GetNthLayer("UDP", 0)
	if outerUDP == nil {
		t.Fatal("GetNthLayer(UDP, 0) = nil, want non-nil")
	}
	if outerUDP != p.Layers()[2] {
		t.Error("GetNthLayer(UDP, 0) should equal Layers()[2] (outer UDP)")
	}

	// GetNthLayer("UDP", 1) == inner UDP
	innerUDP := p.GetNthLayer("UDP", 1)
	if innerUDP == nil {
		t.Fatal("GetNthLayer(UDP, 1) = nil, want non-nil")
	}
	if innerUDP != p.Layers()[6] {
		t.Error("GetNthLayer(UDP, 1) should equal Layers()[6] (inner UDP)")
	}

	// GetNthLayer("UDP", 2) should be nil (only 2 UDP layers)
	if p.GetNthLayer("UDP", 2) != nil {
		t.Error("GetNthLayer(UDP, 2) should be nil")
	}

	// GetNthLayer("UDP", 0) == GetLayer("UDP")
	if p.GetNthLayer("UDP", 0) != p.GetLayer("UDP") {
		t.Error("GetNthLayer(UDP, 0) should equal GetLayer(UDP)")
	}

	// GetNthLayer for non-existent protocol.
	if p.GetNthLayer("ARP", 0) != nil {
		t.Error("GetNthLayer(ARP, 0) should be nil")
	}

	// GetNthLayer for single-occurrence protocol.
	vxlan := p.GetNthLayer("VXLAN", 0)
	if vxlan == nil || vxlan.Proto() != "VXLAN" {
		t.Error("GetNthLayer(VXLAN, 0) should return VXLAN layer")
	}
	if p.GetNthLayer("VXLAN", 1) != nil {
		t.Error("GetNthLayer(VXLAN, 1) should be nil")
	}
}

func TestGetLayersEmptyPacket(t *testing.T) {
	p := New()
	layers := p.GetLayers("IP")
	if len(layers) != 0 {
		t.Fatalf("GetLayers on empty packet = %d layers, want 0", len(layers))
	}
	if p.GetNthLayer("IP", 0) != nil {
		t.Error("GetNthLayer on empty packet should be nil")
	}
}

func TestNewFrom(t *testing.T) {
	p := NewFrom(
		NewLayer("A", nil),
		NewLayer("B", nil),
	)
	if p.Len() != 2 {
		t.Errorf("NewFrom len = %d", p.Len())
	}
}

func TestPacketString(t *testing.T) {
	p := NewFrom(
		NewLayer("Ethernet", nil),
		NewLayer("IP", nil),
		NewLayer("TCP", nil),
	)
	s := p.String()
	if s != "Ethernet / IP / TCP" {
		t.Errorf("String() = %q, want \"Ethernet / IP / TCP\"", s)
	}
}

func TestPacketCopy(t *testing.T) {
	p := NewFrom(NewLayer("IP", nil))
	cp := p.Copy()

	if cp.Len() != 1 {
		t.Error("copy lost layers")
	}

	// modify original
	p.Push(NewLayer("TCP", nil))
	if cp.Len() != 1 {
		t.Error("copy shares layer slice")
	}
}

func TestInsertAfter(t *testing.T) {
	// [Ethernet, IPv6, TCP] → InsertAfter("IPv6", hopByHop) → [Ethernet, IPv6, hopByHop, TCP]
	p := New()
	p.Push(NewLayer("Ethernet", nil))
	p.Push(NewLayer("IPv6", nil))
	p.Push(NewLayer("TCP", nil))

	hopByHop := NewLayer("IPv6 Hop-by-Hop", nil)
	p.InsertAfter("IPv6", hopByHop)

	if p.Len() != 4 {
		t.Fatalf("len = %d, want 4", p.Len())
	}
	protos := make([]string, p.Len())
	for i, l := range p.Layers() {
		protos[i] = l.Proto()
	}
	want := []string{"Ethernet", "IPv6", "IPv6 Hop-by-Hop", "TCP"}
	for i, w := range want {
		if protos[i] != w {
			t.Errorf("layer[%d] = %q, want %q", i, protos[i], w)
		}
	}
}

func TestInsertAfterNotFound(t *testing.T) {
	// If proto not found, layer is pushed on top.
	p := New()
	p.Push(NewLayer("Ethernet", nil))
	p.Push(NewLayer("IP", nil))

	hopByHop := NewLayer("IPv6 Hop-by-Hop", nil)
	p.InsertAfter("IPv6", hopByHop)

	if p.Len() != 3 {
		t.Fatalf("len = %d, want 3", p.Len())
	}
	if p.Last().Proto() != "IPv6 Hop-by-Hop" {
		t.Errorf("last = %s, want IPv6 Hop-by-Hop (pushed on top)", p.Last().Proto())
	}
}

func TestInsertAfterFirstLayer(t *testing.T) {
	// [IP, TCP] → InsertAfter("IP", extHdr) → [IP, extHdr, TCP]
	p := New()
	p.Push(NewLayer("IP", nil))
	p.Push(NewLayer("TCP", nil))

	extHdr := NewLayer("Extension", nil)
	p.InsertAfter("IP", extHdr)

	if p.Len() != 3 {
		t.Fatalf("len = %d, want 3", p.Len())
	}
	want := []string{"IP", "Extension", "TCP"}
	for i, l := range p.Layers() {
		if l.Proto() != want[i] {
			t.Errorf("layer[%d] = %q, want %q", i, l.Proto(), want[i])
		}
	}
}
