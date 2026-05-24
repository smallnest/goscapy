package traceroute

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.MaxTTL != 30 {
		t.Errorf("MaxTTL = %d, want 30", opts.MaxTTL)
	}
	if opts.Probes != 3 {
		t.Errorf("Probes = %d, want 3", opts.Probes)
	}
	if opts.Protocol != ProtoICMP {
		t.Errorf("Protocol = %d, want ProtoICMP", opts.Protocol)
	}
}

func TestResultString(t *testing.T) {
	r := &TracerouteResult{
		Dst:      "example.com",
		DstIP:    "93.184.216.34",
		Protocol: ProtoICMP,
		MaxTTL:   30,
		Hops: []Hop{
			{TTL: 1, IP: "192.168.1.1", RTT: 1 * time.Millisecond},
			{TTL: 2, IP: "10.0.0.1", RTT: 5 * time.Millisecond},
			{TTL: 3, IP: ""},
		},
		Reached: true,
	}

	s := r.String()
	if !strings.Contains(s, "example.com") {
		t.Error("missing destination")
	}
	if !strings.Contains(s, "192.168.1.1") {
		t.Error("missing hop 1")
	}
	if !strings.Contains(s, "*") {
		t.Error("missing star for empty hop")
	}
	if !strings.Contains(s, "Reached") {
		t.Error("missing reached message")
	}
}

func TestResultStringWithAS(t *testing.T) {
	r := &TracerouteResult{
		Dst:      "8.8.8.8",
		DstIP:    "8.8.8.8",
		Protocol: ProtoTCP,
		MaxTTL:   20,
		Hops: []Hop{
			{TTL: 1, IP: "192.168.1.1", RTT: 1 * time.Millisecond, ASNum: "54321", ASName: "ISP-NAME"},
		},
	}

	s := r.String()
	if !strings.Contains(s, "AS54321") {
		t.Error("missing AS number")
	}
	if !strings.Contains(s, "ISP-NAME") {
		t.Error("missing AS name")
	}
	if !strings.Contains(s, "TCP") {
		t.Error("missing protocol name")
	}
}

func TestGraph(t *testing.T) {
	r := &TracerouteResult{
		Dst:   "example.com",
		DstIP: "93.184.216.34",
		Hops: []Hop{
			{TTL: 1, IP: "192.168.1.1", RTT: 1 * time.Millisecond},
			{TTL: 2, IP: "10.0.0.1", RTT: 5 * time.Millisecond, ASNum: "1234", ASName: "TestAS"},
		},
		Reached: true,
	}

	g := r.Graph()
	if !strings.Contains(g, "digraph") {
		t.Error("missing digraph declaration")
	}
	if !strings.Contains(g, "192.168.1.1") {
		t.Error("missing hop 1")
	}
	if !strings.Contains(g, "AS1234") {
		t.Error("missing AS in graph")
	}
	if !strings.Contains(g, "example.com") {
		t.Error("missing destination in graph")
	}
}

func TestGraphEmptyHops(t *testing.T) {
	r := &TracerouteResult{
		Dst:   "10.0.0.1",
		DstIP: "10.0.0.1",
		Hops: []Hop{
			{TTL: 1, IP: ""},
			{TTL: 2, IP: "10.0.0.1", RTT: 2 * time.Millisecond},
		},
	}

	g := r.Graph()
	if !strings.Contains(g, "10.0.0.1") {
		t.Error("missing hop in graph")
	}
}

func TestMinRTT(t *testing.T) {
	min := minRTT([]time.Duration{5 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond})
	if min != 3*time.Millisecond {
		t.Errorf("minRTT = %v, want 3ms", min)
	}
}

func TestMinRTTEmpty(t *testing.T) {
	if minRTT(nil) != 0 {
		t.Error("minRTT(nil) should be 0")
	}
}

func TestDetectInterface(t *testing.T) {
	iface := detectInterface(nil)
	if iface == "" {
		t.Error("detectInterface returned empty string")
	}
}

func TestGetLocalIP(t *testing.T) {
	iface := detectInterface(nil)
	ip := getLocalIP(iface)
	if ip == nil {
		t.Errorf("getLocalIP(%s) returned nil", iface)
	}
}

func TestResolveASCache(t *testing.T) {
	// Pre-populate cache to avoid DNS lookup.
	asCache.Store("1.2.3.4", &ASInfo{ASNum: "9999", ASName: "TestASN"})

	info, err := ResolveAS("1.2.3.4")
	if err != nil {
		t.Fatalf("ResolveAS: %v", err)
	}
	if info.ASNum != "9999" {
		t.Errorf("ASNum = %q, want 9999", info.ASNum)
	}
	if info.ASName != "TestASN" {
		t.Errorf("ASName = %q, want TestASN", info.ASName)
	}
}
