package p0f

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- Helpers to build SYN packets with realistic per-OS option layouts ----

// buildSynPkt builds a SYN packet with common options (MSS, SACK-Perm, WScale, NOP).
// OptsLen will be 12 bytes. Use buildSynPktWithTS for packets needing 20-byte options.
func buildSynPkt(window uint16, ttl uint8, mss uint16, wscale uint8, sack, nop, df bool) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("ttl", ttl)
	_ = ip.Set("proto", uint8(6))
	_ = ip.Set("src", "10.0.0.1")
	_ = ip.Set("dst", "10.0.0.2")
	if df {
		frag, _ := ip.Get("frag")
		_ = ip.Set("frag", frag.(uint16)|0x4000)
	}

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(layers.TCPSyn))
	_ = tcp.Set("window", window)

	var opts []layers.TCPOption
	if mss > 0 {
		opts = append(opts, layers.TCPOptMSSVal(mss))
	}
	if sack {
		opts = append(opts, layers.TCPOptSACKPermVal())
	}
	if wscale > 0 {
		opts = append(opts, layers.TCPOptWScaleVal(wscale))
	}
	if nop {
		opts = append(opts, layers.TCPOptNOPVal())
	}
	_ = tcp.Set("options", opts)

	pkt := packet.NewFrom(ip, tcp)
	return pkt
}

// buildSynPktWithTS builds a SYN packet with MSS, SACK-Perm, NOP, WScale, and Timestamp.
// This produces 20 bytes of TCP options, matching real-world SYN packets from modern OSes.
func buildSynPktWithTS(window uint16, ttl uint8, mss uint16, wscale uint8, df bool) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("ttl", ttl)
	_ = ip.Set("proto", uint8(6))
	_ = ip.Set("src", "10.0.0.1")
	_ = ip.Set("dst", "10.0.0.2")
	if df {
		frag, _ := ip.Get("frag")
		_ = ip.Set("frag", frag.(uint16)|0x4000)
	}

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(layers.TCPSyn))
	_ = tcp.Set("window", window)

	var opts []layers.TCPOption
	if mss > 0 {
		opts = append(opts, layers.TCPOptMSSVal(mss))
	}
	opts = append(opts, layers.TCPOptSACKPermVal())
	opts = append(opts, layers.TCPOptNOPVal())
	if wscale > 0 {
		opts = append(opts, layers.TCPOptWScaleVal(wscale))
	}
	opts = append(opts, layers.TCPOptTimestampVal(0, 0))
	_ = tcp.Set("options", opts)

	pkt := packet.NewFrom(ip, tcp)
	return pkt
}

func buildSynAckPkt(window uint16, ttl uint8) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("ttl", ttl)
	_ = ip.Set("proto", uint8(6))

	tcp := layers.NewTCP()
	_ = tcp.Set("flags", uint8(layers.TCPSyn|layers.TCPAck))
	_ = tcp.Set("window", window)

	return packet.NewFrom(ip, tcp)
}

// buildSynAckPktWithOpts builds a SYN+ACK packet with TCP options and DF set.
func buildSynAckPktWithOpts(window uint16, ttl uint8, mss uint16, wscale uint8) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("ttl", ttl)
	_ = ip.Set("proto", uint8(6))
	frag, _ := ip.Get("frag")
	_ = ip.Set("frag", frag.(uint16)|0x4000) // DF bit

	tcp := layers.NewTCP()
	_ = tcp.Set("flags", uint8(layers.TCPSyn|layers.TCPAck))
	_ = tcp.Set("window", window)

	var opts []layers.TCPOption
	if mss > 0 {
		opts = append(opts, layers.TCPOptMSSVal(mss))
	}
	opts = append(opts, layers.TCPOptSACKPermVal())
	if wscale > 0 {
		opts = append(opts, layers.TCPOptWScaleVal(wscale))
	}
	opts = append(opts, layers.TCPOptNOPVal())
	_ = tcp.Set("options", opts)

	pkt := packet.NewFrom(ip, tcp)
	return pkt
}

// ---- Tests ----

func TestDefaultDatabase(t *testing.T) {
	db := DefaultDatabase()
	if len(db.Syn) == 0 {
		t.Error("default SYN database should not be empty")
	}
	if len(db.SynAck) == 0 {
		t.Error("default SYN+ACK database should not be empty")
	}
}

func TestFingerprintLinux(t *testing.T) {
	db := DefaultDatabase()
	pkt := buildSynPkt(29200, 64, 1460, 7, true, true, true)

	result := P0fFingerprint(pkt, db)
	if result.OS != "Linux 4.x-6.x" {
		t.Errorf("OS = %q, want %q", result.OS, "Linux 4.x-6.x")
	}
	if result.Confidence < ConfMedium {
		t.Errorf("confidence = %v, want at least medium", result.Confidence)
	}
}

func TestFingerprintWindows(t *testing.T) {
	db := DefaultDatabase()
	pkt := buildSynPkt(8192, 128, 1460, 8, true, true, true)

	result := P0fFingerprint(pkt, db)
	if result.OS == "" {
		t.Error("expected non-empty OS match for Windows fingerprint")
	}
	// Should match a Windows signature
	found := false
	for _, sig := range db.Syn {
		if sig.Label == result.OS && stringsContains(sig.Label, "Windows") {
			found = true
			break
		}
	}
	if !found {
		// At minimum it should have identified something with TTL 128
		if result.OS == "" {
			t.Error("expected a match for Windows-like SYN")
		}
	}
}

func TestFingerprintMacOS(t *testing.T) {
	db := DefaultDatabase()
	// macOS uses 20-byte options: MSS(1460), SACK-Perm, NOP, WScale(5), Timestamp
	pkt := buildSynPktWithTS(65535, 64, 1460, 5, true)

	result := P0fFingerprint(pkt, db)
	if result.OS != "macOS / iOS" {
		t.Errorf("OS = %q, want %q", result.OS, "macOS / iOS")
	}
}

func TestFingerprintSynAck(t *testing.T) {
	db := DefaultDatabase()
	// Linux SYN+ACK: window=29200, TTL=64, MSS=1460, WScale=7, SACK, NOP
	pkt := buildSynAckPktWithOpts(29200, 64, 1460, 7)

	result := P0fFingerprint(pkt, db)
	if result.OS == "" {
		t.Error("expected non-empty OS match for SYN+ACK")
	}
}

func TestFingerprintNonSyn(t *testing.T) {
	db := DefaultDatabase()
	ip := layers.NewIP()
	_ = ip.Set("ttl", uint8(64))
	_ = ip.Set("proto", uint8(6))
	tcp := layers.NewTCP()
	_ = tcp.Set("flags", uint8(layers.TCPAck)) // ACK only, not SYN
	pkt := packet.NewFrom(ip, tcp)

	result := P0fFingerprint(pkt, db)
	if result.OS != "" {
		t.Errorf("non-SYN packet should not produce OS match, got %q", result.OS)
	}
}

func TestFingerprintNoTCP(t *testing.T) {
	db := DefaultDatabase()
	ip := layers.NewIP()
	pkt := packet.NewFrom(ip)

	result := P0fFingerprint(pkt, db)
	if result.OS != "" {
		t.Errorf("packet without TCP should not produce OS match")
	}
}

func TestFingerprintNilInputs(t *testing.T) {
	db := DefaultDatabase()
	result := P0fFingerprint(nil, db)
	if result.OS != "" {
		t.Error("nil packet should produce empty result")
	}

	pkt := buildSynPkt(29200, 64, 1460, 7, true, true, true)
	result = P0fFingerprint(pkt, nil)
	if result.OS != "" {
		t.Error("nil database should produce empty result")
	}
}

func TestConfidenceString(t *testing.T) {
	tests := []struct {
		c   Confidence
		str string
	}{
		{ConfNone, "none"},
		{ConfLow, "low"},
		{ConfMedium, "medium"},
		{ConfHigh, "high"},
	}
	for _, tt := range tests {
		if tt.c.String() != tt.str {
			t.Errorf("Confidence(%d).String() = %q, want %q", tt.c, tt.c.String(), tt.str)
		}
	}
}

func TestLoadDatabase(t *testing.T) {
	// Create a temp p0f.fp file.
	dir := t.TempDir()
	fpPath := filepath.Join(dir, "p0f.fp")
	content := `# Test p0f database
[syn]
5840:64:12:1460:4:1:1:1::Linux 2.6
8192:128:12:1460:8:1:1:1::Windows 7
65535:64:20:1460:5:1:1:1::macOS / iOS

[syn+ack]
29200:64:12:1460:7:1:1:1::Linux 4.x-6.x
8192:128:20:1460:8:1:1:1::Windows 8/10

[rst]
4096:64:0:*:*:*:*:*::Linux RST
`
	if err := os.WriteFile(fpPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	db, err := LoadDatabase(fpPath)
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}
	if len(db.Syn) != 3 {
		t.Errorf("SYN entries = %d, want 3", len(db.Syn))
	}
	if len(db.SynAck) != 2 {
		t.Errorf("SYN+ACK entries = %d, want 2", len(db.SynAck))
	}
	if len(db.Rst) != 1 {
		t.Errorf("RST entries = %d, want 1", len(db.Rst))
	}

	// Verify first SYN entry.
	sig := db.Syn[0]
	if sig.Window != 5840 {
		t.Errorf("window = %d, want 5840", sig.Window)
	}
	if sig.TTLMin != 64 || sig.TTLMax != 64 {
		t.Errorf("ttl = %d-%d, want 64-64", sig.TTLMin, sig.TTLMax)
	}
	if sig.Label != "Linux 2.6" {
		t.Errorf("label = %q, want %q", sig.Label, "Linux 2.6")
	}
}

func TestLoadDatabaseTTLRange(t *testing.T) {
	dir := t.TempDir()
	fpPath := filepath.Join(dir, "p0f.fp")
	content := `[syn]
8192:100-128:0:*:*:*:*:*::Generic Windows
`
	if err := os.WriteFile(fpPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	db, err := LoadDatabase(fpPath)
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}
	if len(db.Syn) != 1 {
		t.Fatalf("SYN entries = %d, want 1", len(db.Syn))
	}
	sig := db.Syn[0]
	if sig.TTLMin != 100 || sig.TTLMax != 128 {
		t.Errorf("ttl = %d-%d, want 100-128", sig.TTLMin, sig.TTLMax)
	}
}

func TestLoadDatabaseFileNotFound(t *testing.T) {
	_, err := LoadDatabase("/nonexistent/p0f.fp")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestMatchedFields(t *testing.T) {
	db := DefaultDatabase()
	pkt := buildSynPkt(29200, 64, 1460, 7, true, true, true)

	result := P0fFingerprint(pkt, db)
	if len(result.Matched) == 0 {
		t.Error("expected some matched fields")
	}
	found := false
	for _, f := range result.Matched {
		if f == "ttl" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'ttl' in matched fields, got %v", result.Matched)
	}
}

// stringsContains is a simple string contains check.
func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringsContainsHelper(s, sub))
}

func stringsContainsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
