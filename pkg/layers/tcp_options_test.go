package layers

import (
	"encoding/binary"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

func TestParseTCPOptions(t *testing.T) {
	// Real SYN packet options: MSS(1460), NOP, WScale(7), NOP, NOP, SACK-Perm, NOP, NOP, Timestamps(123,0)
	raw := []byte{
		0x02, 0x04, 0x05, 0xb4, // MSS: kind=2, len=4, value=1460
		0x01,                   // NOP
		0x03, 0x03, 0x07,       // WScale: kind=3, len=3, shift=7
		0x01,                   // NOP
		0x01,                   // NOP
		0x04, 0x02,             // SACK-Perm: kind=4, len=2
		0x01,                   // NOP
		0x01,                   // NOP
		0x08, 0x0a, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x00, // Timestamps: kind=8, len=10, tsval=123, tsecr=0
	}

	opts := ParseTCPOptions(raw)
	if len(opts) != 9 {
		t.Fatalf("expected 9 options, got %d", len(opts))
	}

	// MSS
	if opts[0].Kind != TCPOptMSS || opts[0].Length != 4 {
		t.Errorf("opt[0]: expected MSS(kind=2,len=4), got kind=%d,len=%d", opts[0].Kind, opts[0].Length)
	}
	mss := binary.BigEndian.Uint16(opts[0].Data)
	if mss != 1460 {
		t.Errorf("MSS value: expected 1460, got %d", mss)
	}

	// NOP
	if opts[1].Kind != TCPOptNOP {
		t.Errorf("opt[1]: expected NOP, got kind=%d", opts[1].Kind)
	}

	// WScale
	if opts[2].Kind != TCPOptWScale || opts[2].Length != 3 || opts[2].Data[0] != 7 {
		t.Errorf("opt[2]: expected WScale(shift=7), got kind=%d,len=%d", opts[2].Kind, opts[2].Length)
	}

	// SACK-Perm
	if opts[5].Kind != TCPOptSACKPerm || opts[5].Length != 2 {
		t.Errorf("opt[5]: expected SACK-Perm, got kind=%d,len=%d", opts[5].Kind, opts[5].Length)
	}

	// Timestamps
	if opts[8].Kind != TCPOptTimestamp || opts[8].Length != 10 {
		t.Errorf("opt[8]: expected Timestamps(kind=8,len=10), got kind=%d,len=%d", opts[8].Kind, opts[8].Length)
	}
	tsVal := binary.BigEndian.Uint32(opts[8].Data[0:4])
	tsEcr := binary.BigEndian.Uint32(opts[8].Data[4:8])
	if tsVal != 123 || tsEcr != 0 {
		t.Errorf("Timestamps: expected tsval=123,tsecr=0, got %d,%d", tsVal, tsEcr)
	}
}

func TestSerializeTCPOptions(t *testing.T) {
	opts := []TCPOption{
		TCPOptMSSVal(1460),
		TCPOptNOPVal(),
		TCPOptWScaleVal(7),
		TCPOptSACKPermVal(),
	}

	raw := SerializeTCPOptions(opts)

	// MSS(4) + NOP(1) + WScale(3) + SACK-Perm(2) = 10 bytes → padded to 12
	if len(raw)%4 != 0 {
		t.Fatalf("serialized options not 4-byte aligned: len=%d", len(raw))
	}
	if len(raw) != 12 {
		t.Fatalf("expected 12 bytes, got %d", len(raw))
	}

	// Verify MSS bytes
	if raw[0] != 0x02 || raw[1] != 0x04 {
		t.Errorf("MSS header: expected 02 04, got %02x %02x", raw[0], raw[1])
	}
	mss := binary.BigEndian.Uint16(raw[2:4])
	if mss != 1460 {
		t.Errorf("MSS value: expected 1460, got %d", mss)
	}
}

func TestSerializeTCPOptionsEmpty(t *testing.T) {
	raw := SerializeTCPOptions(nil)
	if raw != nil {
		t.Errorf("expected nil for empty options, got %v", raw)
	}

	raw = SerializeTCPOptions([]TCPOption{})
	if raw != nil {
		t.Errorf("expected nil for empty slice, got %v", raw)
	}
}

func TestTCPOptionsRoundTrip(t *testing.T) {
	opts := []TCPOption{
		TCPOptMSSVal(1460),
		TCPOptNOPVal(),
		TCPOptWScaleVal(7),
		TCPOptNOPVal(),
		TCPOptNOPVal(),
		TCPOptSACKPermVal(),
		TCPOptNOPVal(),
		TCPOptNOPVal(),
		TCPOptTimestampVal(12345, 67890),
	}

	raw := SerializeTCPOptions(opts)
	parsed := ParseTCPOptions(raw)

	if len(parsed) != len(opts) {
		t.Fatalf("round-trip: expected %d options, got %d", len(opts), len(parsed))
	}

	for i, got := range parsed {
		want := opts[i]
		if got.Kind != want.Kind {
			t.Errorf("opt[%d]: kind %d != %d", i, got.Kind, want.Kind)
		}
		if got.Length != want.Length {
			t.Errorf("opt[%d]: length %d != %d", i, got.Length, want.Length)
		}
	}
}

func TestTCPBuildWithOptions(t *testing.T) {
	ip := NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")
	ip.Set("proto", IPProtoTCP)
	tcp := NewTCPWith(12345, 80, TCPSyn)
	tcp.Set("options", []TCPOption{
		TCPOptMSSVal(1460),
		TCPOptNOPVal(),
		TCPOptWScaleVal(7),
		TCPOptSACKPermVal(),
	})

	pkt := packet.NewFrom(ip, tcp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// IP header = 20, TCP header = 20 + 12 (options padded) = 32
	if len(raw) != 52 {
		t.Fatalf("expected 52 bytes, got %d", len(raw))
	}

	// Verify dataofs was auto-computed: (32/4) << 4 = 0x80
	tcpStart := 20
	dataofs := raw[tcpStart+12]
	if dataofs != 0x80 {
		t.Errorf("dataofs: expected 0x80, got 0x%02x", dataofs)
	}

	// Verify checksum is non-zero (computed)
	chksum := binary.BigEndian.Uint16(raw[tcpStart+16 : tcpStart+18])
	if chksum == 0 {
		t.Error("checksum should be non-zero")
	}
}

func TestTCPBuildWithoutOptions(t *testing.T) {
	ip := NewIP()
	ip.Set("src", "10.0.0.1")
	ip.Set("dst", "10.0.0.2")
	ip.Set("proto", IPProtoTCP)
	tcp := NewTCPWith(12345, 80, TCPSyn)

	pkt := packet.NewFrom(ip, tcp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// IP header = 20, TCP header = 20 (no options)
	if len(raw) != 40 {
		t.Fatalf("expected 40 bytes, got %d", len(raw))
	}

	// Verify dataofs remains 0x50
	tcpStart := 20
	dataofs := raw[tcpStart+12]
	if dataofs != 0x50 {
		t.Errorf("dataofs: expected 0x50, got 0x%02x", dataofs)
	}
}

func TestDissectTCPWithOptions(t *testing.T) {
	// Build a real TCP SYN with options, then dissect it.
	ip := NewIP()
	ip.Set("src", "192.168.1.1")
	ip.Set("dst", "192.168.1.2")
	ip.Set("proto", IPProtoTCP)
	tcp := NewTCPWith(54321, 443, TCPSyn)
	tcp.Set("seq", uint32(0xdeadbeef))
	tcp.Set("options", []TCPOption{
		TCPOptMSSVal(1460),
		TCPOptNOPVal(),
		TCPOptWScaleVal(7),
		TCPOptNOPVal(),
		TCPOptNOPVal(),
		TCPOptSACKPermVal(),
		TCPOptNOPVal(),
		TCPOptNOPVal(),
		TCPOptTimestampVal(100, 0),
	})

	pkt := packet.NewFrom(ip, tcp)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// Dissect from IP.
	dissected, err := packet.Dissect(raw, func(_ []byte) (string, error) { return "IP", nil })
	if err != nil {
		t.Fatalf("dissect failed: %v", err)
	}

	tcpLayer := dissected.GetLayer("TCP")
	if tcpLayer == nil {
		t.Fatal("TCP layer not found after dissect")
	}

	// Verify options were parsed.
	optsVal, err := tcpLayer.Get("options")
	if err != nil {
		t.Fatalf("failed to get options: %v", err)
	}
	opts, ok := optsVal.([]TCPOption)
	if !ok {
		t.Fatalf("options is %T, expected []TCPOption", optsVal)
	}
	if len(opts) == 0 {
		t.Fatal("expected non-empty options after dissect")
	}

	// Verify MSS is present and correct.
	foundMSS := false
	for _, opt := range opts {
		if opt.Kind == TCPOptMSS && opt.Length == 4 {
			mss := binary.BigEndian.Uint16(opt.Data)
			if mss != 1460 {
				t.Errorf("MSS: expected 1460, got %d", mss)
			}
			foundMSS = true
		}
	}
	if !foundMSS {
		t.Error("MSS option not found in dissected packet")
	}

	// Verify seq survived round-trip.
	seqVal, _ := tcpLayer.Get("seq")
	if seqVal.(uint32) != 0xdeadbeef {
		t.Errorf("seq: expected 0xdeadbeef, got 0x%08x", seqVal)
	}
}

func TestTCPOptHelpers(t *testing.T) {
	mss := TCPOptMSSVal(1460)
	if mss.Kind != TCPOptMSS || mss.Length != 4 {
		t.Errorf("MSS helper: kind=%d,len=%d", mss.Kind, mss.Length)
	}

	ws := TCPOptWScaleVal(14)
	if ws.Kind != TCPOptWScale || ws.Length != 3 || ws.Data[0] != 14 {
		t.Errorf("WScale helper: kind=%d,len=%d,data=%v", ws.Kind, ws.Length, ws.Data)
	}

	sp := TCPOptSACKPermVal()
	if sp.Kind != TCPOptSACKPerm || sp.Length != 2 || sp.Data != nil {
		t.Errorf("SACKPerm helper: kind=%d,len=%d,data=%v", sp.Kind, sp.Length, sp.Data)
	}

	ts := TCPOptTimestampVal(100, 200)
	if ts.Kind != TCPOptTimestamp || ts.Length != 10 {
		t.Errorf("Timestamp helper: kind=%d,len=%d", ts.Kind, ts.Length)
	}
	tsVal := binary.BigEndian.Uint32(ts.Data[0:4])
	tsEcr := binary.BigEndian.Uint32(ts.Data[4:8])
	if tsVal != 100 || tsEcr != 200 {
		t.Errorf("Timestamp values: %d, %d", tsVal, tsEcr)
	}
}

func TestParseTCPOptionsEOL(t *testing.T) {
	// EOL should terminate parsing.
	raw := []byte{
		0x01,       // NOP
		0x00,       // EOL
		0x02, 0x04, 0x05, 0xb4, // MSS (should not be parsed)
	}
	opts := ParseTCPOptions(raw)
	if len(opts) != 1 {
		t.Fatalf("expected 1 option before EOL, got %d", len(opts))
	}
	if opts[0].Kind != TCPOptNOP {
		t.Errorf("expected NOP, got kind=%d", opts[0].Kind)
	}
}

func TestParseTCPOptionsTruncated(t *testing.T) {
	// Truncated option (length says 4 but only 3 bytes remain).
	raw := []byte{0x02, 0x04, 0x05}
	opts := ParseTCPOptions(raw)
	if len(opts) != 0 {
		t.Errorf("expected 0 options for truncated data, got %d", len(opts))
	}
}
