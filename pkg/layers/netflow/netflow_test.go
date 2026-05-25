package netflow

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

func buildTestPkt(nfLayer *packet.Layer, rawBytes []byte) ([]byte, error) {
	eth := packet.NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", nil),
		fields.NewMACField("src", nil),
		fields.NewShortField("type", 0),
	})
	eth.Set("dst", "ff:ff:ff:ff:ff:ff")
	eth.Set("src", "00:11:22:33:44:55")
	eth.Set("type", uint16(0x0800))

	ip := packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45),
		fields.NewByteField("tos", 0),
		fields.NewShortField("len", 20),
		fields.NewShortField("id", 0),
		fields.NewShortField("frag", 0),
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 17),
		fields.NewShortField("chksum", 0),
		fields.NewIPField("src", nil),
		fields.NewIPField("dst", nil),
	})
	ip.Set("src", "192.168.1.1")
	ip.Set("dst", "8.8.8.8")

	udp := packet.NewLayer("UDP", []fields.Field{
		fields.NewShortField("sport", 0),
		fields.NewShortField("dport", 0),
		fields.NewShortField("len", 8),
		fields.NewShortField("chksum", 0),
	})
	udp.Set("sport", uint16(12345))
	udp.Set("dport", uint16(2055))

	raw := packet.NewLayer("Raw", []fields.Field{
		fields.NewStrField("load", ""),
	})
	raw.Set("load", rawBytes)

	pkt := eth.Over(ip)
	pkt.Push(udp)
	pkt.Push(nfLayer)
	pkt.Push(raw)
	return pkt.Build()
}

func TestNetflowV5BuildDissect(t *testing.T) {
	nf := NewNetflowV5()
	nf.Set("count", uint16(1))
	nf.Set("sys_uptime", uint32(1000))
	nf.Set("unix_secs", uint32(1700000000))
	nf.Set("flow_sequence", uint32(42))
	nf.Set("engine_type", uint8(0))
	nf.Set("engine_id", uint8(1))

	rec := NetflowV5Record{
		SrcAddr: net.ParseIP("10.0.0.1").To4(),
		DstAddr: net.ParseIP("10.0.0.2").To4(),
		NextHop: net.ParseIP("10.0.0.254").To4(),
		Input:   1,
		Output:  2,
		Packets: 100,
		Bytes:   5000,
		First:   500,
		Last:    600,
		SrcPort: 12345,
		DstPort: 80,
		Proto:   6,
		Tos:     0,
		Flags:   0x18,
		SrcAS:   65001,
		DstAS:   65002,
	}

	got, err := buildTestPkt(nf, PackNetflowV5Record(rec))
	if err != nil {
		t.Fatal(err)
	}

	udpEnd := 42
	if binary.BigEndian.Uint16(got[udpEnd:]) != NetflowV5Version {
		t.Errorf("version = %d, want %d", binary.BigEndian.Uint16(got[udpEnd:]), NetflowV5Version)
	}
	if binary.BigEndian.Uint16(got[udpEnd+2:]) != 1 {
		t.Errorf("count = %d, want 1", binary.BigEndian.Uint16(got[udpEnd+2:]))
	}

	recStart := udpEnd + NetflowV5HeaderLen
	parsed, err := UnpackNetflowV5Record(got[recStart:])
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.SrcAddr.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("SrcAddr = %v, want 10.0.0.1", parsed.SrcAddr)
	}
	if parsed.Packets != 100 {
		t.Errorf("Packets = %d, want 100", parsed.Packets)
	}
	if parsed.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", parsed.SrcPort)
	}
	if parsed.Proto != 6 {
		t.Errorf("Proto = %d, want 6", parsed.Proto)
	}
	if parsed.SrcAS != 65001 {
		t.Errorf("SrcAS = %d, want 65001", parsed.SrcAS)
	}
}

func TestNetflowV5RecordRoundTrip(t *testing.T) {
	rec := NetflowV5Record{
		SrcAddr: net.ParseIP("192.168.1.100").To4(),
		DstAddr: net.ParseIP("172.16.0.1").To4(),
		NextHop: net.ParseIP("0.0.0.0").To4(),
		Input:   3,
		Output:  4,
		Packets: 999,
		Bytes:   64000,
		First:   100,
		Last:    200,
		SrcPort: 8080,
		DstPort: 443,
		Proto:   17,
		Tos:     128,
		Flags:   0,
		SrcAS:   100,
		DstAS:   200,
		SrcMask: 24,
		DstMask: 16,
	}

	b := PackNetflowV5Record(rec)
	if len(b) != NetflowV5RecordLen {
		t.Fatalf("PackNetflowV5Record len = %d, want %d", len(b), NetflowV5RecordLen)
	}

	parsed, err := UnpackNetflowV5Record(b)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.SrcAddr.Equal(rec.SrcAddr) {
		t.Errorf("SrcAddr mismatch")
	}
	if parsed.Packets != rec.Packets {
		t.Errorf("Packets = %d, want %d", parsed.Packets, rec.Packets)
	}
	if parsed.SrcMask != rec.SrcMask {
		t.Errorf("SrcMask = %d, want %d", parsed.SrcMask, rec.SrcMask)
	}
}

func TestParseNetflowV5Records(t *testing.T) {
	rec1 := NetflowV5Record{SrcAddr: net.ParseIP("10.0.0.1").To4(), DstAddr: net.ParseIP("10.0.0.2").To4(), Packets: 1}
	rec2 := NetflowV5Record{SrcAddr: net.ParseIP("10.0.0.3").To4(), DstAddr: net.ParseIP("10.0.0.4").To4(), Packets: 2}

	b := PackNetflowV5Records([]NetflowV5Record{rec1, rec2})
	records, err := ParseNetflowV5Records(b, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Packets != 1 {
		t.Errorf("record[0].Packets = %d, want 1", records[0].Packets)
	}
	if records[1].Packets != 2 {
		t.Errorf("record[1].Packets = %d, want 2", records[1].Packets)
	}
}

func TestNetflowV9TemplateRoundTrip(t *testing.T) {
	tmpl := V9Template{
		TemplateID: 256, FieldCount: 3,
		Fields: []V9TemplateField{
			{Type: 1, Len: 4},
			{Type: 2, Len: 4},
			{Type: 7, Len: 2},
		},
	}
	b := PackV9Template(tmpl)
	parsed, err := ParseV9Template(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TemplateID != 256 {
		t.Errorf("TemplateID = %d, want 256", parsed.TemplateID)
	}
	if len(parsed.Fields) != 3 {
		t.Fatalf("got %d fields, want 3", len(parsed.Fields))
	}
	if parsed.Fields[0].Type != 1 || parsed.Fields[0].Len != 4 {
		t.Errorf("field[0] = %+v, want Type=1 Len=4", parsed.Fields[0])
	}
}

func TestNetflowV9FlowSets(t *testing.T) {
	fs1 := V9FlowSet{ID: 0, Data: PackV9Template(V9Template{
		TemplateID: 256, FieldCount: 2,
		Fields: []V9TemplateField{{Type: 1, Len: 4}, {Type: 2, Len: 4}},
	})}
	fs2 := V9FlowSet{ID: 256, Data: []byte{0, 0, 0, 10, 0, 0, 0, 20}}

	var payload []byte
	payload = append(payload, PackV9FlowSet(fs1)...)
	payload = append(payload, PackV9FlowSet(fs2)...)

	sets, err := ParseV9FlowSets(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 {
		t.Fatalf("got %d sets, want 2", len(sets))
	}
	if sets[0].ID != 0 {
		t.Errorf("set[0].ID = %d, want 0", sets[0].ID)
	}
	if sets[1].ID != 256 {
		t.Errorf("set[1].ID = %d, want 256", sets[1].ID)
	}
}

func TestV9TemplateCache(t *testing.T) {
	cache := NewTemplateCache()
	tmpl := V9Template{TemplateID: 256, FieldCount: 1, Fields: []V9TemplateField{{Type: 1, Len: 4}}}
	cache.Store(0, tmpl)

	got, ok := cache.Get(uint32(0), 256)
	if !ok {
		t.Fatal("template not found")
	}
	if got.TemplateID != 256 {
		t.Errorf("TemplateID = %d, want 256", got.TemplateID)
	}
}

func TestV9DecodeDataFlowSet(t *testing.T) {
	tmpl := V9Template{
		TemplateID: 256, FieldCount: 2,
		Fields: []V9TemplateField{{Type: 1, Len: 4}, {Type: 2, Len: 4}},
	}
	data := []byte{
		0, 0, 0, 100, 0, 0, 0, 5,
		0, 0, 1, 44, 0, 0, 0, 10,
	}
	fs := V9FlowSet{ID: 256, Data: data}
	records, err := DecodeDataFlowSet(fs, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0][0].(uint32) != 100 {
		t.Errorf("record[0][0] = %v, want 100", records[0][0])
	}
	if records[1][0].(uint32) != 300 {
		t.Errorf("record[1][0] = %v, want 300", records[1][0])
	}
}

func TestIPFIXTemplateRoundTrip(t *testing.T) {
	tmpl := IPFIXTemplate{
		TemplateID: 256, FieldCount: 3,
		Fields: []IPFIXTemplateField{
			{Type: 1, Len: 8},
			{Type: 2, Len: 4},
			{Type: 100, Len: 4, Pen: 12345},
		},
	}
	b := PackIPFIXTemplate(tmpl)
	parsed, err := ParseIPFIXTemplate(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TemplateID != 256 {
		t.Errorf("TemplateID = %d, want 256", parsed.TemplateID)
	}
	if len(parsed.Fields) != 3 {
		t.Fatalf("got %d fields, want 3", len(parsed.Fields))
	}
	if parsed.Fields[2].Pen != 12345 {
		t.Errorf("field[2].Pen = %d, want 12345", parsed.Fields[2].Pen)
	}
	if parsed.Fields[2].Type != 100 {
		t.Errorf("field[2].Type = %d, want 100", parsed.Fields[2].Type)
	}
}

func TestIPFIXSetParsing(t *testing.T) {
	s1 := IPFIXSet{ID: 2, Data: PackIPFIXTemplate(IPFIXTemplate{
		TemplateID: 258, FieldCount: 1,
		Fields: []IPFIXTemplateField{{Type: 1, Len: 8}},
	})}
	s2 := IPFIXSet{ID: 258, Data: make([]byte, 8)}

	var payload []byte
	payload = append(payload, PackIPFIXSet(s1)...)
	payload = append(payload, PackIPFIXSet(s2)...)

	sets, err := ParseIPFIXSets(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 {
		t.Fatalf("got %d sets, want 2", len(sets))
	}
	if sets[0].ID != 2 {
		t.Errorf("set[0].ID = %d, want 2", sets[0].ID)
	}
	if sets[1].ID != 258 {
		t.Errorf("set[1].ID = %d, want 258", sets[1].ID)
	}
}

func TestIPFIXVariableLength(t *testing.T) {
	tmpl := IPFIXTemplate{
		TemplateID: 256, FieldCount: 2,
		Fields: []IPFIXTemplateField{
			{Type: 1, Len: 4},
			{Type: 100, Len: 65535},
		},
	}
	data := []byte{
		0, 0, 0, 42,
		5, 'h', 'e', 'l', 'l', 'o',
	}
	s := IPFIXSet{ID: 256, Data: data}
	records, err := DecodeIPFIXData(s, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0][0].(uint32) != 42 {
		t.Errorf("field[0] = %v, want 42", records[0][0])
	}
	if string(records[0][1].([]byte)) != "hello" {
		t.Errorf("field[1] = %v, want 'hello'", records[0][1])
	}
}

func TestIPFIXVariableLengthLong(t *testing.T) {
	tmpl := IPFIXTemplate{
		TemplateID: 256, FieldCount: 1,
		Fields: []IPFIXTemplateField{{Type: 100, Len: 65535}},
	}
	longStr := make([]byte, 256)
	for i := range longStr {
		longStr[i] = 'A'
	}
	data := []byte{255, 1, 0}
	data = append(data, longStr...)

	s := IPFIXSet{ID: 256, Data: data}
	records, err := DecodeIPFIXData(s, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if len(records[0][0].([]byte)) != 256 {
		t.Errorf("field len = %d, want 256", len(records[0][0].([]byte)))
	}
}

func TestNetflowV9BuildDissect(t *testing.T) {
	nf := NewNetflowV9()
	nf.Set("count", uint16(1))
	nf.Set("sys_uptime", uint32(1000))
	nf.Set("unix_secs", uint32(1700000000))
	nf.Set("sequence", uint32(1))
	nf.Set("source_id", uint32(0x12345678))

	tmpl := V9Template{
		TemplateID: 256, FieldCount: 2,
		Fields: []V9TemplateField{{Type: 1, Len: 4}, {Type: 2, Len: 4}},
	}
	flowData := []byte{0, 0, 0, 100, 0, 0, 0, 5}
	var payload []byte
	payload = append(payload, PackV9FlowSet(V9FlowSet{ID: 0, Data: PackV9Template(tmpl)})...)
	payload = append(payload, PackV9FlowSet(V9FlowSet{ID: 256, Data: flowData})...)

	got, err := buildTestPkt(nf, payload)
	if err != nil {
		t.Fatal(err)
	}

	udpEnd := 42
	ver := binary.BigEndian.Uint16(got[udpEnd:])
	if ver != NetflowV9Version {
		t.Errorf("version = %d, want %d", ver, NetflowV9Version)
	}

	sets, err := ParseV9FlowSets(got[udpEnd+NetflowV9HeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 {
		t.Fatalf("got %d sets, want 2", len(sets))
	}

	parsedTmpl, err := ParseV9Template(sets[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if parsedTmpl.TemplateID != 256 {
		t.Errorf("template ID = %d, want 256", parsedTmpl.TemplateID)
	}
}

func TestIPFIXBuildDissect(t *testing.T) {
	ipfix := NewIPFIX()
	ipfix.Set("export_time", uint32(1700000000))
	ipfix.Set("sequence", uint32(1))
	ipfix.Set("observation_domain_id", uint32(0xABCD))

	tmpl := IPFIXTemplate{
		TemplateID: 256, FieldCount: 2,
		Fields: []IPFIXTemplateField{{Type: 1, Len: 8}, {Type: 2, Len: 4}},
	}
	var payload []byte
	payload = append(payload, PackIPFIXSet(IPFIXSet{ID: 2, Data: PackIPFIXTemplate(tmpl)})...)

	got, err := buildTestPkt(ipfix, payload)
	if err != nil {
		t.Fatal(err)
	}

	udpEnd := 42
	ver := binary.BigEndian.Uint16(got[udpEnd:])
	if ver != IPFIXVersion {
		t.Errorf("version = %d, want %d", ver, IPFIXVersion)
	}

	sets, err := ParseIPFIXSets(got[udpEnd+IPFIXHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 {
		t.Fatalf("got %d sets, want 1", len(sets))
	}

	parsedTmpl, err := ParseIPFIXTemplate(sets[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if parsedTmpl.TemplateID != 256 {
		t.Errorf("template ID = %d, want 256", parsedTmpl.TemplateID)
	}
}

func TestDetectNetflowVersion(t *testing.T) {
	tests := []struct {
		data []byte
		want string
	}{
		{[]byte{0, 5}, "NetflowV5"},
		{[]byte{0, 9}, "NetflowV9"},
		{[]byte{0, 10}, "IPFIX"},
		{[]byte{0, 1}, ""},
		{[]byte{}, ""},
	}
	for _, tt := range tests {
		got := DetectNetflowVersion(tt.data)
		if got != tt.want {
			t.Errorf("DetectNetflowVersion(%v) = %q, want %q", tt.data, got, tt.want)
		}
	}
}
