package dns

import (
	"bytes"
	"testing"

	"github.com/smallnest/goscapy/pkg/packet"
)

func TestEncodeName(t *testing.T) {
	got := EncodeName("www.example.com")
	want := []byte{
		3, 'w', 'w', 'w',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeName:\n got %#v\nwant %#v", got, want)
	}
}

func TestEncodeNameRoot(t *testing.T) {
	got := EncodeName(".")
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("EncodeName('.') = %#v, want [0]", got)
	}
}

func TestEncodeNameEmpty(t *testing.T) {
	got := EncodeName("")
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("EncodeName('') = %#v, want [0]", got)
	}
}

func TestDecodeName(t *testing.T) {
	raw := []byte{
		3, 'w', 'w', 'w',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	name, consumed, err := DecodeName(raw, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "www.example.com" {
		t.Errorf("name = %q, want \"www.example.com\"", name)
	}
	if consumed != len(raw) {
		t.Errorf("consumed = %d, want %d", consumed, len(raw))
	}
}

func TestDecodeNameRoot(t *testing.T) {
	name, consumed, err := DecodeName([]byte{0}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "." {
		t.Errorf("name = %q, want \".\"", name)
	}
	if consumed != 1 {
		t.Errorf("consumed = %d, want 1", consumed)
	}
}

func TestDecodeNameCompression(t *testing.T) {
	// Full message: [header 12 bytes] + "example.com" + 0 + remaining data
	// Offset 0x0C = 12 points to the start of "example.com"
	msg := []byte{
		// Header placeholder
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// "example.com" labels
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		// Now a pointer to 0x0C ("example.com")
		0xC0, 0x0C,
		// More data
		0x00, 0x01, 0x00, 0x01,
	}

	// Decode the name at the pointer location (offset 0x0C + 13 = 25)
	name, consumed, err := DecodeName(msg, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "example.com" {
		t.Errorf("name = %q, want \"example.com\"", name)
	}
	// The pointer itself is 2 bytes.
	if consumed != 2 {
		t.Errorf("consumed = %d, want 2", consumed)
	}
}

func TestDecodeNameCompressionLoop(t *testing.T) {
	// Create a self-referencing pointer.
	msg := []byte{0xC0, 0x00} // points to itself
	_, _, err := DecodeName(msg, 0, 0)
	if err == nil {
		t.Fatal("expected error for compression loop")
	}
}

func TestNewDNSDefaults(t *testing.T) {
	layer := NewDNS()

	id, _ := layer.Get("id")
	if id.(uint16) != 0 {
		t.Errorf("id = %d, want 0", id)
	}
	flags, _ := layer.Get("flags")
	if flags.(uint16) != 0x0100 {
		t.Errorf("flags = %#x, want 0x0100", flags)
	}
}

func TestDNSSerializeHeader(t *testing.T) {
	layer := NewDNS()
	layer.Set("id", uint16(0x1234))
	layer.Set("flags", uint16(0x0100))
	layer.Set("qdcount", uint16(1))
	layer.Set("data", []byte{})

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 12 {
		t.Fatalf("len = %d, want 12", len(got))
	}
	// ID = 0x1234
	if got[0] != 0x12 || got[1] != 0x34 {
		t.Errorf("ID = %#x %#x", got[0], got[1])
	}
	// Flags = 0x0100
	if got[2] != 0x01 || got[3] != 0x00 {
		t.Errorf("Flags = %#x %#x", got[2], got[3])
	}
	// QDCount = 1
	if got[4] != 0x00 || got[5] != 0x01 {
		t.Errorf("QDCount = %#x %#x", got[4], got[5])
	}
}

func TestDNSParse(t *testing.T) {
		raw := []byte{
			0x12, 0x34, // ID
			0x81, 0x80, // Flags: QR=1, RD=1, RA=1
			0x00, 0x01, // QDCount = 1
			0x00, 0x01, // ANCount = 1
			0x00, 0x00, // NSCount
			0x00, 0x00, // ARCount
		}
	layer := NewDNS()
	consumed, err := layer.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed = %d, want %d", consumed, len(raw))
	}

	id, _ := layer.Get("id")
	if id.(uint16) != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	flags, _ := layer.Get("flags")
	if flags.(uint16) != 0x8180 {
		t.Errorf("flags = %#x", flags)
	}
}

func TestDNSQuery(t *testing.T) {
	// Build DNS query for "example.com" A record.
	q := DNSQuestion{Name: "example.com", Type: QtypeA, Class: QclassIN}
	body := BuildDNSMessage([]DNSQuestion{q}, nil, nil, nil)

	layer := NewDNS()
	layer.Set("id", uint16(0x1234))
	layer.Set("qdcount", uint16(1))
	layer.Set("data", body)

	raw, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Expected: header + encoded question.
	wantHeader := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	wantQ := BuildQuestion(q)
	want := append(wantHeader, wantQ...)

	if !bytes.Equal(raw, want) {
		t.Errorf("DNS query mismatch:\n got %#v\nwant %#v", raw, want)
	}
}

func TestDNSQueryParse(t *testing.T) {
	q := DNSQuestion{Name: "example.com", Type: QtypeA, Class: QclassIN}
	body := BuildDNSMessage([]DNSQuestion{q}, nil, nil, nil)

	layer := NewDNS()
	layer.Set("id", uint16(0x1234))
	layer.Set("qdcount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()

	// Parse it back.
	layer2 := NewDNS()
	consumed, err := layer2.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed = %d, want %d", consumed, len(raw))
	}

	qs, err := GetQuestions(layer2)
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) != 1 {
		t.Fatalf("got %d questions, want 1", len(qs))
	}
	if qs[0].Name != "example.com" {
		t.Errorf("name = %q", qs[0].Name)
	}
	if qs[0].Type != QtypeA {
		t.Errorf("type = %d", qs[0].Type)
	}
	if qs[0].Class != QclassIN {
		t.Errorf("class = %d", qs[0].Class)
	}
}

func TestDNSResponse(t *testing.T) {
	q := DNSQuestion{Name: "example.com", Type: QtypeA, Class: QclassIN}
	rr := DNSRR{
		Name:  "example.com",
		Type:  QtypeA,
		Class: QclassIN,
		TTL:   300,
		RData: BuildARData("93.184.216.34"),
	}
	rr.RDLength = uint16(len(rr.RData))

	body := BuildDNSMessage([]DNSQuestion{q}, []DNSRR{rr}, nil, nil)

	layer := NewDNS()
	layer.Set("id", uint16(0x1234))
	layer.Set("flags", uint16(0x8180)) // QR=1, RD=1, RA=1
	layer.Set("qdcount", uint16(1))
	layer.Set("ancount", uint16(1))
	layer.Set("data", body)

	raw, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Parse back and verify.
	layer2 := NewDNS()
	_, err = layer2.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}

	qs, _ := GetQuestions(layer2)
	if len(qs) != 1 || qs[0].Name != "example.com" {
		t.Error("question mismatch")
	}

	answers, err := GetAnswers(layer2)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("got %d answers, want 1", len(answers))
	}
	if ParseARData(answers[0].RData) != "93.184.216.34" {
		t.Errorf("A = %q", ParseARData(answers[0].RData))
	}
	if answers[0].TTL != 300 {
		t.Errorf("TTL = %d", answers[0].TTL)
	}
}

func TestDNSAAAARecord(t *testing.T) {
	rr := DNSRR{
		Name:  "example.com",
		Type:  QtypeAAAA,
		Class: QclassIN,
		TTL:   300,
		RData: BuildAAAARData("2001:db8::1"),
	}
	rr.RDLength = uint16(len(rr.RData))

	body := BuildDNSMessage(nil, []DNSRR{rr}, nil, nil)

	layer := NewDNS()
	layer.Set("ancount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()
	layer2 := NewDNS()
	layer2.ParseFields(raw)

	answers, _ := GetAnswers(layer2)
	if len(answers) != 1 {
		t.Fatal("no answer")
	}
	ip := ParseAAAARData(answers[0].RData)
	if ip != "2001:db8:0:0:0:0:0:1" {
		t.Errorf("AAAA = %q", ip)
	}
}

func TestDNSCNAME(t *testing.T) {
	q := DNSQuestion{Name: "www.example.com", Type: QtypeA, Class: QclassIN}
	rr := DNSRR{
		Name:  "www.example.com",
		Type:  QtypeCNAME,
		Class: QclassIN,
		TTL:   600,
		RData: EncodeName("example.com"),
	}
	rr.RDLength = uint16(len(rr.RData))

	body := BuildDNSMessage([]DNSQuestion{q}, []DNSRR{rr}, nil, nil)

	layer := NewDNS()
	layer.Set("qdcount", uint16(1))
	layer.Set("ancount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()
	layer2 := NewDNS()
	layer2.ParseFields(raw)

	answers, _ := GetAnswers(layer2)
	if len(answers) != 1 {
		t.Fatal("no answer")
	}
	name, err := ParseCNAMERData(answers[0].RData, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "example.com" {
		t.Errorf("CNAME = %q", name)
	}
}

func TestDNSMX(t *testing.T) {
	rr := DNSRR{
		Name:  "example.com",
		Type:  QtypeMX,
		Class: QclassIN,
		TTL:   600,
		RData: BuildMXData(10, "mail.example.com"),
	}
	rr.RDLength = uint16(len(rr.RData))

	body := BuildDNSMessage(nil, []DNSRR{rr}, nil, nil)

	layer := NewDNS()
	layer.Set("ancount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()

	// Parse back.
	layer2 := NewDNS()
	layer2.ParseFields(raw)
	answers, _ := GetAnswers(layer2)
	if len(answers) != 1 {
		t.Fatal("no answer")
	}
	if len(answers[0].RData) < 2 {
		t.Fatal("RDATA too short")
	}
	pref := uint16(answers[0].RData[0])<<8 | uint16(answers[0].RData[1])
	if pref != 10 {
		t.Errorf("preference = %d, want 10", pref)
	}
}

func TestDNSSOA(t *testing.T) {
	rdata := BuildSOARData("ns1.example.com", "admin.example.com", 2024010101, 7200, 3600, 1209600, 86400)
	rr := DNSRR{
		Name:  "example.com",
		Type:  QtypeSOA,
		Class: QclassIN,
		TTL:   3600,
		RData: rdata,
	}
	rr.RDLength = uint16(len(rr.RData))

	body := BuildDNSMessage(nil, []DNSRR{rr}, nil, nil)

	layer := NewDNS()
	layer.Set("ancount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()
	layer2 := NewDNS()
	layer2.ParseFields(raw)

	answers, _ := GetAnswers(layer2)
	if len(answers) != 1 || answers[0].Type != QtypeSOA {
		t.Error("SOA not found")
	}
}

func TestEDNS0(t *testing.T) {
	opt := BuildEDNS0(4096, 0, 0, 0, nil)

	body := BuildDNSMessage(nil, nil, nil, []DNSRR{*opt})

	layer := NewDNS()
	layer.Set("arcount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()
	layer2 := NewDNS()
	layer2.ParseFields(raw)

	// The OPT record should be in the AR section.
	_, _, _, additionals, err := GetAllSections(layer2)
	if err != nil {
		t.Fatal(err)
	}
	if len(additionals) != 1 {
		t.Fatalf("got %d ARs, want 1", len(additionals))
	}
	if additionals[0].Type != QtypeOPT {
		t.Error("not OPT record")
	}
	if additionals[0].Class != 4096 {
		t.Errorf("UDP size = %d, want 4096", additionals[0].Class)
	}
}

// GetAllSections extracts all four DNS sections from a parsed layer.
func GetAllSections(layer *packet.Layer) (questions []DNSQuestion, answers, authorities, additionals []DNSRR, err error) {
	data, _ := layer.Get("data")
	b := data.([]byte)

	qd, _ := layer.Get("qdcount")
	an, _ := layer.Get("ancount")
	ns, _ := layer.Get("nscount")
	ar, _ := layer.Get("arcount")

	offset := 0
	if qd.(uint16) > 0 {
		questions, _, err = ParseQuestions(b, offset, int(qd.(uint16)), -12)
		if err != nil {
			return
		}
		offset = len(questions) // approximate — but since we only use the offset to skip, we need to re-parse
	}
	// Re-parse to get correct offset.
	_, qc, _ := ParseQuestions(b, 0, int(qd.(uint16)), -12)
	offset = qc

	if an.(uint16) > 0 {
		answers, _, err = ParseRRs(b, offset, int(an.(uint16)), -12)
		if err != nil {
			return
		}
		for _, a := range answers {
			offset += 10 + len(a.RData) + len(EncodeName(a.Name))
		}
		// Recompute offset properly.
		_, ac, _ := ParseRRs(b, offset, int(an.(uint16)), -12)
		offset = qc + ac
	}

	if ns.(uint16) > 0 {
		authorities, _, err = ParseRRs(b, offset, int(ns.(uint16)), -12)
		if err != nil {
			return
		}
		_, nsc, _ := ParseRRs(b, offset, int(ns.(uint16)), -12)
		offset += nsc
	}

	if ar.(uint16) > 0 {
		additionals, _, err = ParseRRs(b, offset, int(ar.(uint16)), -12)
	}
	return
}

func TestTXTRecord(t *testing.T) {
	txt := []byte("hello world")
	rdata := make([]byte, 1+len(txt))
	rdata[0] = byte(len(txt))
	copy(rdata[1:], txt)

	rr := DNSRR{
		Name:  "example.com",
		Type:  QtypeTXT,
		Class: QclassIN,
		TTL:   300,
		RData: rdata,
	}
	rr.RDLength = uint16(len(rr.RData))

	body := BuildDNSMessage(nil, []DNSRR{rr}, nil, nil)
	layer := NewDNS()
	layer.Set("ancount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()
	layer2 := NewDNS()
	layer2.ParseFields(raw)

	answers, _ := GetAnswers(layer2)
	if len(answers) != 1 || answers[0].Type != QtypeTXT {
		t.Error("TXT not found")
	}
}

func TestDNSRoundTrip(t *testing.T) {
	q1 := DNSQuestion{Name: "example.com", Type: QtypeA, Class: QclassIN}
	q2 := DNSQuestion{Name: "example.com", Type: QtypeAAAA, Class: QclassIN}

	ans := DNSRR{
		Name:  "example.com",
		Type:  QtypeA,
		Class: QclassIN,
		TTL:   300,
		RData: BuildARData("1.2.3.4"),
	}
	ans.RDLength = uint16(len(ans.RData))

	body := BuildDNSMessage([]DNSQuestion{q1, q2}, []DNSRR{ans}, nil, nil)

	layer := NewDNS()
	layer.Set("id", uint16(0xABCD))
	layer.Set("flags", uint16(0x8180))
	layer.Set("qdcount", uint16(2))
	layer.Set("ancount", uint16(1))
	layer.Set("data", body)

	raw, _ := layer.SerializeFields()

	// Parse back fully.
	layer2 := NewDNS()
	consumed, err := layer2.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed = %d, want %d", consumed, len(raw))
	}

	qs, _ := GetQuestions(layer2)
	if len(qs) != 2 {
		t.Fatalf("questions = %d, want 2", len(qs))
	}
	if qs[1].Type != QtypeAAAA {
		t.Error("second question type wrong")
	}

	answers, _ := GetAnswers(layer2)
	if len(answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(answers))
	}
	if ParseARData(answers[0].RData) != "1.2.3.4" {
		t.Errorf("A data = %q", ParseARData(answers[0].RData))
	}
}

func TestDNSFlags(t *testing.T) {
	layer := NewDNS()
	layer.Set("flags", uint16(0x0100)) // RD=1

	flags, _ := layer.Get("flags")
	if flags.(uint16)&0x0100 == 0 {
		t.Error("RD not set")
	}

	// Set QR bit.
	layer.Set("flags", uint16(0x8180))
	flags, _ = layer.Get("flags")
	if flags.(uint16)&0x8000 == 0 {
		t.Error("QR not set")
	}
}

func TestParseDNSWithCompressedResponse(t *testing.T) {
	// Build a message with compression pointers in RR names.
	q := DNSQuestion{Name: "example.com", Type: QtypeA, Class: QclassIN}
	qRaw := BuildQuestion(q)

	// Build answer with pointer to qname in question section.
	msg := make([]byte, 12+len(qRaw)+16)
	// Header
	msg[0], msg[1] = 0x12, 0x34  // ID
	msg[2], msg[3] = 0x81, 0x80  // Flags
	msg[4], msg[5] = 0x00, 0x01  // QDCount
	msg[6], msg[7] = 0x00, 0x01  // ANCount
	msg[8], msg[9] = 0x00, 0x00  // NSCount
	msg[10], msg[11] = 0x00, 0x00 // ARCount
	// Question
	copy(msg[12:], qRaw)
	// Answer with compression pointer to 0x0C (offset of question name)
	off := 12 + len(qRaw)
	msg[off], msg[off+1] = 0xC0, 0x0C // pointer to question name
	msg[off+2], msg[off+3] = 0x00, 0x01  // TYPE A
	msg[off+4], msg[off+5] = 0x00, 0x01  // CLASS IN
	msg[off+6], msg[off+7], msg[off+8], msg[off+9] = 0x00, 0x00, 0x01, 0x2C // TTL=300
	msg[off+10], msg[off+11] = 0x00, 0x04 // RDLENGTH=4
	msg[off+12], msg[off+13], msg[off+14], msg[off+15] = 1, 2, 3, 4 // RDATA

	layer := NewDNS()
	_, err := layer.ParseFields(msg)
	if err != nil {
		t.Fatal(err)
	}

	answers, err := GetAnswers(layer)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(answers))
	}
	if answers[0].Name != "example.com" {
		t.Errorf("RR name = %q, want \"example.com\"", answers[0].Name)
	}
}