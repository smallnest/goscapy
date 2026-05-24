package tls

import (
	"testing"
)

func TestNewTLS(t *testing.T) {
	layer := NewTLS()
	ct, _ := layer.Get("content_type")
	if ct.(uint8) != ContentTypeHandshake {
		t.Errorf("default content_type = %d, want %d", ct, ContentTypeHandshake)
	}
}

func TestTLSSerializeParse(t *testing.T) {
	layer := NewTLS()
	layer.Set("content_type", uint8(ContentTypeHandshake))
	layer.Set("version", uint16(VersionTLS12))
	layer.Set("fragment", []byte{0x01, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00})

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// content_type(1) + version(2) + length(2) + fragment(9) = 14
	if len(data) != 14 {
		t.Errorf("size = %d, want 14", len(data))
	}
	if data[0] != ContentTypeHandshake {
		t.Errorf("content_type = %d", data[0])
	}

	layer2 := NewTLS()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 14 {
		t.Errorf("consumed = %d, want 14", n)
	}
}

func TestParseHandshake(t *testing.T) {
	// ClientHello with minimal body
	hs := []byte{
		0x01,                   // type = ClientHello
		0x00, 0x00, 0x05,       // length = 5
		0x03, 0x03,             // version TLS 1.2
		0x00, 0x00, 0x00,       // partial random
	}
	hsType, length, body, err := ParseHandshake(hs)
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if hsType != HandshakeTypeClientHello {
		t.Errorf("type = %d, want %d", hsType, HandshakeTypeClientHello)
	}
	if length != 5 {
		t.Errorf("length = %d, want 5", length)
	}
	if len(body) != 5 {
		t.Errorf("body len = %d, want 5", len(body))
	}
}

func TestParseHandshakeTruncated(t *testing.T) {
	_, _, _, err := ParseHandshake([]byte{0x01, 0x00})
	if err == nil {
		t.Error("expected error for truncated handshake")
	}
}

func TestBuildParseClientHello(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}

	ch := &ClientHello{
		Version:       VersionTLS12,
		Random:        random,
		SessionID:     nil,
		CipherSuites:  []uint16{0xC02F, 0xC030, 0x009E}, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 etc.
		Compression:   []uint8{0},
		Extensions: []Extension{
			BuildSNIExtension("example.com"),
		},
	}

	body := BuildClientHello(ch)
	parsed, err := ParseClientHello(body)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	if parsed.Version != VersionTLS12 {
		t.Errorf("version = %#x, want %#x", parsed.Version, VersionTLS12)
	}
	if len(parsed.Random) != 32 {
		t.Errorf("random len = %d", len(parsed.Random))
	}
	if len(parsed.CipherSuites) != 3 {
		t.Errorf("cipher suites count = %d, want 3", len(parsed.CipherSuites))
	}
	if parsed.CipherSuites[0] != 0xC02F {
		t.Errorf("first cipher = %#x, want 0xC02F", parsed.CipherSuites[0])
	}

	sni := ParseSNI(parsed.Extensions)
	if sni != "example.com" {
		t.Errorf("SNI = %q, want %q", sni, "example.com")
	}
}

func TestParseClientHelloNoExtensions(t *testing.T) {
	// Minimal ClientHello without extensions
	body := []byte{
		0x03, 0x03, // TLS 1.2
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // random (32 bytes)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00,                   // session ID length = 0
		0x00, 0x02,             // cipher suites length = 2
		0x00, 0x2F,             // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01,                   // compression methods length = 1
		0x00,                   // null compression
	}
	ch, err := ParseClientHello(body)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.Version != VersionTLS12 {
		t.Errorf("version = %#x", ch.Version)
	}
	if len(ch.CipherSuites) != 1 {
		t.Errorf("cipher suites = %d, want 1", len(ch.CipherSuites))
	}
	if len(ch.Extensions) != 0 {
		t.Errorf("extensions should be empty")
	}
}

func TestParseServerHello(t *testing.T) {
	// Minimal ServerHello
	body := []byte{
		0x03, 0x03, // TLS 1.2
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // random (32 bytes)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00,                   // session ID length = 0
		0xC0, 0x2F,             // selected cipher suite
		0x00,                   // compression = null
		// no extensions
	}
	sh, err := ParseServerHello(body)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	if sh.Version != VersionTLS12 {
		t.Errorf("version = %#x", sh.Version)
	}
	if sh.CipherSuite != 0xC02F {
		t.Errorf("cipher = %#x, want 0xC02F", sh.CipherSuite)
	}
}

func TestParseCertificate(t *testing.T) {
	// Two dummy certificates
	cert1 := []byte{0x01, 0x02, 0x03, 0x04}
	cert2 := []byte{0x05, 0x06}

	var body []byte
	// Total certificates length
	totalLen := 3 + len(cert1) + 3 + len(cert2)
	body = append(body, byte(totalLen>>16), byte(totalLen>>8), byte(totalLen))
	// Cert 1
	body = append(body, byte(len(cert1)>>16), byte(len(cert1)>>8), byte(len(cert1)))
	body = append(body, cert1...)
	// Cert 2
	body = append(body, byte(len(cert2)>>16), byte(len(cert2)>>8), byte(len(cert2)))
	body = append(body, cert2...)

	certs, err := ParseCertificate(body)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("certs count = %d, want 2", len(certs))
	}
	if len(certs[0].Data) != 4 {
		t.Errorf("cert[0] len = %d, want 4", len(certs[0].Data))
	}
	if certs[1].Data[0] != 0x05 {
		t.Errorf("cert[1][0] = %#x", certs[1].Data[0])
	}
}

func TestParseAlert(t *testing.T) {
	alert, err := ParseAlert([]byte{AlertLevelFatal, AlertHandshakeFailure})
	if err != nil {
		t.Fatalf("ParseAlert: %v", err)
	}
	if alert.Level != AlertLevelFatal {
		t.Errorf("level = %d", alert.Level)
	}
	if alert.Description != AlertHandshakeFailure {
		t.Errorf("desc = %d", alert.Description)
	}
}

func TestParseAlertTooShort(t *testing.T) {
	_, err := ParseAlert([]byte{0x01})
	if err == nil {
		t.Error("expected error for short alert")
	}
}

func TestSNIExtension(t *testing.T) {
	ext := BuildSNIExtension("test.example.com")
	sni := ParseSNI([]Extension{ext})
	if sni != "test.example.com" {
		t.Errorf("SNI = %q, want %q", sni, "test.example.com")
	}
}

func TestParseSNIMissing(t *testing.T) {
	sni := ParseSNI(nil)
	if sni != "" {
		t.Errorf("SNI = %q, want empty", sni)
	}
}

func TestALPN(t *testing.T) {
	// Build ALPN extension data manually: list_len(2) + proto_len(1) + proto("h2") + proto_len(1) + proto("http/1.1")
	data := []byte{
		0x00, 0x0C, // list length = 12
		0x02, 'h', '2',              // h2
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1', // http/1.1
	}
	exts := []Extension{{Type: ExtTypeALPN, Data: data}}
	protos := ParseALPN(exts)
	if len(protos) != 2 {
		t.Fatalf("ALPN count = %d, want 2", len(protos))
	}
	if protos[0] != "h2" {
		t.Errorf("proto[0] = %q", protos[0])
	}
	if protos[1] != "http/1.1" {
		t.Errorf("proto[1] = %q", protos[1])
	}
}

func TestSupportedGroups(t *testing.T) {
	data := []byte{
		0x00, 0x04, // list length = 4
		0x00, 0x17, // secp256r1 = 23
		0x00, 0x18, // secp384r1 = 24
	}
	exts := []Extension{{Type: ExtTypeSupportedGroups, Data: data}}
	groups := ParseSupportedGroups(exts)
	if len(groups) != 2 {
		t.Fatalf("groups count = %d, want 2", len(groups))
	}
	if groups[0] != 0x17 {
		t.Errorf("group[0] = %#x", groups[0])
	}
}

func TestContentTypeString(t *testing.T) {
	if ContentTypeString(ContentTypeHandshake) != "Handshake" {
		t.Errorf("unexpected string")
	}
	if ContentTypeString(99) != "Unknown(99)" {
		t.Errorf("unexpected unknown string")
	}
}

func TestHandshakeTypeString(t *testing.T) {
	if HandshakeTypeString(HandshakeTypeClientHello) != "ClientHello" {
		t.Errorf("unexpected string")
	}
}

func TestFindExtension(t *testing.T) {
	exts := []Extension{
		{Type: 0, Data: nil},
		{Type: 16, Data: []byte{1}},
	}
	if FindExtension(exts, 99) != nil {
		t.Error("should return nil for missing")
	}
	if FindExtension(exts, 16) == nil {
		t.Error("should find ext 16")
	}
}

func TestTLSRecordRoundTrip(t *testing.T) {
	layer := NewTLS()
	layer.Set("content_type", uint8(ContentTypeApplication))
	layer.Set("version", uint16(VersionTLS12))
	fragment := []byte("hello tls")
	layer.Set("fragment", fragment)

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// 1 + 2 + 2 + 9 = 14
	if len(data) != 14 {
		t.Errorf("size = %d, want 14", len(data))
	}

	layer2 := NewTLS()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	ct, _ := layer2.Get("content_type")
	if ct.(uint8) != ContentTypeApplication {
		t.Errorf("content_type = %d", ct)
	}
}

func TestBuildExtensions(t *testing.T) {
	exts := []Extension{
		{Type: 0, Data: []byte{1, 2}},
		{Type: 16, Data: []byte{3}},
	}
	raw := BuildExtensions(exts)
	// ext1: type(2)+len(2)+data(2) = 6, ext2: type(2)+len(2)+data(1) = 5, total = 11
	if len(raw) != 11 {
		t.Errorf("extensions size = %d, want 11", len(raw))
	}
}
