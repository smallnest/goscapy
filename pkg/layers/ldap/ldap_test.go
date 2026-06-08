package ldap

import (
	"testing"

	"github.com/smallnest/goscapy/pkg/asn1"
)

func TestOpName(t *testing.T) {
	tests := []struct {
		tag  byte
		want string
	}{
		{TagBindRequest, "BindRequest"},
		{TagBindResponse, "BindResponse"},
		{TagSearchRequest, "SearchRequest"},
		{0xFF, "Unknown(0xff)"},
	}
	for _, tt := range tests {
		got := OpName(tt.tag)
		if got != tt.want {
			t.Errorf("OpName(0x%02x) = %q, want %q", tt.tag, got, tt.want)
		}
	}
}

func TestResultName(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{ResultSuccess, "success"},
		{ResultInvalidCredentials, "invalidCredentials"},
		{99, "code(99)"},
	}
	for _, tt := range tests {
		got := ResultName(tt.code)
		if got != tt.want {
			t.Errorf("ResultName(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestBindRequestRoundTrip(t *testing.T) {
	raw := BuildBindRequest(1, "cn=admin,dc=example,dc=com", "secret")

	msg, err := ParseLDAPMessage(raw)
	if err != nil {
		t.Fatalf("ParseLDAPMessage: %v", err)
	}

	if msg.MessageID != 1 {
		t.Errorf("MessageID = %d, want 1", msg.MessageID)
	}
	if msg.ProtocolOp.Tag != TagBindRequest {
		t.Errorf("ProtocolOp.Tag = 0x%02x, want 0x%02x", msg.ProtocolOp.Tag, TagBindRequest)
	}

	// Parse the BindRequest: ProtocolOp.Value is the full TLV including the app tag.
	// Decode outer app tag, then inner SEQUENCE.
	appTag, appVal, _, err := asn1.BERDecodeTLV(msg.ProtocolOp.Value)
	if err != nil {
		t.Fatalf("decode BindRequest app tag: %v", err)
	}
	if appTag != TagBindRequest {
		t.Errorf("app tag = 0x%02x, want 0x%02x", appTag, TagBindRequest)
	}

	pos := 0
	// Version.
	tag, val, consumed, err := asn1.BERDecodeTLV(appVal[pos:])
	if err != nil {
		t.Fatalf("parse version: %v", err)
	}
	if tag != asn1.TagInteger {
		t.Errorf("version tag = 0x%02x", tag)
	}
	version, _ := asn1.BERDecodeInteger(val)
	if version != 3 {
		t.Errorf("version = %d, want 3", version)
	}
	pos += consumed

	// Name (DN).
	tag, val, consumed, err = asn1.BERDecodeTLV(appVal[pos:])
	if err != nil {
		t.Fatalf("parse name: %v", err)
	}
	if tag != asn1.TagOctetString {
		t.Errorf("name tag = 0x%02x", tag)
	}
	if string(val) != "cn=admin,dc=example,dc=com" {
		t.Errorf("name = %q", string(val))
	}
	pos += consumed

	// Simple authentication (context tag 0x80).
	tag, val, _, err = asn1.BERDecodeTLV(appVal[pos:])
	if err != nil {
		t.Fatalf("parse auth: %v", err)
	}
	if tag != 0x80 {
		t.Errorf("auth tag = 0x%02x, want 0x80 (simple)", tag)
	}
	if string(val) != "secret" {
		t.Errorf("password = %q, want %q", string(val), "secret")
	}
}

func TestBindResponseRoundTrip(t *testing.T) {
	raw := BuildBindResponse(2, ResultSuccess, "", "")

	msg, err := ParseLDAPMessage(raw)
	if err != nil {
		t.Fatalf("ParseLDAPMessage: %v", err)
	}

	if msg.MessageID != 2 {
		t.Errorf("MessageID = %d, want 2", msg.MessageID)
	}
	if msg.ProtocolOp.Tag != TagBindResponse {
		t.Errorf("ProtocolOp.Tag = 0x%02x", msg.ProtocolOp.Tag)
	}

	// Parse the BindResponse inner.
	appTag, appVal, _, err := asn1.BERDecodeTLV(msg.ProtocolOp.Value)
	if err != nil {
		t.Fatalf("decode BindResponse app tag: %v", err)
	}
	if appTag != TagBindResponse {
		t.Errorf("app tag = 0x%02x", appTag)
	}

	resultCode, matchedDN, diagnostic, err := ParseLDAPResult(appVal)
	if err != nil {
		t.Fatalf("ParseLDAPResult: %v", err)
	}
	if resultCode != ResultSuccess {
		t.Errorf("resultCode = %d, want %d", resultCode, ResultSuccess)
	}
	if matchedDN != "" {
		t.Errorf("matchedDN = %q, want empty", matchedDN)
	}
	if diagnostic != "" {
		t.Errorf("diagnostic = %q, want empty", diagnostic)
	}
}

func TestSearchRequestRoundTrip(t *testing.T) {
	raw := BuildSearchRequest(3, "dc=example,dc=com",
		ScopeWholeSubtree, NeverDerefAliases,
		0, 0, false, nil,
		[]string{"cn", "mail"})

	msg, err := ParseLDAPMessage(raw)
	if err != nil {
		t.Fatalf("ParseLDAPMessage: %v", err)
	}

	if msg.MessageID != 3 {
		t.Errorf("MessageID = %d, want 3", msg.MessageID)
	}
	if msg.ProtocolOp.Tag != TagSearchRequest {
		t.Errorf("ProtocolOp.Tag = 0x%02x", msg.ProtocolOp.Tag)
	}
}

func TestSearchResultDoneRoundTrip(t *testing.T) {
	raw := BuildSearchResultDone(4, ResultSizeLimitExceeded, "", "too many results")

	msg, err := ParseLDAPMessage(raw)
	if err != nil {
		t.Fatalf("ParseLDAPMessage: %v", err)
	}

	if msg.MessageID != 4 {
		t.Errorf("MessageID = %d, want 4", msg.MessageID)
	}

	appTag, appVal, _, err := asn1.BERDecodeTLV(msg.ProtocolOp.Value)
	if err != nil {
		t.Fatalf("decode SearchResultDone inner: %v", err)
	}
	if appTag != TagSearchResultDone {
		t.Errorf("app tag = 0x%02x", appTag)
	}

	resultCode, _, diagnostic, err := ParseLDAPResult(appVal)
	if err != nil {
		t.Fatalf("ParseLDAPResult: %v", err)
	}
	if resultCode != ResultSizeLimitExceeded {
		t.Errorf("resultCode = %d, want %d", resultCode, ResultSizeLimitExceeded)
	}
	if diagnostic != "too many results" {
		t.Errorf("diagnostic = %q", diagnostic)
	}
}

func TestParseLDAPMessageErrors(t *testing.T) {
	_, err := ParseLDAPMessage(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}

	_, err = ParseLDAPMessage([]byte{0x05, 0x00}) // NULL instead of SEQUENCE
	if err == nil {
		t.Error("expected error for wrong outer tag")
	}

	// Truncated: SEQUENCE tag but not enough data.
	_, err = ParseLDAPMessage([]byte{0x30, 0x05, 0x02, 0x01, 0x01})
	if err == nil {
		t.Error("expected error for truncated LDAP message")
	}
}

func TestParseLDAPResultErrors(t *testing.T) {
	_, _, _, err := ParseLDAPResult(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}
}

func TestBuildLDAPMessageDirect(t *testing.T) {
	msg := &LDAPMessage{
		MessageID: 42,
		ProtocolOp: LDAPOp{
			Tag:   TagUnbindRequest,
			Value: asn1.BERTLV(TagUnbindRequest, nil),
		},
	}
	raw := BuildLDAPMessage(msg)

	parsed, err := ParseLDAPMessage(raw)
	if err != nil {
		t.Fatalf("ParseLDAPMessage: %v", err)
	}
	if parsed.MessageID != 42 {
		t.Errorf("MessageID = %d, want 42", parsed.MessageID)
	}
	if parsed.ProtocolOp.Tag != TagUnbindRequest {
		t.Errorf("ProtocolOp.Tag = 0x%02x", parsed.ProtocolOp.Tag)
	}
}
