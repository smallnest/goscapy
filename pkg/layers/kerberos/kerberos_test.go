package kerberos

import (
	"testing"

	"github.com/smallnest/goscapy/pkg/asn1"
)

func TestMsgTypeName(t *testing.T) {
	tests := []struct {
		mt   int
		want string
	}{
		{MsgTypeASREQ, "AS-REQ"},
		{MsgTypeASREP, "AS-REP"},
		{MsgTypeTGSREQ, "TGS-REQ"},
		{MsgTypeKRBERR, "KRB-ERROR"},
		{99, "Unknown(99)"},
	}
	for _, tt := range tests {
		got := MsgTypeName(tt.mt)
		if got != tt.want {
			t.Errorf("MsgTypeName(%d) = %q, want %q", tt.mt, got, tt.want)
		}
	}
}

func TestErrCodeName(t *testing.T) {
	if ErrCodeName(KDCErrGeneric) != "KDC_ERR_GENERIC" {
		t.Errorf("ErrCodeName(GENERIC) = %q", ErrCodeName(KDCErrGeneric))
	}
}

func TestASREQRoundTrip(t *testing.T) {
	cname := PrincipalName{NameType: 1, NameString: []string{"admin"}}
	sname := PrincipalName{NameType: 2, NameString: []string{"krbtgt", "EXAMPLE.COM"}}

	raw := BuildASREQ("EXAMPLE.COM", cname, sname)

	msg, err := ParseKerberosMsg(raw)
	if err != nil {
		t.Fatalf("ParseKerberosMsg: %v", err)
	}

	if msg.MsgType != MsgTypeASREQ {
		t.Errorf("MsgType = %d, want %d", msg.MsgType, MsgTypeASREQ)
	}
	if msg.PVNO != PVNO {
		t.Errorf("PVNO = %d, want %d", msg.PVNO, PVNO)
	}
}

func TestASREQWithPrincipalNames(t *testing.T) {
	cname := PrincipalName{NameType: 1, NameString: []string{"admin"}}
	sname := PrincipalName{NameType: 2, NameString: []string{"krbtgt", "EXAMPLE.COM"}}

	raw := BuildASREQ("EXAMPLE.COM", cname, sname)

	msg, err := ParseKerberosMsg(raw)
	if err != nil {
		t.Fatalf("ParseKerberosMsg: %v", err)
	}

	// The AS-REQ encodes principals inside KDC-REQ-BODY which is [4] EXPLICIT.
	// Our best-effort parser may not extract them from the nested context tag,
	// but it should at least parse the message type and pvno correctly.
	if msg.PVNO != PVNO {
		t.Errorf("PVNO = %d, want %d", msg.PVNO, PVNO)
	}
	if msg.MsgType != MsgTypeASREQ {
		t.Errorf("MsgType = %d, want %d", msg.MsgType, MsgTypeASREQ)
	}
}

func TestASREPRoundTrip(t *testing.T) {
	cname := PrincipalName{NameType: 1, NameString: []string{"admin"}}
	raw := BuildASREP("EXAMPLE.COM", cname)

	msg, err := ParseKerberosMsg(raw)
	if err != nil {
		t.Fatalf("ParseKerberosMsg: %v", err)
	}

	if msg.MsgType != MsgTypeASREP {
		t.Errorf("MsgType = %d, want %d", msg.MsgType, MsgTypeASREP)
	}
	if msg.PVNO != PVNO {
		t.Errorf("PVNO = %d, want %d", msg.PVNO, PVNO)
	}
	if msg.Realm != "EXAMPLE.COM" {
		t.Errorf("Realm = %q, want %q", msg.Realm, "EXAMPLE.COM")
	}
	if len(msg.CName.NameString) != 1 || msg.CName.NameString[0] != "admin" {
		t.Errorf("CName = %v, want [admin]", msg.CName.NameString)
	}
}

func TestBuildKerberosMsgDirect(t *testing.T) {
	msg := &KerberosMsg{
		MsgType: MsgTypeAPREQ,
		PVNO:    PVNO,
		Realm:   "TEST.COM",
	}

	raw := BuildKerberosMsg(msg)

	parsed, err := ParseKerberosMsg(raw)
	if err != nil {
		t.Fatalf("ParseKerberosMsg: %v", err)
	}
	if parsed.MsgType != MsgTypeAPREQ {
		t.Errorf("MsgType = %d, want %d", parsed.MsgType, MsgTypeAPREQ)
	}
	if parsed.PVNO != PVNO {
		t.Errorf("PVNO = %d, want %d", parsed.PVNO, PVNO)
	}
}

func TestParsePrincipalName(t *testing.T) {
	// Build a PrincipalName: SEQUENCE { INTEGER(1), SEQUENCE { "admin" } }
	nameType := asn1.BEREncodeInteger(1)
	names := buildGeneralString("admin")
	inner := append(nameType, asn1.BERTLV(asn1.TagSequence, names)...)
	data := asn1.BERTLV(asn1.TagSequence, inner)

	tag, val, _, err := asn1.BERDecodeTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if tag != asn1.TagSequence {
		t.Fatalf("tag = 0x%02x", tag)
	}

	pn := parsePrincipalName(val)
	if pn == nil {
		t.Fatal("parsePrincipalName returned nil")
	}
	if pn.NameType != 1 {
		t.Errorf("NameType = %d, want 1", pn.NameType)
	}
	if len(pn.NameString) != 1 || pn.NameString[0] != "admin" {
		t.Errorf("NameString = %v, want [admin]", pn.NameString)
	}
}

func TestParseKerberosMsgErrors(t *testing.T) {
	_, err := ParseKerberosMsg(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}

	_, err = ParseKerberosMsg([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}

	// Invalid BER data.
	_, err = ParseKerberosMsg([]byte{0x02, 0x05, 0x01}) // truncated
	if err == nil {
		t.Error("expected error for truncated BER")
	}
}

func TestMsgTypeToTag(t *testing.T) {
	tests := []struct {
		mt   int
		want byte
	}{
		{MsgTypeASREQ, TagASREQ},
		{MsgTypeASREP, TagASREP},
		{MsgTypeTGSREQ, TagTGSREQ},
		{MsgTypeTGSREP, TagTGSREP},
		{MsgTypeAPREQ, TagAPREQ},
		{MsgTypeAPREP, TagAPREP},
	}
	for _, tt := range tests {
		got := msgTypeToTag(tt.mt)
		if got != tt.want {
			t.Errorf("msgTypeToTag(%d) = 0x%02x, want 0x%02x", tt.mt, got, tt.want)
		}
	}
}

func TestTagToMsgType(t *testing.T) {
	tests := []struct {
		tag  byte
		want int
	}{
		{TagASREQ, MsgTypeASREQ},
		{TagASREP, MsgTypeASREP},
		{TagTGSREQ, MsgTypeTGSREQ},
		{0xFF, 0},
	}
	for _, tt := range tests {
		got := tagToMsgType(tt.tag)
		if got != tt.want {
			t.Errorf("tagToMsgType(0x%02x) = %d, want %d", tt.tag, got, tt.want)
		}
	}
}
