package radius

import (
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
)

func TestCodeName(t *testing.T) {
	tests := []struct {
		code uint8
		want string
	}{
		{CodeAccessRequest, "Access-Request"},
		{CodeAccessAccept, "Access-Accept"},
		{CodeAccessReject, "Access-Reject"},
		{99, "Unknown(99)"},
	}
	for _, tt := range tests {
		got := CodeName(tt.code)
		if got != tt.want {
			t.Errorf("CodeName(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestParseAndBuildAVPs(t *testing.T) {
	avps := []fields.TLVOption{
		NewUserNameAVP("testuser"),
		NewNASIPAVP("192.168.1.1"),
		NewNASPortAVP(1234),
	}

	wire := BuildRADIUSAVPs(avps)
	parsed, err := ParseRADIUSAVPs(wire)
	if err != nil {
		t.Fatalf("ParseRADIUSAVPs: %v", err)
	}

	if len(parsed) != 3 {
		t.Fatalf("got %d AVPs, want 3", len(parsed))
	}

	// User-Name
	u := GetRADIUSAVP(parsed, AVPUserName)
	if u == nil || string(u.Value) != "testuser" {
		t.Errorf("User-Name = %q, want %q", u.Value, "testuser")
	}

	// NAS-IP
	n := GetRADIUSAVP(parsed, AVPNASIP)
	if n == nil {
		t.Fatal("NAS-IP not found")
	}
	wantIP := []byte{192, 168, 1, 1}
	if len(n.Value) != 4 || string(n.Value) != string(wantIP) {
		t.Errorf("NAS-IP = %v, want %v", n.Value, wantIP)
	}

	// NAS-Port
	p := GetRADIUSAVP(parsed, AVPNASPort)
	if p == nil {
		t.Fatal("NAS-Port not found")
	}
	port := uint32(p.Value[0])<<24 | uint32(p.Value[1])<<16 | uint32(p.Value[2])<<8 | uint32(p.Value[3])
	if port != 1234 {
		t.Errorf("NAS-Port = %d, want 1234", port)
	}
}

func TestRADIUSAVPRoundTrip(t *testing.T) {
	// Build AVPs with various types.
	original := []fields.TLVOption{
		NewUserNameAVP("admin"),
		NewFramedIPAVP("10.0.0.1"),
		NewStateAVP([]byte{0x01, 0x02, 0x03}),
		NewVendorSpecificAVP(9, []byte{0x01, 0x02}),
	}

	wire := BuildRADIUSAVPs(original)
	parsed, err := ParseRADIUSAVPs(wire)
	if err != nil {
		t.Fatalf("ParseRADIUSAVPs: %v", err)
	}

	if len(parsed) != len(original) {
		t.Fatalf("got %d AVPs, want %d", len(parsed), len(original))
	}

	for i, p := range parsed {
		if p.Type != original[i].Type {
			t.Errorf("AVP[%d] type = %d, want %d", i, p.Type, original[i].Type)
		}
		if string(p.Value) != string(original[i].Value) {
			t.Errorf("AVP[%d] value = %v, want %v", i, p.Value, original[i].Value)
		}
	}
}

func TestRADIUSAVPTruncated(t *testing.T) {
	_, err := ParseRADIUSAVPs([]byte{0x01})
	if err == nil {
		t.Error("expected error for truncated AVP")
	}
}

func TestRADIUSAVPInvalidLength(t *testing.T) {
	// Type=1, Length=1 (invalid, minimum is 2)
	_, err := ParseRADIUSAVPs([]byte{0x01, 0x01})
	if err == nil {
		t.Error("expected error for AVP with length < 2")
	}
}

func TestBuildRADIUSAVPsWireFormat(t *testing.T) {
	// Manually verify wire format for a simple AVP.
	avps := []fields.TLVOption{
		{Type: 1, Value: []byte("abc")}, // User-Name, 3 bytes value
	}
	wire := BuildRADIUSAVPs(avps)
	// Expected: Type(1) + Length(1+1+3=5) + Value("abc")
	want := []byte{1, 5, 'a', 'b', 'c'}
	if len(wire) != len(want) || string(wire) != string(want) {
		t.Errorf("wire = %v, want %v", wire, want)
	}
}

func TestNewServiceTypeAVP(t *testing.T) {
	avp := NewServiceTypeAVP(2) // Framed
	if avp.Type != AVPServiceType {
		t.Errorf("type = %d, want %d", avp.Type, AVPServiceType)
	}
	port := uint32(avp.Value[0])<<24 | uint32(avp.Value[1])<<16 | uint32(avp.Value[2])<<8 | uint32(avp.Value[3])
	if port != 2 {
		t.Errorf("value = %d, want 2", port)
	}
}
