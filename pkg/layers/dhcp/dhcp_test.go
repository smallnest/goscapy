package dhcp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestNewDHCPDefaults(t *testing.T) {
	layer := NewDHCP()

	op, _ := layer.Get("op")
	if op.(uint8) != BOOTREQUEST {
		t.Errorf("op = %d, want %d", op, BOOTREQUEST)
	}
	htype, _ := layer.Get("htype")
	if htype.(uint8) != 1 {
		t.Errorf("htype = %d, want 1", htype)
	}
	hlen, _ := layer.Get("hlen")
	if hlen.(uint8) != 6 {
		t.Errorf("hlen = %d, want 6", hlen)
	}
	cookie, _ := layer.Get("cookie")
	if cookie.(uint32) != MagicCookie {
		t.Errorf("cookie = %#x, want %#x", cookie, MagicCookie)
	}
}

func TestDHCPSerializeHeader(t *testing.T) {
	layer := NewDHCP()
	layer.Set("op", uint8(BOOTREQUEST))
	layer.Set("htype", uint8(1))
	layer.Set("hlen", uint8(6))
	layer.Set("hops", uint8(0))
	layer.Set("xid", uint32(0x12345678))
	layer.Set("secs", uint16(0))
	layer.Set("flags", uint16(0x8000))
	layer.Set("ciaddr", net.IPv4zero)
	layer.Set("yiaddr", net.IPv4zero)
	layer.Set("siaddr", net.IPv4zero)
	layer.Set("giaddr", net.IPv4zero)
	layer.Set("options", []byte{OptEnd})

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Verify total size: 240 fixed + 1 (End option) = 241
	if len(got) != 241 {
		t.Fatalf("len = %d, want 241", len(got))
	}

	// Verify key fields at correct offsets.
	if got[0] != 0x01 {
		t.Errorf("op = %#x", got[0])
	}
	if got[1] != 0x01 {
		t.Errorf("htype = %#x", got[1])
	}
	if got[2] != 0x06 {
		t.Errorf("hlen = %#x", got[2])
	}
	// xid at offset 4
	if binary.BigEndian.Uint32(got[4:8]) != 0x12345678 {
		t.Errorf("xid = %#x", binary.BigEndian.Uint32(got[4:8]))
	}
	// flags at offset 10
	if binary.BigEndian.Uint16(got[10:12]) != 0x8000 {
		t.Errorf("flags = %#x", binary.BigEndian.Uint16(got[10:12]))
	}
	// cookie at offset 236 (4+4+4+16+16+64+128)
	cookieOff := 236
	if binary.BigEndian.Uint32(got[cookieOff:cookieOff+4]) != MagicCookie {
		t.Errorf("cookie = %#x", binary.BigEndian.Uint32(got[cookieOff:cookieOff+4]))
	}
	// End option at offset 240
	if got[240] != OptEnd {
		t.Errorf("end option = %#x", got[240])
	}
}

func TestDHCPParseHeader(t *testing.T) {
	layer := NewDHCP()
	layer.Set("xid", uint32(0x12345678))
	layer.Set("flags", uint16(0x8000))
	layer.Set("options", []byte{OptEnd})

	raw, _ := layer.SerializeFields()

	layer2 := NewDHCP()
	consumed, err := layer2.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed = %d, want %d", consumed, len(raw))
	}

	xid, _ := layer2.Get("xid")
	if xid.(uint32) != 0x12345678 {
		t.Errorf("xid = %#x", xid)
	}
	flags, _ := layer2.Get("flags")
	if flags.(uint16) != 0x8000 {
		t.Errorf("flags = %#x", flags)
	}
	cookie, _ := layer2.Get("cookie")
	if cookie.(uint32) != MagicCookie {
		t.Errorf("cookie = %#x", cookie)
	}
}

func TestDHCPParseOptions(t *testing.T) {
	optsRaw := []byte{
		53, 1, 1, // Message Type: DHCPDISCOVER
		55, 4, 1, 3, 6, 15, // Param List
		255, // End
	}

	opts, err := ParseDHCPOptions(optsRaw)
	if err != nil {
		t.Fatal(err)
	}

	mt := GetMessageType(opts)
	if mt != DHCPDISCOVER {
		t.Errorf("message type = %d, want %d", mt, DHCPDISCOVER)
	}

	pl := GetDHCPOption(opts, OptParamList)
	if pl == nil {
		t.Fatal("param list option not found")
	}
	if len(pl.Value) != 4 {
		t.Fatalf("param list len = %d, want 4", len(pl.Value))
	}
}

func TestDHCPBuildOptions(t *testing.T) {
	opts := []fields.TLVOption{
		NewMessageTypeOption(DHCPDISCOVER),
		NewParamListOption([]uint8{1, 3, 6, 15}),
	}

	got := BuildDHCPOptions(opts)

	// Expected: type(53) len(1) val(1) type(55) len(4) val(1,3,6,15) End(255)
	want := []byte{53, 1, 1, 55, 4, 1, 3, 6, 15, 255}
	if !bytes.Equal(got, want) {
		t.Errorf("BuildDHCPOptions:\n got %#v\nwant %#v", got, want)
	}
}

func TestDHCPDiscover(t *testing.T) {
	layer := NewDHCP()
	layer.Set("xid", uint32(0x12345678))
	layer.Set("flags", uint16(0x8000))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPDISCOVER),
		NewParamListOption([]uint8{1, 3, 6, 15}),
	})
	layer.Set("options", opts)

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Build expected bytes.
	// Fixed header (240 bytes) + options
	expected := make([]byte, 240)
	expected[0] = BOOTREQUEST // op
	expected[1] = 1            // htype
	expected[2] = 6            // hlen
	binary.BigEndian.PutUint32(expected[4:8], 0x12345678)
	binary.BigEndian.PutUint16(expected[10:12], 0x8000)
	binary.BigEndian.PutUint32(expected[236:240], MagicCookie)
	// Options: message-type(53,1,1), param-list(55,4,1,3,6,15), End(255)
	expected = append(expected, 53, 1, 1, 55, 4, 1, 3, 6, 15, 255)

	if !bytes.Equal(got, expected) {
		t.Errorf("DHCPDISCOVER mismatch:\n got  %#v\nwant %#v", got, expected)
	}
}

func TestDHCPOffer(t *testing.T) {
	layer := NewDHCP()
	layer.Set("op", uint8(BOOTREPLY))
	layer.Set("xid", uint32(0x12345678))
	layer.Set("yiaddr", net.ParseIP("192.168.1.100"))
	layer.Set("siaddr", net.ParseIP("192.168.1.1"))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPOFFER),
		NewServerIDOption("192.168.1.1"),
		NewLeaseTimeOption(86400),
		NewSubnetMaskOption("255.255.255.0"),
		NewRouterOption([]string{"192.168.1.1"}),
		NewDNSOption([]string{"8.8.8.8"}),
	})
	layer.Set("options", opts)

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Build expected bytes.
	expected := make([]byte, 240)
	expected[0] = BOOTREPLY
	expected[1] = 1
	expected[2] = 6
	binary.BigEndian.PutUint32(expected[4:8], 0x12345678)
	// yiaddr at offset 16
	copy(expected[16:20], net.ParseIP("192.168.1.100").To4())
	// siaddr at offset 20
	copy(expected[20:24], net.ParseIP("192.168.1.1").To4())
	binary.BigEndian.PutUint32(expected[236:240], MagicCookie)

	// Options: message-type(53,1,2), server-id(54,4,192.168.1.1), lease-time(51,4,86400),
	//          subnet-mask(1,4,255.255.255.0), router(3,4,192.168.1.1),
	//          dns(6,4,8.8.8.8), End(255)
	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, 86400)
	expected = append(expected,
		53, 1, 2, // Message Type: OFFER
		54, 4, 192, 168, 1, 1, // Server ID
		51, 4, lt[0], lt[1], lt[2], lt[3], // Lease Time
		1, 4, 255, 255, 255, 0, // Subnet Mask
		3, 4, 192, 168, 1, 1, // Router
		6, 4, 8, 8, 8, 8, // DNS
		255, // End
	)

	if !bytes.Equal(got, expected) {
		t.Errorf("DHCPOFFER mismatch:\n got  %#v\nwant %#v", got, expected)
	}
}

func TestDHCPRequest(t *testing.T) {
	layer := NewDHCP()
	layer.Set("xid", uint32(0xDEADBEEF))
	layer.Set("flags", uint16(0x8000))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPREQUEST),
		NewRequestedIPOption("192.168.1.100"),
		NewServerIDOption("192.168.1.1"),
	})
	layer.Set("options", opts)

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]byte, 240)
	expected[0] = BOOTREQUEST
	expected[1] = 1
	expected[2] = 6
	binary.BigEndian.PutUint32(expected[4:8], 0xDEADBEEF)
	binary.BigEndian.PutUint16(expected[10:12], 0x8000)
	binary.BigEndian.PutUint32(expected[236:240], MagicCookie)

	expected = append(expected,
		53, 1, 3, // Message Type: REQUEST
		50, 4, 192, 168, 1, 100, // Requested IP
		54, 4, 192, 168, 1, 1, // Server ID
		255, // End
	)

	if !bytes.Equal(got, expected) {
		t.Errorf("DHCPREQUEST mismatch:\n got  %#v\nwant %#v", got, expected)
	}
}

func TestDHCPAck(t *testing.T) {
	layer := NewDHCP()
	layer.Set("op", uint8(BOOTREPLY))
	layer.Set("xid", uint32(0x12345678))
	layer.Set("yiaddr", net.ParseIP("192.168.1.100"))
	layer.Set("siaddr", net.ParseIP("192.168.1.1"))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPACK),
		NewServerIDOption("192.168.1.1"),
		NewLeaseTimeOption(86400),
		NewSubnetMaskOption("255.255.255.0"),
		NewRouterOption([]string{"192.168.1.1"}),
		NewDNSOption([]string{"8.8.8.8", "8.8.4.4"}),
	})
	layer.Set("options", opts)

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]byte, 240)
	expected[0] = BOOTREPLY
	expected[1] = 1
	expected[2] = 6
	binary.BigEndian.PutUint32(expected[4:8], 0x12345678)
	copy(expected[16:20], net.ParseIP("192.168.1.100").To4())
	copy(expected[20:24], net.ParseIP("192.168.1.1").To4())
	binary.BigEndian.PutUint32(expected[236:240], MagicCookie)

	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, 86400)
	expected = append(expected,
		53, 1, 5, // Message Type: ACK
		54, 4, 192, 168, 1, 1, // Server ID
		51, 4, lt[0], lt[1], lt[2], lt[3], // Lease Time
		1, 4, 255, 255, 255, 0, // Subnet Mask
		3, 4, 192, 168, 1, 1, // Router
		6, 8, 8, 8, 8, 8, 8, 8, 4, 4, // DNS (two servers)
		255, // End
	)

	if !bytes.Equal(got, expected) {
		t.Errorf("DHCPACK mismatch:\n got  %#v\nwant %#v", got, expected)
	}
}

func TestDHCPRoundTrip(t *testing.T) {
	layer := NewDHCP()
	layer.Set("op", uint8(BOOTREPLY))
	layer.Set("xid", uint32(0xCAFEBABE))
	layer.Set("flags", uint16(0x8000))
	layer.Set("yiaddr", net.ParseIP("10.0.0.100"))
	layer.Set("siaddr", net.ParseIP("10.0.0.1"))
	layer.Set("giaddr", net.ParseIP("10.0.0.254"))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPOFFER),
		NewServerIDOption("10.0.0.1"),
		NewLeaseTimeOption(3600),
		NewSubnetMaskOption("255.255.255.0"),
		NewRouterOption([]string{"10.0.0.1"}),
		NewDNSOption([]string{"10.0.0.53"}),
		NewHostnameOption("client1"),
		NewDomainOption("example.com"),
		NewRenewalOption(1800),
		NewRebindingOption(3150),
	})
	layer.Set("options", opts)

	raw, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// Parse back.
	layer2 := NewDHCP()
	consumed, err := layer2.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed = %d, want %d", consumed, len(raw))
	}

	// Verify header fields.
	xid, _ := layer2.Get("xid")
	if xid.(uint32) != 0xCAFEBABE {
		t.Errorf("xid = %#x", xid)
	}
	flags, _ := layer2.Get("flags")
	if flags.(uint16) != 0x8000 {
		t.Errorf("flags = %#x", flags)
	}

	// Parse and verify options.
	optData, _ := layer2.Get("options")
	opts2, err := ParseDHCPOptions(optData.([]byte))
	if err != nil {
		t.Fatal(err)
	}

	mt := GetMessageType(opts2)
	if mt != DHCPOFFER {
		t.Errorf("message type = %d, want DHCPOFFER", mt)
	}

	// Check each option.
	if o := GetDHCPOption(opts2, OptServerID); o == nil || !bytes.Equal(o.Value, net.ParseIP("10.0.0.1").To4()) {
		t.Error("server-id mismatch")
	}
	if o := GetDHCPOption(opts2, OptSubnetMask); o == nil || !bytes.Equal(o.Value, net.ParseIP("255.255.255.0").To4()) {
		t.Error("subnet mask mismatch")
	}
	if o := GetDHCPOption(opts2, OptHostname); o == nil || string(o.Value) != "client1" {
		t.Error("hostname mismatch")
	}
	if o := GetDHCPOption(opts2, OptDomain); o == nil || string(o.Value) != "example.com" {
		t.Error("domain mismatch")
	}

	lt := GetDHCPOption(opts2, OptLeaseTime)
	if lt == nil || binary.BigEndian.Uint32(lt.Value) != 3600 {
		t.Error("lease time mismatch")
	}

	rn := GetDHCPOption(opts2, OptRenewal)
	if rn == nil || binary.BigEndian.Uint32(rn.Value) != 1800 {
		t.Error("renewal mismatch")
	}

	rb := GetDHCPOption(opts2, OptRebinding)
	if rb == nil || binary.BigEndian.Uint32(rb.Value) != 3150 {
		t.Error("rebinding mismatch")
	}

	// Verify layer can be built into a full packet.
	layer3 := NewDHCP()
	layer3.Set("xid", uint32(0xABCD))
	layer3.Set("options", []byte{OptEnd})
	pkt := packet.NewFrom(layer3)
	raw3, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}
	if raw3[len(raw3)-1] != OptEnd {
		t.Errorf("last byte = %#x, want End(255)", raw3[len(raw3)-1])
	}
}

func TestGetMessageType(t *testing.T) {
	opts := []fields.TLVOption{
		NewMessageTypeOption(DHCPACK),
	}
	mt := GetMessageType(opts)
	if mt != DHCPACK {
		t.Errorf("GetMessageType = %d, want DHCPACK(5)", mt)
	}

	// Empty options.
	if GetMessageType(nil) != 0 {
		t.Error("GetMessageType(nil) should be 0")
	}
}

func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		mt   uint8
		want string
	}{
		{DHCPDISCOVER, "DHCPDISCOVER"},
		{DHCPOFFER, "DHCPOFFER"},
		{DHCPREQUEST, "DHCPREQUEST"},
		{DHCPDECLINE, "DHCPDECLINE"},
		{DHCPACK, "DHCPACK"},
		{DHCPNAK, "DHCPNAK"},
		{DHCPRELEASE, "DHCPRELEASE"},
		{DHCPINFORM, "DHCPINFORM"},
		{99, "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		got := MessageTypeString(tt.mt)
		if got != tt.want {
			t.Errorf("MessageTypeString(%d) = %q, want %q", tt.mt, got, tt.want)
		}
	}
}

func TestConvenienceOptionConstructors(t *testing.T) {
	// Subnet Mask.
	sm := NewSubnetMaskOption("255.255.255.0")
	if sm.Type != OptSubnetMask || sm.Length != 4 {
		t.Error("SubnetMaskOption wrong type/length")
	}
	if !bytes.Equal(sm.Value, []byte{255, 255, 255, 0}) {
		t.Errorf("SubnetMaskOption value = %v", sm.Value)
	}

	// Router.
	r := NewRouterOption([]string{"192.168.1.1"})
	if r.Type != OptRouter || r.Length != 4 {
		t.Error("RouterOption wrong type/length")
	}

	// DNS.
	d := NewDNSOption([]string{"8.8.8.8", "8.8.4.4"})
	if d.Type != OptDNS || d.Length != 8 {
		t.Errorf("DNSOption len = %d, want 8", d.Length)
	}

	// Hostname.
	h := NewHostnameOption("myhost")
	if h.Type != OptHostname || h.Length != 6 || string(h.Value) != "myhost" {
		t.Error("HostnameOption mismatch")
	}

	// Domain.
	dom := NewDomainOption("example.com")
	if dom.Type != OptDomain || string(dom.Value) != "example.com" {
		t.Error("DomainOption mismatch")
	}

	// Requested IP.
	rip := NewRequestedIPOption("10.0.0.1")
	if rip.Type != OptRequestedIP || rip.Length != 4 {
		t.Error("RequestedIPOption wrong")
	}

	// Lease Time.
	lt := NewLeaseTimeOption(86400)
	if lt.Type != OptLeaseTime || lt.Length != 4 {
		t.Error("LeaseTimeOption wrong type/length")
	}
	if binary.BigEndian.Uint32(lt.Value) != 86400 {
		t.Error("LeaseTimeOption value mismatch")
	}

	// Server ID.
	sid := NewServerIDOption("192.168.1.1")
	if sid.Type != OptServerID || sid.Length != 4 {
		t.Error("ServerIDOption wrong")
	}

	// Param List.
	pl := NewParamListOption([]uint8{1, 3, 6, 15, 28})
	if pl.Type != OptParamList || pl.Length != 5 {
		t.Error("ParamListOption wrong")
	}

	// Renewal.
	rn := NewRenewalOption(1800)
	if rn.Type != OptRenewal || rn.Length != 4 {
		t.Error("RenewalOption wrong")
	}

	// Rebinding.
	rb := NewRebindingOption(3150)
	if rb.Type != OptRebinding || rb.Length != 4 {
		t.Error("RebindingOption wrong")
	}

	// End.
	end := EndOption()
	if end.Type != OptEnd || end.Length != 0 {
		t.Error("EndOption wrong")
	}
}

func TestDHCPParseWithOptions(t *testing.T) {
	// Build a full DHCPOFFER with options.
	layer := NewDHCP()
	layer.Set("op", uint8(BOOTREPLY))
	layer.Set("xid", uint32(0xAABBCCDD))
	layer.Set("yiaddr", net.ParseIP("172.16.0.50"))
	layer.Set("siaddr", net.ParseIP("172.16.0.1"))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPOFFER),
		NewServerIDOption("172.16.0.1"),
		NewLeaseTimeOption(7200),
		NewSubnetMaskOption("255.255.0.0"),
		NewRouterOption([]string{"172.16.0.1"}),
		NewDNSOption([]string{"172.16.0.53"}),
	})
	layer.Set("options", opts)

	raw, _ := layer.SerializeFields()

	// Parse it back.
	layer2 := NewDHCP()
	_, err := layer2.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Check header.
	op, _ := layer2.Get("op")
	if op.(uint8) != BOOTREPLY {
		t.Error("op mismatch")
	}

	yiaddr, _ := layer2.Get("yiaddr")
	if !yiaddr.(net.IP).Equal(net.ParseIP("172.16.0.50")) {
		t.Error("yiaddr mismatch")
	}

	// Check options.
	optData, _ := layer2.Get("options")
	opts2, err := ParseDHCPOptions(optData.([]byte))
	if err != nil {
		t.Fatal(err)
	}
	if GetMessageType(opts2) != DHCPOFFER {
		t.Error("message type mismatch")
	}

	// Verify DNS option.
	dns := GetDHCPOption(opts2, OptDNS)
	if dns == nil || len(dns.Value) != 4 {
		t.Error("DNS option mismatch")
	}

	// Verify lease time.
	lt := GetDHCPOption(opts2, OptLeaseTime)
	if lt == nil || binary.BigEndian.Uint32(lt.Value) != 7200 {
		t.Error("lease time mismatch")
	}
}

func TestDHCPEmptyOptionsAutoEnd(t *testing.T) {
	// BuildDHCPOptions always appends End.
	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPDISCOVER),
	})
	if len(opts) < 1 || opts[len(opts)-1] != OptEnd {
		t.Error("BuildDHCPOptions did not append End")
	}

	// BuildDHCPOptions with no options should produce just End.
	empty := BuildDHCPOptions(nil)
	if len(empty) != 1 || empty[0] != OptEnd {
		t.Errorf("BuildDHCPOptions(nil) = %#v, want [255]", empty)
	}

	// Options with End already don't get double End.
	opts2 := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPACK),
		EndOption(), // explicit End, should be filtered
	})
	endCount := 0
	for _, b := range opts2 {
		if b == OptEnd {
			endCount++
		}
	}
	if endCount != 1 {
		t.Errorf("double End: endCount=%d, want 1", endCount)
	}
}

func TestDHCPRelease(t *testing.T) {
	layer := NewDHCP()
	layer.Set("xid", uint32(0x11112222))
	layer.Set("ciaddr", net.ParseIP("192.168.1.100"))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPRELEASE),
		NewServerIDOption("192.168.1.1"),
	})
	layer.Set("options", opts)

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]byte, 240)
	expected[0] = BOOTREQUEST
	expected[1] = 1
	expected[2] = 6
	binary.BigEndian.PutUint32(expected[4:8], 0x11112222)
	copy(expected[12:16], net.ParseIP("192.168.1.100").To4())
	binary.BigEndian.PutUint32(expected[236:240], MagicCookie)

	expected = append(expected,
		53, 1, 7, // RELEASE
		54, 4, 192, 168, 1, 1, // Server ID
		255,
	)

	if !bytes.Equal(got, expected) {
		t.Errorf("DHCPRELEASE mismatch:\n got  %#v\nwant %#v", got, expected)
	}
}

func TestDHCPInform(t *testing.T) {
	layer := NewDHCP()
	layer.Set("xid", uint32(0x99990000))
	layer.Set("ciaddr", net.ParseIP("10.0.0.50"))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPINFORM),
	})
	layer.Set("options", opts)

	got, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]byte, 240)
	expected[0] = BOOTREQUEST
	expected[1] = 1
	expected[2] = 6
	binary.BigEndian.PutUint32(expected[4:8], 0x99990000)
	copy(expected[12:16], net.ParseIP("10.0.0.50").To4())
	binary.BigEndian.PutUint32(expected[236:240], MagicCookie)

	expected = append(expected, 53, 1, 8, 255)

	if !bytes.Equal(got, expected) {
		t.Errorf("DHCPINFORM mismatch:\n got  %#v\nwant %#v", got, expected)
	}
}

func TestDHCPChaddr(t *testing.T) {
	layer := NewDHCP()

	// Set a 6-byte MAC as chaddr (should be right-padded to 16 bytes).
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	layer.Set("chaddr", mac)

	raw, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// chaddr is at offset 28 (after 4+4+4+16 bytes of IP fields).
	// Actually: op(1)+htype(1)+hlen(1)+hops(1)+xid(4)+secs(2)+flags(2)+ciaddr(4)+yiaddr(4)+siaddr(4)+giaddr(4) = 28
	for i := 0; i < 6; i++ {
		if raw[28+i] != mac[i] {
			t.Errorf("chaddr[%d] = %#x, want %#x", i, raw[28+i], mac[i])
		}
	}
	// Remaining 10 bytes should be zero-padded.
	for i := 6; i < 16; i++ {
		if raw[28+i] != 0 {
			t.Errorf("chaddr[%d] = %#x, want 0 (padding)", i, raw[28+i])
		}
	}

	// Parse back.
	layer2 := NewDHCP()
	_, err = layer2.ParseFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	chaddr, _ := layer2.Get("chaddr")
	parsed := chaddr.([]byte)
	if !bytes.Equal(parsed[:6], mac) {
		t.Error("chaddr parse mismatch")
	}
}

func TestDHCPSnameFile(t *testing.T) {
	layer := NewDHCP()
	layer.Set("sname", []byte("myserver"))
	layer.Set("file", []byte("pxelinux.0"))

	raw, err := layer.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	// sname at offset 44 (28 + 16 chaddr), 64 bytes.
	snameOff := 44
	if string(raw[snameOff:snameOff+8]) != "myserver" {
		t.Errorf("sname = %q", raw[snameOff:snameOff+8])
	}
	// Should be zero-padded.
	if raw[snameOff+63] != 0 {
		t.Error("sname not zero-padded")
	}

	// file at offset 108 (44 + 64 sname), 128 bytes.
	fileOff := 108
	if string(raw[fileOff:fileOff+10]) != "pxelinux.0" {
		t.Errorf("file = %q", raw[fileOff:fileOff+10])
	}
	if raw[fileOff+127] != 0 {
		t.Error("file not zero-padded")
	}
}

func TestDHCPOverUDPOverIPOverEther(t *testing.T) {
	// Full stack test: Ether/IP/UDP/DHCP with Raw options payload.
	// This tests that the DHCP layer integrates with the full packet pipeline.
	dhcp := NewDHCP()
	dhcp.Set("xid", uint32(0x12345678))
	dhcp.Set("flags", uint16(0x8000))

	opts := BuildDHCPOptions([]fields.TLVOption{
		NewMessageTypeOption(DHCPDISCOVER),
		NewParamListOption([]uint8{1, 3, 6, 15}),
	})
	dhcp.Set("options", opts)

	// We use Raw layer to carry DHCP bytes as UDP payload.
	// This simulates how DHCP would work in real packet building.
	dhcpBytes, err := dhcp.SerializeFields()
	if err != nil {
		t.Fatal(err)
	}

	raw := packet.NewLayer("Raw", []fields.Field{
		fields.NewStrField("load", ""),
	})
	raw.Set("load", dhcpBytes)

	eth := packet.NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		fields.NewMACField("src", net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		fields.NewShortField("type", 0x0800),
	})
	ip := packet.NewLayer("IP", []fields.Field{
		fields.NewByteField("verihl", 0x45),
		fields.NewByteField("dscpecn", 0),
		fields.NewShortField("len", 20),
		fields.NewShortField("id", 0),
		fields.NewShortField("flagsfrag", 0),
		fields.NewByteField("ttl", 64),
		fields.NewByteField("proto", 17),
		fields.NewShortField("chksum", 0),
		fields.NewIPField("src", net.IPv4zero),
		fields.NewIPField("dst", net.IPv4zero),
	})
	ip.Set("src", "192.168.1.10")
	ip.Set("dst", "255.255.255.255")

	udp := packet.NewLayer("UDP", []fields.Field{
		fields.NewShortField("sport", 0),
		fields.NewShortField("dport", 0),
		fields.NewShortField("len", 8),
		fields.NewShortField("chksum", 0),
	})
	udp.Set("sport", uint16(68))
	udp.Set("dport", uint16(67))

	pkt := packet.NewFrom(eth, ip, udp, raw)
	built, err := pkt.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the DHCP data starts after Ether(14) + IP(20) + UDP(8).
	dhcpStart := 14 + 20 + 8
	if len(built) < dhcpStart+240 {
		t.Fatalf("built packet too short: %d", len(built))
	}
	if built[dhcpStart] != BOOTREQUEST {
		t.Errorf("DHCP op = %#x", built[dhcpStart])
	}
	// Verify cookie.
	if binary.BigEndian.Uint32(built[dhcpStart+236:dhcpStart+240]) != MagicCookie {
		t.Error("cookie not found in built packet")
	}
}

func TestUint8OverflowInOptionLength(t *testing.T) {
	// Test that BuildDHCPOptions doesn't error on options with length > 255.
	// In practice, DHCP options have small lengths, but the TLV framework
	// uses uint8 for length. This test verifies no overflow.
	largeVal := make([]byte, 255)
	opt := fields.TLVOption{Type: 100, Length: 255, Value: largeVal}
	got := BuildDHCPOptions([]fields.TLVOption{opt})
	if len(got) != 257+1 { // type(1) + length(1) + value(255) + End(1)
		t.Errorf("large option len = %d, want 258", len(got))
	}
}

func TestParsePartialDHCP(t *testing.T) {
	// Test that parsing truncated DHCP data returns an error.
	layer := NewDHCP()
	// Only 10 bytes — not enough for even the fixed header.
	_, err := layer.ParseFields(make([]byte, 10))
	if err == nil {
		t.Error("expected error for truncated DHCP data")
	}
}

func TestStrFixedFieldOverflow(t *testing.T) {
	// Test that StrFixedField rejects values larger than its fixed size.
	f := fields.NewStrFixedField("test", 4, make([]byte, 4))
	_, err := f.Pack([]byte("too_long"))
	if err == nil {
		t.Error("expected error for oversized value")
	}
}