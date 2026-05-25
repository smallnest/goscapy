package voip

import (
	"testing"
)

func TestRTPRoundTrip(t *testing.T) {
	h := RTPHeader{
		Version:     2,
		PayloadType: 0, // PCMU
		Sequence:    12345,
		Timestamp:   160000,
		SSRC:        0xDEADBEEF,
		Payload:     []byte{0x01, 0x02, 0x03, 0x04},
	}
	b := PackRTP(h)
	parsed, err := ParseRTP(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 2 {
		t.Errorf("Version = %d, want 2", parsed.Version)
	}
	if parsed.PayloadType != 0 {
		t.Errorf("PayloadType = %d, want 0", parsed.PayloadType)
	}
	if parsed.Sequence != 12345 {
		t.Errorf("Sequence = %d, want 12345", parsed.Sequence)
	}
	if parsed.Timestamp != 160000 {
		t.Errorf("Timestamp = %d, want 160000", parsed.Timestamp)
	}
	if parsed.SSRC != 0xDEADBEEF {
		t.Errorf("SSRC = %x, want DEADBEEF", parsed.SSRC)
	}
	if len(parsed.Payload) != 4 {
		t.Errorf("Payload len = %d, want 4", len(parsed.Payload))
	}
}

func TestRTPWithCSRC(t *testing.T) {
	h := RTPHeader{
		Version:     2,
		CSRCCount:   2,
		PayloadType: 8, // PCMA
		Sequence:    1,
		Timestamp:   0,
		SSRC:        0x11111111,
		CSRC:        []uint32{0x22222222, 0x33333333},
		Payload:     []byte{0xAA},
	}
	b := PackRTP(h)
	parsed, err := ParseRTP(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.CSRC) != 2 {
		t.Fatalf("CSRC count = %d, want 2", len(parsed.CSRC))
	}
	if parsed.CSRC[0] != 0x22222222 {
		t.Errorf("CSRC[0] = %x, want 22222222", parsed.CSRC[0])
	}
	if parsed.CSRC[1] != 0x33333333 {
		t.Errorf("CSRC[1] = %x, want 33333333", parsed.CSRC[1])
	}
}

func TestRTPWithExtension(t *testing.T) {
	h := RTPHeader{
		Version:     2,
		Extension:   true,
		PayloadType: 96,
		Sequence:    100,
		Timestamp:   999,
		SSRC:        0xAAAAAAAA,
		ExtProfile:  0x1234,
		ExtLength:   1,
		ExtData:     []byte{0, 0, 0, 1},
		Payload:     []byte{0xFF},
	}
	b := PackRTP(h)
	parsed, err := ParseRTP(b)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Extension {
		t.Error("Extension = false, want true")
	}
	if parsed.ExtProfile != 0x1234 {
		t.Errorf("ExtProfile = %x, want 1234", parsed.ExtProfile)
	}
	if len(parsed.ExtData) != 4 {
		t.Errorf("ExtData len = %d, want 4", len(parsed.ExtData))
	}
}

func TestRTPMarker(t *testing.T) {
	h := RTPHeader{
		Version:     2,
		Marker:      true,
		PayloadType: 96,
		Sequence:    1,
		Timestamp:   0,
		SSRC:        0,
		Payload:     nil,
	}
	b := PackRTP(h)
	parsed, err := ParseRTP(b)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Marker {
		t.Error("Marker = false, want true")
	}
}

func TestRTPBadVersion(t *testing.T) {
	data := []byte{0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // V=0
	_, err := ParseRTP(data)
	if err == nil {
		t.Error("expected error for bad version")
	}
}

func TestRTCPCompound(t *testing.T) {
	// Build a compound: SR + BYE.
	sr := RTCPSenderReport{
		SSRC:        0x12345678,
		NTPMSW:      0,
		NTPLSW:      0,
		RTPTime:     1600,
		PacketCount: 100,
		OctetCount:  8000,
	}
	srBytes := PackSenderReport(sr)

	bye := RTCPBYEPacket{
		Sources: []uint32{0x12345678},
		Reason:  "goodbye",
	}
	byeBytes := PackBYEPacket(bye)

	compound := append(srBytes, byeBytes...)

	packets, err := ParseRTCPPackets(compound)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 2 {
		t.Fatalf("got %d packets, want 2", len(packets))
	}
	if packets[0].Type != RTCPSR {
		t.Errorf("packet[0].Type = %d, want SR(%d)", packets[0].Type, RTCPSR)
	}
	if packets[1].Type != RTCPBYE {
		t.Errorf("packet[1].Type = %d, want BYE(%d)", packets[1].Type, RTCPBYE)
	}
}

func TestRTCPSenderReport(t *testing.T) {
	sr := RTCPSenderReport{
		SSRC:        0xABCDEF01,
		NTPMSW:      1000,
		NTPLSW:      2000,
		RTPTime:     3000,
		PacketCount: 50,
		OctetCount:  4000,
		Reports: []RTCPReceiverBlock{
			{
				SSRC:         0x11111111,
				FractionLost: 0,
				PacketsLost:  0,
				LastSeq:      1000,
				Jitter:       5,
				LSR:          0,
				DLSR:         0,
			},
		},
	}
	b := PackSenderReport(sr)

	packets, err := ParseRTCPPackets(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("got %d packets, want 1", len(packets))
	}
	if packets[0].Type != RTCPSR {
		t.Errorf("Type = %d, want SR", packets[0].Type)
	}

	parsed, err := ParseSenderReport(packets[0].RawPayload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SSRC != 0xABCDEF01 {
		t.Errorf("SSRC = %x, want ABCDEF01", parsed.SSRC)
	}
	if parsed.PacketCount != 50 {
		t.Errorf("PacketCount = %d, want 50", parsed.PacketCount)
	}
	if len(parsed.Reports) != 1 {
		t.Fatalf("Reports = %d, want 1", len(parsed.Reports))
	}
	if parsed.Reports[0].SSRC != 0x11111111 {
		t.Errorf("Report.SSRC = %x, want 11111111", parsed.Reports[0].SSRC)
	}
}

func TestRTCPReceiverReport(t *testing.T) {
	rr := RTCPReceiverReport{
		SSRC: 0x22222222,
		Reports: []RTCPReceiverBlock{
			{
				SSRC:         0x33333333,
				FractionLost: 10,
				PacketsLost:  5,
				LastSeq:      500,
				Jitter:       100,
				LSR:          0xAAAA,
				DLSR:         0xBBBB,
			},
		},
	}
	b := PackReceiverReport(rr)
	packets, err := ParseRTCPPackets(b)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceiverReport(packets[0].RawPayload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SSRC != 0x22222222 {
		t.Errorf("SSRC = %x, want 22222222", parsed.SSRC)
	}
	if parsed.Reports[0].FractionLost != 10 {
		t.Errorf("FractionLost = %d, want 10", parsed.Reports[0].FractionLost)
	}
	if parsed.Reports[0].PacketsLost != 5 {
		t.Errorf("PacketsLost = %d, want 5", parsed.Reports[0].PacketsLost)
	}
}

func TestRTCPBYE(t *testing.T) {
	bye := RTCPBYEPacket{
		Sources: []uint32{0x11111111, 0x22222222},
		Reason:  "session ended",
	}
	b := PackBYEPacket(bye)
	packets, err := ParseRTCPPackets(b)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBYEPacket(packets[0].RC, packets[0].RawPayload)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Sources) != 2 {
		t.Fatalf("Sources = %d, want 2", len(parsed.Sources))
	}
	if parsed.Sources[0] != 0x11111111 {
		t.Errorf("Sources[0] = %x, want 11111111", parsed.Sources[0])
	}
	if parsed.Reason != "session ended" {
		t.Errorf("Reason = %q, want 'session ended'", parsed.Reason)
	}
}

func TestRTCPSDES(t *testing.T) {
	// Build SDES packet manually via compound parse.
	sdesData := []byte{
		// Chunk 1: SSRC
		0x11, 0x11, 0x11, 0x11,
		// Item: CNAME, len=6, "user12"
		0x01, 0x06, 'u', 's', 'e', 'r', '1', '2',
		// End item
		0x00,
		// Padding to 4-byte boundary
		0x00, 0x00,
	}
	// Wrap as RTCP SDES packet.
	pktBytes := PackRTCPPacket(1, RTCPSDES, sdesData)
	packets, err := ParseRTCPPackets(pktBytes)
	if err != nil {
		t.Fatal(err)
	}
	if packets[0].Type != RTCPSDES {
		t.Errorf("Type = %d, want SDES", packets[0].Type)
	}
	sdes, err := ParseSDESPacket(packets[0].RC, packets[0].RawPayload)
	if err != nil {
		t.Fatal(err)
	}
	if len(sdes.Chunks) != 1 {
		t.Fatalf("Chunks = %d, want 1", len(sdes.Chunks))
	}
	if len(sdes.Chunks[0].Items) != 1 {
		t.Fatalf("Items = %d, want 1", len(sdes.Chunks[0].Items))
	}
	if sdes.Chunks[0].Items[0].Type != SDESCNAME {
		t.Errorf("Item.Type = %d, want CNAME(%d)", sdes.Chunks[0].Items[0].Type, SDESCNAME)
	}
	if sdes.Chunks[0].Items[0].Data != "user12" {
		t.Errorf("Item.Data = %q, want 'user12'", sdes.Chunks[0].Items[0].Data)
	}
}

func TestSIPRequest(t *testing.T) {
	raw := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhds\r\n" +
		"From: Alice <sip:alice@example.com>;tag=1928301774\r\n" +
		"To: Bob <sip:bob@example.com>\r\n" +
		"Call-ID: a84b4c76e66710@pc33.example.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:alice@pc33.example.com>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 4\r\n" +
		"\r\n" +
		"test"

	msg, err := ParseSIP([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !msg.IsRequest() {
		t.Error("expected request")
	}
	if msg.Method != SIPInvite {
		t.Errorf("Method = %q, want INVITE", msg.Method)
	}
	if msg.RequestURI != "sip:bob@example.com" {
		t.Errorf("RequestURI = %q, want sip:bob@example.com", msg.RequestURI)
	}
	if msg.Version != "SIP/2.0" {
		t.Errorf("Version = %q, want SIP/2.0", msg.Version)
	}
	if msg.CallID() != "a84b4c76e66710@pc33.example.com" {
		t.Errorf("Call-ID = %q", msg.CallID())
	}
	if msg.ContentType() != "application/sdp" {
		t.Errorf("Content-Type = %q", msg.ContentType())
	}
	if msg.ContentLength() != 4 {
		t.Errorf("Content-Length = %d, want 4", msg.ContentLength())
	}
	if msg.Body != "test" {
		t.Errorf("Body = %q, want 'test'", msg.Body)
	}
}

func TestSIPResponse(t *testing.T) {
	raw := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776\r\n" +
		"From: Alice <sip:alice@example.com>;tag=1928301774\r\n" +
		"To: Bob <sip:bob@example.com>;tag=9876\r\n" +
		"Call-ID: a84b4c76e66710@pc33.example.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"

	msg, err := ParseSIP([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.IsRequest() {
		t.Error("expected response")
	}
	if msg.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", msg.StatusCode)
	}
	if msg.Reason != "OK" {
		t.Errorf("Reason = %q, want OK", msg.Reason)
	}
	if msg.CSeq() != "314159 INVITE" {
		t.Errorf("CSeq = %q", msg.CSeq())
	}
}

func TestSIPSerializeRoundTrip(t *testing.T) {
	msg := SIPMessage{
		Method:     SIPInvite,
		RequestURI: "sip:bob@example.com",
		Version:    "SIP/2.0",
		Headers: []SIPHeader{
			{Name: "Via", Value: "SIP/2.0/UDP 10.0.0.1:5060;branch=z9"},
			{Name: "From", Value: "<sip:alice@example.com>;tag=1"},
			{Name: "To", Value: "<sip:bob@example.com>"},
			{Name: "Call-ID", Value: "test@example.com"},
			{Name: "CSeq", Value: "1 INVITE"},
			{Name: "Content-Length", Value: "5"},
		},
		Body: "hello",
	}
	serialized := SerializeSIP(msg)
	parsed, err := ParseSIPString(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Method != SIPInvite {
		t.Errorf("Method = %q, want INVITE", parsed.Method)
	}
	if parsed.Body != "hello" {
		t.Errorf("Body = %q, want 'hello'", parsed.Body)
	}
	if parsed.CallID() != "test@example.com" {
		t.Errorf("CallID = %q", parsed.CallID())
	}
}

func TestSIPResponseRoundTrip(t *testing.T) {
	msg := SIPMessage{
		Version:    "SIP/2.0",
		StatusCode: 180,
		Reason:     "Ringing",
		Headers: []SIPHeader{
			{Name: "Call-ID", Value: "abc123"},
			{Name: "Content-Length", Value: "0"},
		},
	}
	b := PackSIP(msg)
	parsed, err := ParseSIP(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.StatusCode != 180 {
		t.Errorf("StatusCode = %d, want 180", parsed.StatusCode)
	}
	if parsed.Reason != "Ringing" {
		t.Errorf("Reason = %q, want 'Ringing'", parsed.Reason)
	}
}

func TestSIPLineFolding(t *testing.T) {
	raw := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;\r\n" +
		" branch=z9hG4bK776\r\n" +
		"Call-ID: test\r\n" +
		"\r\n"

	msg, err := ParseSIP([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	via := msg.GetHeader("Via")
	if via != "SIP/2.0/UDP 10.0.0.1:5060; branch=z9hG4bK776" {
		t.Errorf("Via = %q", via)
	}
}

func TestRTPTooShort(t *testing.T) {
	_, err := ParseRTP([]byte{0x80, 0x00})
	if err == nil {
		t.Error("expected error for short RTP data")
	}
}

func TestRTCPTruncated(t *testing.T) {
	_, err := ParseRTCPPackets([]byte{0x80, 0xC8, 0x00})
	if err == nil {
		t.Error("expected error for truncated RTCP")
	}
}

func TestSIPEmpty(t *testing.T) {
	_, err := ParseSIP([]byte{})
	if err == nil {
		t.Error("expected error for empty SIP")
	}
}
