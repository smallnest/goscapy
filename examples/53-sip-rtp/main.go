// 示例 53: SIP/RTP/RTCP VoIP 协议层
//
// 运行: go run main.go
package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers/voip"
)

func main() {
	fmt.Println("=== SIP/RTP/RTCP VoIP 协议层示例 ===")
	fmt.Println()

	// 1. SIP INVITE
	fmt.Println("--- 1. SIP INVITE ---")
	invite := voip.SIPMessage{
		Method:     voip.SIPInvite,
		RequestURI: "sip:bob@example.com",
		Version:    "SIP/2.0",
		Headers: []voip.SIPHeader{
			{Name: "Via", Value: "SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776"},
			{Name: "From", Value: "Alice <sip:alice@example.com>;tag=1928301774"},
			{Name: "To", Value: "Bob <sip:bob@example.com>"},
			{Name: "Call-ID", Value: "a84b4c76e66710@pc33.example.com"},
			{Name: "CSeq", Value: "314159 INVITE"},
			{Name: "Contact", Value: "<sip:alice@pc33.example.com>"},
			{Name: "Content-Type", Value: "application/sdp"},
			{Name: "Content-Length", Value: "0"},
		},
	}
	raw := voip.SerializeSIP(invite)
	fmt.Printf("  INVITE message (%d bytes):\n", len(raw))

	parsed, err := voip.ParseSIP([]byte(raw))
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  Method: %s\n", parsed.Method)
	fmt.Printf("  Request-URI: %s\n", parsed.RequestURI)
	fmt.Printf("  Call-ID: %s\n", parsed.CallID())
	fmt.Printf("  From: %s\n", parsed.From())
	fmt.Printf("  To: %s\n", parsed.To())

	// 2. SIP 200 OK Response
	fmt.Println()
	fmt.Println("--- 2. SIP 200 OK ---")
	ok := voip.SIPMessage{
		Version:    "SIP/2.0",
		StatusCode: 200,
		Reason:     "OK",
		Headers: []voip.SIPHeader{
			{Name: "Via", Value: "SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776"},
			{Name: "From", Value: "Alice <sip:alice@example.com>;tag=1928301774"},
			{Name: "To", Value: "Bob <sip:bob@example.com>;tag=9876"},
			{Name: "Call-ID", Value: "a84b4c76e66710@pc33.example.com"},
			{Name: "CSeq", Value: "314159 INVITE"},
			{Name: "Content-Length", Value: "0"},
		},
	}
	okRaw := voip.PackSIP(ok)
	okParsed, err := voip.ParseSIP(okRaw)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  Status: %d %s\n", okParsed.StatusCode, okParsed.Reason)
	fmt.Printf("  IsRequest: %v\n", okParsed.IsRequest())

	// 3. RTP packet
	fmt.Println()
	fmt.Println("--- 3. RTP ---")
	rtp := voip.RTPHeader{
		Version:     2,
		PayloadType: voip.RTPPayloadPCMU,
		Sequence:    1,
		Timestamp:   160,
		SSRC:        0x12345678,
		Payload:     []byte{0x01, 0x02, 0x03, 0x04},
	}
	rtpBytes := voip.PackRTP(rtp)
	fmt.Printf("  RTP packet: %d bytes\n", len(rtpBytes))

	rtpParsed, err := voip.ParseRTP(rtpBytes)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  V=%d PT=%d Seq=%d TS=%d SSRC=%08X\n",
		rtpParsed.Version, rtpParsed.PayloadType, rtpParsed.Sequence,
		rtpParsed.Timestamp, rtpParsed.SSRC)

	// 4. RTP with CSRC and extension
	fmt.Println()
	fmt.Println("--- 4. RTP with CSRC + Extension ---")
	rtpExt := voip.RTPHeader{
		Version:     2,
		Extension:   true,
		CSRCCount:   2,
		PayloadType: voip.RTPPayloadDynMin,
		Sequence:    100,
		Timestamp:   320,
		SSRC:        0xAAAAAAAA,
		CSRC:        []uint32{0x11111111, 0x22222222},
		ExtProfile:  0x1234,
		ExtLength:   1,
		ExtData:     []byte{0, 0, 0, 1},
		Payload:     []byte{0xFF, 0xFE},
	}
	rtpExtBytes := voip.PackRTP(rtpExt)
	fmt.Printf("  RTP+CSRC+Ext packet: %d bytes\n", len(rtpExtBytes))

	extParsed, err := voip.ParseRTP(rtpExtBytes)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  CSRC: %v\n", extParsed.CSRC)
	fmt.Printf("  ExtProfile: %04X ExtData: %v\n", extParsed.ExtProfile, extParsed.ExtData)

	// 5. RTCP Sender Report
	fmt.Println()
	fmt.Println("--- 5. RTCP Sender Report ---")
	sr := voip.RTCPSenderReport{
		SSRC:        0x12345678,
		NTPMSW:      1000000,
		NTPLSW:      0,
		RTPTime:     160,
		PacketCount: 42,
		OctetCount:  3360,
		Reports: []voip.RTCPReceiverBlock{
			{SSRC: 0xBBBBBBBB, FractionLost: 0, PacketsLost: 0, LastSeq: 42, Jitter: 5},
		},
	}
	srBytes := voip.PackSenderReport(sr)
	fmt.Printf("  SR packet: %d bytes\n", len(srBytes))

	pkts, err := voip.ParseRTCPPackets(srBytes)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	srParsed, err := voip.ParseSenderReport(pkts[0].RawPayload)
	if err != nil {
		fmt.Printf("  Parse SR error: %v\n", err)
		return
	}
	fmt.Printf("  SSRC=%08X Packets=%d Octets=%d Reports=%d\n",
		srParsed.SSRC, srParsed.PacketCount, srParsed.OctetCount, len(srParsed.Reports))

	// 6. RTCP BYE
	fmt.Println()
	fmt.Println("--- 6. RTCP BYE ---")
	bye := voip.RTCPBYEPacket{
		Sources: []uint32{0x12345678},
		Reason:  "call ended",
	}
	byeBytes := voip.PackBYEPacket(bye)
	fmt.Printf("  BYE packet: %d bytes\n", len(byeBytes))

	pkts2, err := voip.ParseRTCPPackets(byeBytes)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	byeParsed, err := voip.ParseBYEPacket(pkts2[0].RC, pkts2[0].RawPayload)
	if err != nil {
		fmt.Printf("  Parse BYE error: %v\n", err)
		return
	}
	fmt.Printf("  Sources: %v Reason: %q\n", byeParsed.Sources, byeParsed.Reason)

	// 7. Compound RTCP: SR + BYE
	fmt.Println()
	fmt.Println("--- 7. Compound RTCP (SR + BYE) ---")
	compound := append(srBytes, byeBytes...)
	allPkts, err := voip.ParseRTCPPackets(compound)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  Parsed %d compound packets\n", len(allPkts))
	for i, p := range allPkts {
		fmt.Printf("    packet[%d]: type=%d length=%d\n", i, p.Type, p.Length)
	}
}
