package lorawan

import (
	"testing"
)

func TestNewLoRaWAN(t *testing.T) {
	layer := NewLoRaWAN()
	mhdr, _ := layer.Get("mhdr")
	expected := uint8(MTypeUnconfirmedUp)<<5 | Major
	if mhdr.(uint8) != expected {
		t.Errorf("default mhdr = %#x, want %#x", mhdr, expected)
	}
}

func TestLoRaWANRoundTrip(t *testing.T) {
	lwData := BuildLoRaWANData(&LoRaWANData{
		FOpts:   []byte{},
		FPort:   1,
		Payload: []byte{0xAA, 0xBB},
		MIC:     []byte{0x01, 0x02, 0x03, 0x04},
	})

	layer := NewLoRaWAN()
	_ = layer.Set("mhdr", uint8(MTypeConfirmedUp)<<5|Major)
	_ = layer.Set("dev_addr", uint32(0x01020304))
	_ = layer.Set("fctrl", uint8(0))
	_ = layer.Set("fcnt", uint16(42))
	_ = layer.Set("data", lwData)

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// mhdr(1) + dev_addr(4) + fctrl(1) + fcnt(2) + data(7: fport(1)+payload(2)+mic(4)) = 15
	if len(data) != 15 {
		t.Errorf("size = %d, want 15", len(data))
	}

	layer2 := NewLoRaWAN()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 15 {
		t.Errorf("consumed = %d, want 15", n)
	}

	devAddr, _ := layer2.Get("dev_addr")
	if devAddr.(uint32) != 0x01020304 {
		t.Errorf("dev_addr = %#x, want 0x01020304", devAddr)
	}
	fcnt, _ := layer2.Get("fcnt")
	if fcnt.(uint16) != 42 {
		t.Errorf("fcnt = %d, want 42", fcnt)
	}

	// Decompose data field
	dataField, _ := layer2.Get("data")
	parsed, err := ParseLoRaWANData(dataField.([]byte), 0)
	if err != nil {
		t.Fatalf("ParseLoRaWANData: %v", err)
	}
	if parsed.FPort != 1 {
		t.Errorf("FPort = %d, want 1", parsed.FPort)
	}
	if len(parsed.Payload) != 2 || parsed.Payload[0] != 0xAA {
		t.Errorf("Payload = %x, want [AA BB]", parsed.Payload)
	}
}

func TestLoRaWANWithFOpts(t *testing.T) {
	lwData := BuildLoRaWANData(&LoRaWANData{
		FOpts:   []byte{MACCmdLinkCheckAns, 0x05, 0x0A}, // 3 bytes of FOpts
		FPort:   2,
		Payload: []byte{0xCC},
		MIC:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
	})

	layer := NewLoRaWAN()
	_ = layer.Set("mhdr", uint8(MTypeUnconfirmedUp)<<5|Major)
	_ = layer.Set("dev_addr", uint32(0x11223344))
	_ = layer.Set("fctrl", uint8(3)) // FOptsLen=3
	_ = layer.Set("fcnt", uint16(1))
	_ = layer.Set("data", lwData)

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// mhdr(1) + dev_addr(4) + fctrl(1) + fcnt(2) + data(9: fopts(3)+fport(1)+payload(1)+mic(4)) = 17
	if len(data) != 17 {
		t.Errorf("size = %d, want 17", len(data))
	}

	layer2 := NewLoRaWAN()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	fctrl, _ := layer2.Get("fctrl")
	foptsLen := int(FCtrlFOptsLen(fctrl.(uint8)))
	dataField, _ := layer2.Get("data")
	parsed, err := ParseLoRaWANData(dataField.([]byte), foptsLen)
	if err != nil {
		t.Fatalf("ParseLoRaWANData: %v", err)
	}
	if len(parsed.FOpts) != 3 {
		t.Errorf("FOpts len = %d, want 3", len(parsed.FOpts))
	}
	if parsed.FPort != 2 {
		t.Errorf("FPort = %d, want 2", parsed.FPort)
	}
}

func TestLoRaWANJoinReqRoundTrip(t *testing.T) {
	layer := NewLoRaWANJoinReq()
	_ = layer.Set("mhdr", uint8(MTypeJoinRequest)<<5|Major)
	_ = layer.Set("app_eui", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	_ = layer.Set("dev_eui", []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18})
	_ = layer.Set("dev_nonce", uint16(0x1234))
	_ = layer.Set("mic", []byte{0xAA, 0xBB, 0xCC, 0xDD})

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	if len(data) != 23 {
		t.Errorf("size = %d, want 23", len(data))
	}

	layer2 := NewLoRaWANJoinReq()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 23 {
		t.Errorf("consumed = %d, want 23", n)
	}

	nonce, _ := layer2.Get("dev_nonce")
	if nonce.(uint16) != 0x1234 {
		t.Errorf("dev_nonce = %#x, want 0x1234", nonce)
	}
}

func TestLoRaWANJoinAcceptRoundTrip(t *testing.T) {
	jaData := BuildJoinAcceptData(&JoinAcceptData{
		CFList: []byte{},
		MIC:    []byte{0x11, 0x22, 0x33, 0x44},
	})

	layer := NewLoRaWANJoinAccept()
	_ = layer.Set("mhdr", uint8(MTypeJoinAccept)<<5|Major)
	_ = layer.Set("app_nonce", []byte{0x01, 0x02, 0x03})
	_ = layer.Set("net_id", []byte{0x04, 0x05, 0x06})
	_ = layer.Set("dev_addr", uint32(0x01020304))
	_ = layer.Set("dl_settings", uint8(0x03))
	_ = layer.Set("rx_delay", uint8(1))
	_ = layer.Set("data", jaData)

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// mhdr(1) + app_nonce(3) + net_id(3) + dev_addr(4) + dl_settings(1) + rx_delay(1) + data(4: mic only) = 17
	if len(data) != 17 {
		t.Errorf("size = %d, want 17", len(data))
	}

	layer2 := NewLoRaWANJoinAccept()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 17 {
		t.Errorf("consumed = %d, want 17", n)
	}

	devAddr, _ := layer2.Get("dev_addr")
	if devAddr.(uint32) != 0x01020304 {
		t.Errorf("dev_addr = %#x", devAddr)
	}

	// Decompose data field
	dataField, _ := layer2.Get("data")
	ja := ParseJoinAcceptData(dataField.([]byte))
	if len(ja.MIC) != 4 || ja.MIC[0] != 0x11 {
		t.Errorf("MIC = %x", ja.MIC)
	}
}

func TestMTypeFromMHDR(t *testing.T) {
	mhdr := uint8(MTypeJoinRequest) << 5
	if MTypeFromMHDR(mhdr) != MTypeJoinRequest {
		t.Errorf("MTypeFromMHDR = %d, want %d", MTypeFromMHDR(mhdr), MTypeJoinRequest)
	}
}

func TestMajorFromMHDR(t *testing.T) {
	if MajorFromMHDR(0x00) != 0 {
		t.Errorf("MajorFromMHDR = %d, want 0", MajorFromMHDR(0x00))
	}
}

func TestMTypeString(t *testing.T) {
	if MTypeString(MTypeJoinRequest) != "JoinRequest" {
		t.Errorf("unexpected MTypeString")
	}
	if MTypeString(MTypeUnconfirmedUp) != "UnconfirmedDataUp" {
		t.Errorf("unexpected MTypeString for UnconfirmedUp")
	}
	if MTypeString(99) != "Unknown(99)" {
		t.Errorf("unexpected unknown string")
	}
}

func TestFCtrlFOptsLen(t *testing.T) {
	if FCtrlFOptsLen(0x05) != 5 {
		t.Errorf("FOptsLen(0x05) = %d, want 5", FCtrlFOptsLen(0x05))
	}
	if FCtrlFOptsLen(0x0F) != 15 {
		t.Errorf("FOptsLen(0x0F) = %d, want 15", FCtrlFOptsLen(0x0F))
	}
}

func TestFCtrlFlags(t *testing.T) {
	fctrl := uint8(FCtrlADR | FCtrlAck)
	if !IsFCtrlADR(fctrl) {
		t.Error("ADR should be set")
	}
	if fctrl&FCtrlADRAckReq != 0 {
		t.Error("ADRAckReq should not be set")
	}
	if !IsFCtrlAck(fctrl) {
		t.Error("Ack should be set")
	}
}

func TestParseMACCommands(t *testing.T) {
	fopts := []byte{MACCmdLinkCheckAns, 0x05, 0x0A}
	cmds, err := ParseMACCommands(fopts)
	if err != nil {
		t.Fatalf("ParseMACCommands: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("cmds = %d, want 1", len(cmds))
	}
	if cmds[0].CID != MACCmdLinkCheckAns {
		t.Errorf("CID = %#x, want %#x", cmds[0].CID, MACCmdLinkCheckAns)
	}
	if len(cmds[0].Value) != 2 {
		t.Errorf("value len = %d, want 2", len(cmds[0].Value))
	}
}

func TestParseMACCommandsMultiple(t *testing.T) {
	fopts := []byte{MACCmdDevStatusReq, MACCmdLinkCheckAns, 0x03, 0x07}
	cmds, err := ParseMACCommands(fopts)
	if err != nil {
		t.Fatalf("ParseMACCommands: %v", err)
	}
	if len(cmds) != 2 {
		t.Fatalf("cmds = %d, want 2", len(cmds))
	}
	if cmds[0].CID != MACCmdDevStatusReq {
		t.Errorf("cmd[0] CID = %#x", cmds[0].CID)
	}
	if len(cmds[0].Value) != 0 {
		t.Errorf("cmd[0] value len = %d, want 0", len(cmds[0].Value))
	}
	if cmds[1].CID != MACCmdLinkCheckAns {
		t.Errorf("cmd[1] CID = %#x", cmds[1].CID)
	}
}

func TestBuildMACCommands(t *testing.T) {
	cmds := []MACCommand{
		{CID: MACCmdLinkCheckAns, Value: []byte{0x05, 0x0A}},
		{CID: MACCmdDevStatusReq},
	}
	wire := BuildMACCommands(cmds)
	if len(wire) != 4 {
		t.Errorf("wire len = %d, want 4", len(wire))
	}
	if wire[0] != MACCmdLinkCheckAns {
		t.Errorf("wire[0] = %#x", wire[0])
	}
	if wire[3] != MACCmdDevStatusReq {
		t.Errorf("wire[3] = %#x", wire[3])
	}
}

func TestParseMACCommandsTruncated(t *testing.T) {
	fopts := []byte{MACCmdLinkADRReq, 0x01, 0x02}
	_, err := ParseMACCommands(fopts)
	if err == nil {
		t.Error("expected error for truncated MAC command")
	}
}

func TestBuildLoRaWANDataRoundTrip(t *testing.T) {
	original := &LoRaWANData{
		FOpts:    []byte{MACCmdDevStatusReq},
		FPort:    10,
		Payload:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		MIC:      []byte{0x01, 0x02, 0x03, 0x04},
	}
	wire := BuildLoRaWANData(original)
	parsed, err := ParseLoRaWANData(wire, 1) // 1 byte FOpts
	if err != nil {
		t.Fatalf("ParseLoRaWANData: %v", err)
	}
	if parsed.FPort != 10 {
		t.Errorf("FPort = %d, want 10", parsed.FPort)
	}
	if len(parsed.Payload) != 4 {
		t.Errorf("Payload len = %d, want 4", len(parsed.Payload))
	}
	if parsed.FOpts[0] != MACCmdDevStatusReq {
		t.Errorf("FOpts[0] = %#x", parsed.FOpts[0])
	}
}

func TestParseLoRaWANDataTooShort(t *testing.T) {
	_, err := ParseLoRaWANData([]byte{0x01, 0x02}, 0) // need at least 5 bytes
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestParseLoRaWANDataInvalidFOptsLen(t *testing.T) {
	_, err := ParseLoRaWANData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20}, 16)
	if err == nil {
		t.Error("expected error for FOptsLen > 15")
	}
}
