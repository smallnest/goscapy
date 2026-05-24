package bt

import (
	"testing"
)

func TestNewHCI(t *testing.T) {
	layer := NewHCI()
	typ, _ := layer.Get("type")
	if typ.(uint8) != HCICommand {
		t.Errorf("default type = %d, want %d", typ, HCICommand)
	}
}

func TestHCISerializeParse(t *testing.T) {
	layer := NewHCI()
	layer.Set("type", uint8(HCICommand))
	layer.Set("opcode", uint16(0x0406)) // HCI_Reset
	layer.Set("param_len", uint8(0))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// type(1) + opcode(2) + param_len(1) + params(0) = 4
	if len(data) != 4 {
		t.Errorf("size = %d, want 4", len(data))
	}
	if data[0] != HCICommand {
		t.Errorf("type = %d", data[0])
	}

	layer2 := NewHCI()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 4 {
		t.Errorf("consumed = %d, want 4", n)
	}

	opcode, _ := layer2.Get("opcode")
	if opcode.(uint16) != 0x0406 {
		t.Errorf("opcode = %#x, want 0x0406", opcode)
	}
}

func TestHCIEventRoundTrip(t *testing.T) {
	layer := NewHCI()
	layer.Set("type", uint8(HCIEvent))
	layer.Set("opcode", uint16(0x0E)) // Command Complete
	layer.Set("param_len", uint8(3))
	layer.Set("params", []byte{0x01, 0x03, 0x0C})

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}

	layer2 := NewHCI()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	typ, _ := layer2.Get("type")
	if typ.(uint8) != HCIEvent {
		t.Errorf("type = %d", typ)
	}
}

func TestNewL2CAP(t *testing.T) {
	layer := NewL2CAP()
	cid, _ := layer.Get("cid")
	if cid.(uint16) != L2CAPCIDATT {
		t.Errorf("default cid = %#x, want %#x", cid, L2CAPCIDATT)
	}
}

func TestL2CAPRoundTrip(t *testing.T) {
	layer := NewL2CAP()
	layer.Set("length", uint16(5))
	layer.Set("cid", uint16(L2CAPCIDATT))
	layer.Set("data", []byte{0x0A, 0x00, 0x01, 0x00, 0x00})

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// length(2) + cid(2) + data(5) = 9
	if len(data) != 9 {
		t.Errorf("size = %d, want 9", len(data))
	}

	layer2 := NewL2CAP()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 9 {
		t.Errorf("consumed = %d, want 9", n)
	}

	cid, _ := layer2.Get("cid")
	if cid.(uint16) != L2CAPCIDATT {
		t.Errorf("cid = %#x", cid)
	}
}

func TestATTRoundTrip(t *testing.T) {
	layer := NewATT()
	layer.Set("opcode", uint8(ATTOpcodeReadReq))
	layer.Set("params", []byte{0x01, 0x00}) // handle = 0x0001

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// opcode(1) + params(2) = 3
	if len(data) != 3 {
		t.Errorf("size = %d, want 3", len(data))
	}
	if data[0] != ATTOpcodeReadReq {
		t.Errorf("opcode = %#x", data[0])
	}

	layer2 := NewATT()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	op, _ := layer2.Get("opcode")
	if op.(uint8) != ATTOpcodeReadReq {
		t.Errorf("opcode = %#x", op)
	}
}

func TestSMRoundTrip(t *testing.T) {
	layer := NewSM()
	layer.Set("opcode", uint8(SMOpcodePairingReq))
	layer.Set("data", []byte{0x03, 0x00, 0x01, 0x10, 0x07, 0x07})

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// opcode(1) + data(6) = 7
	if len(data) != 7 {
		t.Errorf("size = %d, want 7", len(data))
	}
}

func TestParseBuildEIR(t *testing.T) {
	entries := []EIR{
		{Type: EIRTypeFlags, Data: []byte{0x06}},
		{Type: EIRTypeCompleteName, Data: []byte("TestDevice")},
		{Type: EIRTypeTxPowerLevel, Data: []byte{0x04}},
	}

	raw := BuildEIR(entries)
	parsed, err := ParseEIR(raw)
	if err != nil {
		t.Fatalf("ParseEIR: %v", err)
	}
	if len(parsed) != 3 {
		t.Fatalf("entries = %d, want 3", len(parsed))
	}

	name := DeviceName(parsed)
	if name != "TestDevice" {
		t.Errorf("name = %q, want %q", name, "TestDevice")
	}

	flags := FindEIR(parsed, EIRTypeFlags)
	if flags == nil || flags.Data[0] != 0x06 {
		t.Errorf("flags = %v", flags)
	}
}

func TestParseEIRTruncated(t *testing.T) {
	data := []byte{0x05, 0x01, 0x06, 0x02} // length=5 but only 3 bytes follow
	_, err := ParseEIR(data)
	if err == nil {
		t.Error("expected error for truncated EIR")
	}
}

func TestParseATTError(t *testing.T) {
	params := []byte{ATTOpcodeReadReq, 0x01, 0x00, ATTErrorReadNotPermitted}
	errResp, err := ParseATTError(params)
	if err != nil {
		t.Fatalf("ParseATTError: %v", err)
	}
	if errResp.RequestOpcode != ATTOpcodeReadReq {
		t.Errorf("opcode = %#x", errResp.RequestOpcode)
	}
	if errResp.Handle != 0x0001 {
		t.Errorf("handle = %#x", errResp.Handle)
	}
	if errResp.ErrorCode != ATTErrorReadNotPermitted {
		t.Errorf("error = %#x", errResp.ErrorCode)
	}
}

func TestParseATTReadByTypeReq(t *testing.T) {
	params := []byte{0x01, 0x00, 0xFF, 0xFF, 0x00, 0x18} // handles 1-0xFFFF, UUID 0x1800
	req, err := ParseATTReadByTypeReq(params)
	if err != nil {
		t.Fatalf("ParseATTReadByTypeReq: %v", err)
	}
	if req.StartHandle != 1 {
		t.Errorf("start = %d", req.StartHandle)
	}
	if req.EndHandle != 0xFFFF {
		t.Errorf("end = %#x", req.EndHandle)
	}
	if len(req.UUID) != 2 {
		t.Errorf("UUID len = %d", len(req.UUID))
	}
}

func TestParseATTWriteReq(t *testing.T) {
	params := []byte{0x0A, 0x00, 0x01, 0x02, 0x03} // handle=0x000A, value=[1,2,3]
	req, err := ParseATTWriteReq(params)
	if err != nil {
		t.Fatalf("ParseATTWriteReq: %v", err)
	}
	if req.Handle != 0x000A {
		t.Errorf("handle = %#x", req.Handle)
	}
	if len(req.Value) != 3 {
		t.Errorf("value len = %d", len(req.Value))
	}
}

func TestParseATTNotify(t *testing.T) {
	params := []byte{0x0F, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F} // handle=0x000F, value="Hello"
	n, err := ParseATTNotify(params)
	if err != nil {
		t.Fatalf("ParseATTNotify: %v", err)
	}
	if n.Handle != 0x000F {
		t.Errorf("handle = %#x", n.Handle)
	}
	if string(n.Value) != "Hello" {
		t.Errorf("value = %q", string(n.Value))
	}
}

func TestParseSMPairingReq(t *testing.T) {
	data := []byte{0x03, 0x00, 0x01, 0x10, 0x07, 0x07}
	req, err := ParseSMPairingReq(data)
	if err != nil {
		t.Fatalf("ParseSMPairingReq: %v", err)
	}
	if req.IOCapability != 3 {
		t.Errorf("IOCap = %d", req.IOCapability)
	}
	if req.MaxEncSize != 0x10 {
		t.Errorf("MaxEncSize = %#x", req.MaxEncSize)
	}
}

func TestHCITypeString(t *testing.T) {
	if HCITypeString(HCICommand) != "Command" {
		t.Errorf("unexpected string")
	}
	if HCITypeString(99) != "Unknown(99)" {
		t.Errorf("unexpected unknown string")
	}
}

func TestATTOpcodeString(t *testing.T) {
	if ATTOpcodeString(ATTOpcodeReadReq) != "ReadReq" {
		t.Errorf("unexpected string")
	}
	if ATTOpcodeString(ATTOpcodeNotify) != "Notify" {
		t.Errorf("unexpected string")
	}
}

func TestFindEIRMissing(t *testing.T) {
	entries := []EIR{{Type: EIRTypeFlags, Data: []byte{0x06}}}
	if FindEIR(entries, EIRTypeCompleteName) != nil {
		t.Error("should return nil for missing EIR type")
	}
}

func TestDeviceNameEmpty(t *testing.T) {
	if DeviceName(nil) != "" {
		t.Error("should return empty for nil entries")
	}
}

func TestEIRZeroTerminator(t *testing.T) {
	data := []byte{0x03, 0x01, 0x06, 0x00} // flags entry + zero terminator
	parsed, err := ParseEIR(data)
	if err != nil {
		t.Fatalf("ParseEIR: %v", err)
	}
	if len(parsed) != 1 {
		t.Errorf("entries = %d, want 1", len(parsed))
	}
}
