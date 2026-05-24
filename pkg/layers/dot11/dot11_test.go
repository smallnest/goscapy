package dot11

import (
	"bytes"
	"net"
	"testing"
)

func TestSetFC(t *testing.T) {
	fc := SetFC(TypeManagement, SubtypeBeacon, 0)
	if fc[0] != 0x80 {
		t.Errorf("fc[0] = %#x, want 0x80", fc[0])
	}
	if FCType(fc[0]) != TypeManagement {
		t.Errorf("type = %d, want 0", FCType(fc[0]))
	}
	if FCSubtype(fc[0]) != SubtypeBeacon {
		t.Errorf("subtype = %d, want 8", FCSubtype(fc[0]))
	}
}

func TestFCFlags(t *testing.T) {
	fc := SetFC(TypeData, 0, FlagToDS|FlagFromDS)
	if FCFlags(fc) != (FlagToDS | FlagFromDS) {
		t.Errorf("flags = %#x", FCFlags(fc))
	}
}

func TestSCSeqFrag(t *testing.T) {
	var sc uint16 = 0x0123 // seq=18, frag=3
	if SCSeq(sc) != 18 {
		t.Errorf("seq = %d, want 18", SCSeq(sc))
	}
	if SCFrag(sc) != 3 {
		t.Errorf("frag = %d, want 3", SCFrag(sc))
	}
}

func TestNewDot11(t *testing.T) {
	layer := NewDot11()
	fc0, _ := layer.Get("fc0")
	if fc0.(uint8) != 0x80 {
		t.Errorf("fc0 default = %#x, want 0x80 (beacon)", fc0)
	}
}

func TestDot11SerializeParse(t *testing.T) {
	layer := NewDot11()
	fc := SetFC(TypeManagement, SubtypeBeacon, 0)
	layer.Set("fc0", fc[0])
	layer.Set("fc1", fc[1])
	layer.Set("addr1", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	layer.Set("addr2", []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	layer.Set("addr3", []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	layer.Set("sc", uint16(0x0100)) // seq=16, frag=0

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// fc0(1) + fc1(1) + duration(2) + addr1(6) + addr2(6) + addr3(6) + sc(2) = 24
	if len(data) != 24 {
		t.Errorf("size = %d, want 24", len(data))
	}
	if data[0] != 0x80 {
		t.Errorf("fc[0] = %#x, want 0x80", data[0])
	}

	layer2 := NewDot11()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 24 {
		t.Errorf("consumed = %d, want 24", n)
	}

	addr2, _ := layer2.Get("addr2")
	mac, _ := addr2.(net.HardwareAddr)
	if !bytes.Equal(mac, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("addr2 = %v", addr2)
	}
}

func TestDot11BeaconRoundTrip(t *testing.T) {
	layer := NewDot11Beacon()
	layer.Set("timestamp", uint64(12345678))
	layer.Set("beacon_interval", uint16(100))
	layer.Set("cap", uint16(0x0411)) // ESS + privacy + short-slot

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// timestamp(8) + beacon_interval(2) + cap(2) = 12
	if len(data) != 12 {
		t.Errorf("size = %d, want 12", len(data))
	}

	layer2 := NewDot11Beacon()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	ts, _ := layer2.Get("timestamp")
	if ts.(uint64) != 12345678 {
		t.Errorf("timestamp = %d", ts)
	}
	bi, _ := layer2.Get("beacon_interval")
	if bi.(uint16) != 100 {
		t.Errorf("beacon_interval = %d", bi)
	}
}

func TestDot11AuthRoundTrip(t *testing.T) {
	layer := NewDot11Auth()
	layer.Set("algo", uint16(0))    // open
	layer.Set("seqnum", uint16(1))
	layer.Set("status", uint16(0))  // success

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	if len(data) != 6 {
		t.Errorf("size = %d, want 6", len(data))
	}

	layer2 := NewDot11Auth()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	algo, _ := layer2.Get("algo")
	if algo.(uint16) != 0 {
		t.Errorf("algo = %d", algo)
	}
	seq, _ := layer2.Get("seqnum")
	if seq.(uint16) != 1 {
		t.Errorf("seqnum = %d", seq)
	}
}

func TestDot11DeauthRoundTrip(t *testing.T) {
	layer := NewDot11Deauth()
	layer.Set("reason", uint16(ReasonDeauthLeaving))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	if len(data) != 2 {
		t.Errorf("size = %d, want 2", len(data))
	}

	layer2 := NewDot11Deauth()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	reason, _ := layer2.Get("reason")
	if reason.(uint16) != ReasonDeauthLeaving {
		t.Errorf("reason = %d, want %d", reason, ReasonDeauthLeaving)
	}
}

func TestDot11QoSRoundTrip(t *testing.T) {
	layer := NewDot11QoS()
	layer.Set("qos0", uint8(0x07)) // TID=0, Ack Policy=normal
	layer.Set("qos1", uint8(0))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	if len(data) != 2 {
		t.Errorf("size = %d, want 2", len(data))
	}
}

func TestDot11EltRoundTrip(t *testing.T) {
	layer := NewDot11Elt()
	layer.Set("id", uint8(EltIDSSID))
	layer.Set("len", uint8(4))
	layer.Set("info", []byte("test"))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// id(1) + len(1) + info(4) = 6
	if len(data) != 6 {
		t.Errorf("size = %d, want 6", len(data))
	}
	if data[0] != EltIDSSID {
		t.Errorf("id = %d, want %d", data[0], EltIDSSID)
	}

	layer2 := NewDot11Elt()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	id, _ := layer2.Get("id")
	if id.(uint8) != EltIDSSID {
		t.Errorf("id = %d", id)
	}
}

func TestBuildParseDot11Elts(t *testing.T) {
	elts := []IE{
		{ID: EltIDSSID, Info: []byte("TestNet")},
		{ID: EltIDSupportedRates, Info: []byte{0x82, 0x84, 0x8b, 0x96}},
		{ID: EltIDRSN, Info: make([]byte, 20)},
	}

	raw := BuildDot11Elts(elts)
	parsed, err := ParseDot11Elts(raw)
	if err != nil {
		t.Fatalf("ParseDot11Elts: %v", err)
	}

	if len(parsed) != 3 {
		t.Fatalf("got %d IEs, want 3", len(parsed))
	}

	ssid := SSIDFromIE(parsed)
	if ssid != "TestNet" {
		t.Errorf("SSID = %q, want %q", ssid, "TestNet")
	}

	if parsed[1].ID != EltIDSupportedRates {
		t.Errorf("IE[1] ID = %d, want %d", parsed[1].ID, EltIDSupportedRates)
	}
}

func TestParseDot11EltsTruncated(t *testing.T) {
	data := []byte{0, 10, 'h', 'e', 'l'} // ID=0, len=10, but only 3 bytes
	elts, err := ParseDot11Elts(data)
	if err == nil {
		t.Error("expected error for truncated IE")
	}
	if len(elts) != 0 {
		t.Errorf("got %d IEs on truncated data", len(elts))
	}
}

func TestRadioTapSerializeParse(t *testing.T) {
	layer := NewRadioTap()
	layer.Set("version", uint8(0))
	layer.Set("len", uint16(8))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	if len(data) < 8 {
		t.Errorf("size = %d, want >= 8", len(data))
	}

	layer2 := NewRadioTap()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 8 {
		t.Errorf("consumed = %d, want 8", n)
	}
}

func TestRadioTapWithFields(t *testing.T) {
	// Build a RadioTap with TSFT + Rate + dBm_AntSignal present.
	layer := NewRadioTap()

	// Build variable field data manually:
	// TSFT (bit 0): 8 bytes, aligned to 4 → offset 0
	// Flags (bit 1): not set
	// Rate (bit 2): 1 byte → offset 8
	// dBm_AntSignal (bit 5): 1 byte → offset 9
	var fieldData []byte
	fieldData = append(fieldData, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}...) // TSFT
	fieldData = append(fieldData, 0x12)   // Rate = 18 → 9 Mbps
	fieldData = append(fieldData, 0xC5)   // dBm signal = -59

	present := uint32(1<<RTFlagTSFT | 1<<RTFlagRate | 1<<RTFlagDBmAntSignal)
	layer.Set("present", present)
	layer.Set("data", fieldData)
	layer.Set("len", uint16(8+len(fieldData))) // 8 fixed + 10 variable = 18

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}

	// Parse it back.
	layer2 := NewRadioTap()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}

	p, _ := layer2.Get("present")
	gotPresent := p.(uint32)
	if gotPresent != present {
		t.Errorf("present = %#x, want %#x", gotPresent, present)
	}

	// Parse the variable fields.
	d, _ := layer2.Get("data")
	parsed := ParseRadioTapData(d.([]byte), gotPresent)

	tsft, ok := parsed["tsft"]
	if !ok {
		t.Error("missing tsft")
	} else if tsft.(uint64) != 0x0807060504030201 {
		t.Errorf("tsft = %#x", tsft)
	}

	rate, ok := parsed["rate"]
	if !ok {
		t.Error("missing rate")
	} else if rate.(uint8) != 0x12 {
		t.Errorf("rate = %#x", rate)
	}

	sig, ok := parsed["dbm_antsignal"]
	if !ok {
		t.Error("missing dbm_antsignal")
	} else if sig.(int8) != -59 {
		t.Errorf("dbm_antsignal = %d, want -59", sig)
	}
}

func TestDot11ProbeReqRoundTrip(t *testing.T) {
	layer := NewDot11ProbeReq()
	layer.Set("data", BuildDot11Elts([]IE{
		{ID: EltIDSSID, Info: []byte("")},
	}))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}

	layer2 := NewDot11ProbeReq()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
}

func TestDot11ProbeRespRoundTrip(t *testing.T) {
	layer := NewDot11ProbeResp()
	layer.Set("timestamp", uint64(99999))
	layer.Set("beacon_interval", uint16(100))
	layer.Set("cap", uint16(0x0411))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	if len(data) != 12 {
		t.Errorf("size = %d, want 12", len(data))
	}
}

func TestFindIE(t *testing.T) {
	elts := []IE{
		{ID: 1, Info: []byte{1, 2}},
		{ID: 3, Info: []byte{3}},
	}
	if FindIE(elts, 5) != nil {
		t.Error("FindIE(5) should return nil")
	}
	if ie := FindIE(elts, 3); ie == nil || ie.ID != 3 {
		t.Error("FindIE(3) failed")
	}
}
