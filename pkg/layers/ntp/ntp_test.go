package ntp

import (
	"testing"
)

func TestNewNTP(t *testing.T) {
	layer := NewNTP()

	lvm, _ := layer.Get("lvm")
	if lvm.(uint8) != 0x23 {
		t.Errorf("lvm default = %#x, want 0x23", lvm)
	}

	stratum, _ := layer.Get("stratum")
	if stratum.(uint8) != 0 {
		t.Errorf("stratum default = %d, want 0", stratum)
	}
}

func TestLI_VN_Mode(t *testing.T) {
	lvm := SetLVM(LINoWarning, 4, ModeClient)
	if LI(lvm) != 0 {
		t.Errorf("LI = %d, want 0", LI(lvm))
	}
	if VN(lvm) != 4 {
		t.Errorf("VN = %d, want 4", VN(lvm))
	}
	if Mode(lvm) != 3 {
		t.Errorf("Mode = %d, want 3", Mode(lvm))
	}

	lvm2 := SetLVM(LI61Sec, 3, ModeServer)
	if LI(lvm2) != 1 {
		t.Errorf("LI = %d, want 1", LI(lvm2))
	}
	if VN(lvm2) != 3 {
		t.Errorf("VN = %d, want 3", VN(lvm2))
	}
	if Mode(lvm2) != 4 {
		t.Errorf("Mode = %d, want 4", Mode(lvm2))
	}
}

func TestNTPLayerSetGet(t *testing.T) {
	layer := NewNTP()

	// Set client mode.
	layer.Set("lvm", SetLVM(LINoWarning, 4, ModeClient))
	layer.Set("stratum", uint8(2))

	lvm, _ := layer.Get("lvm")
	if lvm.(uint8) != 0x23 {
		t.Errorf("lvm = %#x, want 0x23", lvm)
	}

	s, _ := layer.Get("stratum")
	if s.(uint8) != 2 {
		t.Errorf("stratum = %d, want 2", s)
	}
}

func TestNTPSerialize(t *testing.T) {
	layer := NewNTP()
	layer.Set("lvm", SetLVM(LINoWarning, 4, ModeClient))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields error: %v", err)
	}
	if len(data) != 48 {
		t.Errorf("NTP packet size = %d, want 48", len(data))
	}
	if data[0] != 0x23 {
		t.Errorf("first byte = %#x, want 0x23", data[0])
	}
}

func TestNTPParse(t *testing.T) {
	// Build a minimal NTP packet.
	raw := make([]byte, 48)
	raw[0] = 0x24 // LI=0, VN=4, Mode=4 (server)
	raw[1] = 2    // stratum 2

	layer := NewNTP()
	n, err := layer.ParseFields(raw)
	if err != nil {
		t.Fatalf("ParseFields error: %v", err)
	}
	if n != 48 {
		t.Errorf("consumed = %d, want 48", n)
	}

	lvm, _ := layer.Get("lvm")
	if LI(lvm.(uint8)) != 0 {
		t.Errorf("LI = %d, want 0", LI(lvm.(uint8)))
	}
	if VN(lvm.(uint8)) != 4 {
		t.Errorf("VN = %d, want 4", VN(lvm.(uint8)))
	}
	if Mode(lvm.(uint8)) != 4 {
		t.Errorf("Mode = %d, want 4", Mode(lvm.(uint8)))
	}

	s, _ := layer.Get("stratum")
	if s.(uint8) != 2 {
		t.Errorf("stratum = %d, want 2", s)
	}
}

func TestNTPRoundTrip(t *testing.T) {
	layer := NewNTP()
	layer.Set("lvm", SetLVM(LINoWarning, 4, ModeClient))
	layer.Set("stratum", uint8(1))
	layer.Set("poll", uint8(6))
	layer.Set("precision", uint8(0xEC)) // -20 as uint8
	layer.Set("rootdelay", uint32(0x00010000)) // 1 second in 16.16 fixed-point
	layer.Set("rootdispersion", uint32(0x00008000))
	layer.Set("refid", uint32(0x475A4953)) // "GZIS"

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields error: %v", err)
	}

	layer2 := NewNTP()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields error: %v", err)
	}

	// Verify all fields round-trip.
	lvm, _ := layer2.Get("lvm")
	if lvm.(uint8) != SetLVM(LINoWarning, 4, ModeClient) {
		t.Errorf("lvm round-trip = %#x", lvm)
	}
	stratum, _ := layer2.Get("stratum")
	if stratum.(uint8) != 1 {
		t.Errorf("stratum round-trip = %d", stratum)
	}
	poll, _ := layer2.Get("poll")
	if poll.(uint8) != 6 {
		t.Errorf("poll round-trip = %d", poll)
	}
	prec, _ := layer2.Get("precision")
	if prec.(uint8) != 0xEC {
		t.Errorf("precision round-trip = %#x", prec)
	}
	delay, _ := layer2.Get("rootdelay")
	if delay.(uint32) != 0x00010000 {
		t.Errorf("rootdelay round-trip = %#x", delay)
	}
	refid, _ := layer2.Get("refid")
	if refid.(uint32) != 0x475A4953 {
		t.Errorf("refid round-trip = %#x", refid)
	}
}

func TestModeConstants(t *testing.T) {
	tests := []struct {
		mode uint8
		name string
	}{
		{ModeReserved, "Reserved"},
		{ModeSymActive, "Symmetric Active"},
		{ModeSymPassive, "Symmetric Passive"},
		{ModeClient, "Client"},
		{ModeServer, "Server"},
		{ModeBroadcast, "Broadcast"},
		{ModeControl, "Control"},
		{ModePrivate, "Private"},
	}
	for i, tt := range tests {
		if tt.mode != uint8(i) {
			t.Errorf("%s = %d, want %d", tt.name, tt.mode, i)
		}
	}
}

func TestNTPIPv4RefID(t *testing.T) {
	// For stratum 1, refid is a 4-char ASCII string.
	// For stratum 2+, refid is the server's IPv4 address.
	layer := NewNTP()
	layer.Set("lvm", SetLVM(LINoWarning, 4, ModeServer))
	layer.Set("stratum", uint8(1))
	layer.Set("refid", uint32(0x474D524F)) // "GMRO" (GPS)

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields error: %v", err)
	}

	layer2 := NewNTP()
	_, err = layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields error: %v", err)
	}

	refid, _ := layer2.Get("refid")
	if refid.(uint32) != 0x474D524F {
		t.Errorf("refid = %#x, want 0x474D524F", refid)
	}
}
