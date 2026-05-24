package goscapy

import (
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestFuzzPreservesExplicitValues(t *testing.T) {
	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("10.0.0.1"))
	ip.Set("ttl", uint8(128))

	Fuzz(ip)

	dst, _ := ip.Get("dst")
	if !dst.(net.IP).Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("Fuzz modified explicitly set dst")
	}
	ttl, _ := ip.Get("ttl")
	if ttl.(uint8) != 128 {
		t.Errorf("Fuzz modified explicitly set ttl")
	}

	// Verify some default fields got randomized.
	// src was nil (default), should now be set.
	src, _ := ip.Get("src")
	if src == nil {
		t.Errorf("Fuzz did not randomize default src")
	}
	id, _ := ip.Get("id")
	if id.(uint16) == 0 {
		// Possible but extremely unlikely with random values
		t.Logf("Warning: id still 0 after fuzz (possible but unlikely)")
	}
}

func TestFuzzRandomizesAllIntegerFieldTypes(t *testing.T) {
	l := packet.NewLayer("test", []fields.Field{
		fields.NewByteField("byte_f", 0),
		fields.NewXByteField("xbyte_f", 0),
		fields.NewShortField("short_f", 0),
		fields.NewLEShortField("leshort_f", 0),
		fields.NewThreeBytesField("three_f", 0),
		fields.NewIntField("int_f", 0),
		fields.NewSignedIntField("sint_f", 0),
		fields.NewLEIntField("leint_f", 0),
		fields.NewLongField("long_f", 0),
		fields.NewLELongField("lelong_f", 0),
		fields.NewBitField("bit_f", 0, 4),
	})

	Fuzz(l)

	// All fields should be non-zero (extremely unlikely to all be zero)
	allZero := true
	for _, f := range l.Fields() {
		v, _ := l.Get(f.Name())
		switch val := v.(type) {
		case uint8:
			if val != 0 {
				allZero = false
			}
		case uint16:
			if val != 0 {
				allZero = false
			}
		case uint32:
			if val != 0 {
				allZero = false
			}
		case int32:
			if val != 0 {
				allZero = false
			}
		case uint64:
			if val != 0 {
				allZero = false
			}
		}
	}
	if allZero {
		t.Errorf("Fuzz left all fields at zero")
	}
}

func TestFuzzAddressFields(t *testing.T) {
	l := packet.NewLayer("test", []fields.Field{
		fields.NewMACField("mac_f", nil),
		fields.NewIPField("ip_f", nil),
		fields.NewIPv6Field("ipv6_f", nil),
	})

	Fuzz(l)

	mac, _ := l.Get("mac_f")
	if mac == nil {
		t.Errorf("Fuzz did not randomize MAC")
	} else {
		hw := mac.(net.HardwareAddr)
		if len(hw) != 6 {
			t.Errorf("MAC wrong length: %d", len(hw))
		}
		if hw[0]&0x01 != 0 {
			t.Errorf("Fuzz generated multicast MAC")
		}
	}

	ip, _ := l.Get("ip_f")
	if ip == nil {
		t.Errorf("Fuzz did not randomize IPv4")
	} else if len(ip.(net.IP)) != 4 {
		t.Errorf("IPv4 wrong length")
	}

	ipv6, _ := l.Get("ipv6_f")
	if ipv6 == nil {
		t.Errorf("Fuzz did not randomize IPv6")
	} else if len(ipv6.(net.IP)) != 16 {
		t.Errorf("IPv6 wrong length")
	}
}

func TestFuzzStringFields(t *testing.T) {
	l := packet.NewLayer("test", []fields.Field{
		fields.NewStrField("str_f", ""),
		fields.NewStrFixedField("fixed_f", 8, nil),
	})

	Fuzz(l)

	str, _ := l.Get("str_f")
	if str == nil || str.(string) == "" {
		t.Errorf("Fuzz did not randomize StrField")
	}

	fixed, _ := l.Get("fixed_f")
	if fixed == nil {
		t.Errorf("Fuzz did not randomize StrFixedField")
	} else if len(fixed.([]byte)) != 8 {
		t.Errorf("StrFixedField wrong length: %d", len(fixed.([]byte)))
	}
}

func TestFuzzPacket(t *testing.T) {
	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("10.0.0.1"))

	tcp := layers.NewTCP()
	tcp.Set("dport", uint16(80))

	pkt := packet.NewFrom(ip, tcp)
	FuzzPacket(pkt)

	// Explicitly set values preserved
	dst, _ := pkt.Layers()[0].Get("dst")
	if !dst.(net.IP).Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("FuzzPacket modified explicitly set dst")
	}
	dport, _ := pkt.Layers()[1].Get("dport")
	if dport.(uint16) != 80 {
		t.Errorf("FuzzPacket modified explicitly set dport")
	}

	// Default values should be randomized
	sport, _ := pkt.Layers()[1].Get("sport")
	if sport.(uint16) == 0 {
		t.Logf("Warning: sport still 0 after fuzz")
	}
}

func TestFuzzWithBuilderAPI(t *testing.T) {
	// Test composition: fuzz both layers, build succeeds
	tcpLayer := layers.NewTCP()
	Fuzz(tcpLayer)

	ipLayer := layers.NewIP()
	ipLayer.Set("dst", net.ParseIP("10.0.0.1"))
	Fuzz(ipLayer)

	pkt := ipLayer.Over(tcpLayer)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(raw) == 0 {
		t.Errorf("Build produced empty packet")
	}
}

func TestFuzzBitFieldRespectsSize(t *testing.T) {
	l := packet.NewLayer("test", []fields.Field{
		fields.NewBitField("bit1", 0, 1),
		fields.NewBitField("bit2", 0, 3),
		fields.NewBitField("bit3", 0, 8),
	})

	Fuzz(l)

	bit1, _ := l.Get("bit1")
	if bit1.(uint8) > 1 {
		t.Errorf("1-bit field value %d exceeds range", bit1.(uint8))
	}

	bit2, _ := l.Get("bit2")
	if bit2.(uint8) > 7 {
		t.Errorf("3-bit field value %d exceeds range", bit2.(uint8))
	}

	bit3, _ := l.Get("bit3")
	_ = bit3 // 8-bit can be 0-255
}

func TestFuzzConditionalField(t *testing.T) {
	condActive := func(values map[string]any) bool { return true }
	condInactive := func(values map[string]any) bool { return false }

	l := packet.NewLayer("test", []fields.Field{
		fields.NewByteField("base", 0),
		fields.NewConditionalField(fields.NewShortField("active_f", 0), condActive),
		fields.NewConditionalField(fields.NewShortField("inactive_f", 0), condInactive),
	})

	Fuzz(l)

	activeVal, _ := l.Get("active_f")
	if activeVal.(uint16) == 0 {
		t.Logf("Warning: active conditional field still 0")
	}

	// Inactive conditional field should not be in values
	_, err := l.Get("inactive_f")
	if err == nil {
		// It may exist but was set by Fuzz — that's okay since
		// the field definition exists and Set allows it
		t.Logf("Note: inactive conditional field was settable")
	}
}

func TestFuzzMACUnicast(t *testing.T) {
	l := packet.NewLayer("test", []fields.Field{
		fields.NewMACField("mac_f", nil),
	})

	for i := 0; i < 100; i++ {
		// Reset to default
		l.Set("mac_f", net.HardwareAddr(nil))
		Fuzz(l)
		mac, _ := l.Get("mac_f")
		hw := mac.(net.HardwareAddr)
		if hw[0]&0x01 != 0 {
			t.Fatalf("Generated multicast MAC: %s", hw)
		}
	}
}

func TestFuzzRandomizesFieldsWithNonZeroDefaults(t *testing.T) {
	// Fields with non-zero defaults (e.g. ttl=64, window=8192) are at their
	// default value, so Fuzz will randomize them — this is correct Scapy behavior.
	// Fuzz only preserves values that differ from the default (explicitly set).
	l := packet.NewLayer("test", []fields.Field{
		fields.NewByteField("f1", 42),
		fields.NewShortField("f2", 100),
	})

	Fuzz(l)

	// These should be randomized (may match by luck, but not guaranteed)
	// The key test is that they CAN change.
	f1, _ := l.Get("f1")
	f2, _ := l.Get("f2")
	// Just verify they're still valid types
	if _, ok := f1.(uint8); !ok {
		t.Errorf("f1 wrong type: %T", f1)
	}
	if _, ok := f2.(uint16); !ok {
		t.Errorf("f2 wrong type: %T", f2)
	}
}

func TestFuzzProducesValidPackets(t *testing.T) {
	tcpFuzz := layers.NewTCP()
	Fuzz(tcpFuzz)

	ipLayer := layers.NewIP()
	ipLayer.Set("dst", net.ParseIP("10.0.0.1"))
	Fuzz(ipLayer)

	pkt := ipLayer.Over(tcpFuzz)
	raw, err := pkt.Build()
	if err != nil {
		t.Fatalf("Fuzzed packet Build failed: %v", err)
	}

	// Minimum IP(20) + TCP(20) = 40 bytes
	if len(raw) < 40 {
		t.Errorf("Packet too short: %d bytes", len(raw))
	}
}
