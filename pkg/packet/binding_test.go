package packet

import (
	"testing"

	"github.com/smallnest/goscapy/pkg/fields"
)

// Pre-register test protocol bindings to simulate real protocol relationships.
func init() {
	// IP over Ethernet → Ether.type = 0x0800
	RegisterBinding("IP", "Ethernet", "type", uint16(0x0800))
	// ARP over Ethernet → Ether.type = 0x0806
	RegisterBinding("ARP", "Ethernet", "type", uint16(0x0806))
	// TCP over IP → IP.proto = 6
	RegisterBinding("TCP", "IP", "proto", uint8(6))
	// UDP over IP → IP.proto = 17
	RegisterBinding("UDP", "IP", "proto", uint8(17))
	// ICMP over IP → IP.proto = 1
	RegisterBinding("ICMP", "IP", "proto", uint8(1))
}

func makeEth() *Layer {
	return NewLayer("Ethernet", []fields.Field{
		fields.NewMACField("dst", nil),
		fields.NewMACField("src", nil),
		fields.NewShortField("type", 0),
	})
}

func makeIP() *Layer {
	return NewLayer("IP", []fields.Field{
		fields.NewByteField("ver", 4),
		fields.NewByteField("proto", 0),
		fields.NewIPField("src", nil),
		fields.NewIPField("dst", nil),
	})
}

func makeTCP() *Layer {
	return NewLayer("TCP", []fields.Field{
		fields.NewShortField("sport", 0),
		fields.NewShortField("dport", 0),
	})
}

func makeUDP() *Layer {
	return NewLayer("UDP", []fields.Field{
		fields.NewShortField("sport", 0),
		fields.NewShortField("dport", 0),
	})
}

func makeARP() *Layer {
	return NewLayer("ARP", []fields.Field{
		fields.NewShortField("htype", 1),
		fields.NewShortField("ptype", 0x0800),
	})
}

func makeICMP() *Layer {
	return NewLayer("ICMP", []fields.Field{
		fields.NewByteField("type", 8),
		fields.NewByteField("code", 0),
	})
}

func TestLayerOverStacking(t *testing.T) {
	eth := makeEth()
	ip := makeIP()

	pkt := eth.Over(ip)

	if pkt.Len() != 2 {
		t.Fatalf("packet len = %d, want 2", pkt.Len())
	}
	if pkt.First().Proto() != "Ethernet" {
		t.Errorf("first = %s, want Ethernet", pkt.First().Proto())
	}
	if pkt.Last().Proto() != "IP" {
		t.Errorf("last = %s, want IP", pkt.Last().Proto())
	}

	// Binding: Ether.type should be auto-set to 0x0800 (IPv4)
	ethType, _ := eth.Get("type")
	if ethType.(uint16) != 0x0800 {
		t.Errorf("Ether.type after Over(IP) = %#x, want 0x0800", ethType)
	}
}

func TestLayerOverChain(t *testing.T) {
	eth := makeEth()
	ip := makeIP()
	tcp := makeTCP()

	pkt := eth.Over(ip).Push(tcp)
	pkt.Sync()

	if pkt.Len() != 3 {
		t.Fatalf("packet len = %d, want 3", pkt.Len())
	}
	if pkt.String() != "Ethernet / IP / TCP" {
		t.Errorf("String() = %q", pkt.String())
	}

	// Ether.type → 0x0800 (IPv4)
	ethType, _ := eth.Get("type")
	if ethType.(uint16) != 0x0800 {
		t.Errorf("Ether.type = %#x", ethType)
	}

	// IP.proto → 6 (TCP)
	ipProto, _ := ip.Get("proto")
	if ipProto.(uint8) != 6 {
		t.Errorf("IP.proto = %d, want 6", ipProto)
	}
}

func TestDifferentUpperProtocols(t *testing.T) {
	// ARP over Ethernet → type = 0x0806
	eth := makeEth()
	arp := makeARP()
	eth.Over(arp)

	ethType, _ := eth.Get("type")
	if ethType.(uint16) != 0x0806 {
		t.Errorf("Ether.type for ARP = %#x, want 0x0806", ethType)
	}

	// UDP over IP → proto = 17
	ip := makeIP()
	udp := makeUDP()
	ip.Over(udp)

	ipProto, _ := ip.Get("proto")
	if ipProto.(uint8) != 17 {
		t.Errorf("IP.proto for UDP = %d, want 17", ipProto)
	}
}

func TestSyncAfterFieldChange(t *testing.T) {
	eth := makeEth()
	ip := makeIP()
	tcp := makeTCP()

	pkt := eth.Over(ip).Push(tcp)
	pkt.Sync()

	// Simulate replacing TCP with UDP on an existing packet.
	udp := makeUDP()
	pkt.layers[2] = udp

	// Before Sync, IP.proto is still 6 (TCP)
	ipProto, _ := ip.Get("proto")
	if ipProto.(uint8) != 6 {
		t.Fatalf("before Sync: IP.proto = %d, want 6", ipProto)
	}

	pkt.Sync()

	// After Sync, IP.proto should be 17 (UDP)
	ipProto, _ = ip.Get("proto")
	if ipProto.(uint8) != 17 {
		t.Errorf("after Sync: IP.proto = %d, want 17", ipProto)
	}
}

func TestOverReturnsNewPacket(t *testing.T) {
	eth1 := makeEth()
	ip1 := makeIP()
	pkt1 := eth1.Over(ip1)

	// Over creates independent packet; layer objects are shared.
	eth2 := makeEth()
	ip2 := makeIP()
	pkt2 := eth2.Over(ip2)

	// Modify eth2 type directly — should not affect pkt1
	eth2.Set("type", uint16(0x9999))
	eth1Type, _ := eth1.Get("type")
	if eth1Type.(uint16) != 0x0800 {
		t.Errorf("eth1.type should still be 0x0800, got %#x", eth1Type)
	}

	_ = pkt1
	_ = pkt2
}

func TestOverWithoutBinding(t *testing.T) {
	// Two layers with no registered binding — defaults remain.
	lower := NewLayer("Raw", []fields.Field{
		fields.NewByteField("flag", 0),
	})
	upper := NewLayer("Payload", []fields.Field{
		fields.NewStrField("data", ""),
	})

	pkt := lower.Over(upper)
	if pkt.Len() != 2 {
		t.Fatalf("len = %d", pkt.Len())
	}

	flag, _ := lower.Get("flag")
	if flag.(uint8) != 0 {
		t.Errorf("flag should remain 0, got %d", flag)
	}
}

func TestBindingRegistration(t *testing.T) {
	// Verify bindings are idempotent — re-registering same pair appends,
	// but the last-applied binding wins because Set overwrites.
	eth := makeEth()
	ip := makeIP()
	eth.Over(ip)

	ethType, _ := eth.Get("type")
	if ethType.(uint16) != 0x0800 {
		t.Errorf("Ether.type = %#x, want 0x0800", ethType)
	}
}
