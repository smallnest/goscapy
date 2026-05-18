package sendrecv

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// skipIfNotRoot skips the test if not running as root.
func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: test requires root privileges")
	}
}

func TestSendRequiresIP(t *testing.T) {
	// A packet with only ICMP layer should fail because there is no IP layer.
	icmp := layers.NewICMPEcho(1, 1)
	pkt := packet.NewFrom(icmp)

	err := Send(pkt, loopbackName())
	if err == nil {
		t.Fatal("expected error for packet without IP layer")
	}
	t.Logf("got expected error: %v", err)
}

func TestBuildForSendSkipsEthernet(t *testing.T) {
	// Verify that buildL3 skips Ethernet when present.
	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("127.0.0.1"))
	ip.Set("src", net.ParseIP("127.0.0.1"))
	icmp := layers.NewICMPEcho(0x1234, 1)
	pkt := ip.Over(icmp)

	raw, err := buildL3(pkt)
	if err != nil {
		t.Fatalf("buildL3 failed: %v", err)
	}

	// First byte should be IP version/IHL (0x45), not an Ethernet byte.
	if len(raw) == 0 {
		t.Fatal("buildL3 returned empty bytes")
	}
	if raw[0] != 0x45 {
		t.Errorf("expected IP version/IHL byte 0x45, got 0x%02x", raw[0])
	}
	t.Logf("buildL3 returned %d bytes starting with 0x%02x", len(raw), raw[0])
}

func TestRecvInvalidInterface(t *testing.T) {
	_, err := OpenReceiver("nonexistent_iface_12345")
	if err == nil {
		t.Fatal("expected error for invalid interface")
	}
	t.Logf("got expected error: %v", err)
}

func TestSendICMPOnLoopback(t *testing.T) {
	skipIfNotRoot(t)

	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("127.0.0.1"))
	ip.Set("src", net.ParseIP("127.0.0.1"))
	icmp := layers.NewICMPEcho(0xABCD, 1)
	pkt := ip.Over(icmp)

	err := Send(pkt, loopbackName())
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	t.Log("Send succeeded")
}

func TestSendRecv1ICMP(t *testing.T) {
	skipIfNotRoot(t)

	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("127.0.0.1"))
	ip.Set("src", net.ParseIP("127.0.0.1"))
	icmp := layers.NewICMPEcho(0xDCBA, 42)
	pkt := ip.Over(icmp)

	sent, resp, err := SendRecv1(pkt, loopbackName(), 3*time.Second)
	if err != nil {
		t.Fatalf("SendRecv1 failed: %v", err)
	}
	if sent == nil {
		t.Fatal("sent packet is nil")
	}
	if resp == nil {
		t.Fatal("no response received (nil)")
	}

	// Verify the response has IP and ICMP layers.
	if resp.GetLayer("IP") == nil {
		t.Fatal("response has no IP layer")
	}
	icmpLayer := resp.GetLayer("ICMP")
	if icmpLayer == nil {
		t.Fatal("response has no ICMP layer")
	}

	icmpType, _ := icmpLayer.Get("type")
	t.Logf("response ICMP type=%v (0=EchoReply)", icmpType)
}

func TestSendpEthernetFrame(t *testing.T) {
	skipIfNotRoot(t)

	eth := layers.NewEthernetWith(
		"00:00:00:00:00:00",
		"00:00:00:00:00:00",
		layers.EtherTypeIPv4,
	)
	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("127.0.0.1"))
	ip.Set("src", net.ParseIP("127.0.0.1"))
	icmp := layers.NewICMPEcho(0x5555, 1)

	// Build 3-layer packet: Ethernet / IP / ICMP.
	pkt := packet.NewFrom(eth, ip, icmp)
	pkt.Sync()

	err := Sendp(pkt, loopbackName())
	if err != nil {
		t.Fatalf("Sendp failed: %v", err)
	}
	t.Log("Sendp succeeded")
}
