package sendrecv

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func testIPStartFn(_ []byte) (string, error) {
	return "IP", nil
}

func TestDialRawPermission(t *testing.T) {
	// If not running as root, DialRaw should fail with a permission error.
	if os.Getuid() == 0 {
		t.Skip("skipping TestDialRawPermission: running as root")
	}

	conn, err := DialRaw(1)
	if err == nil {
		conn.Close()
		t.Fatal("expected DialRaw to fail for non-root user")
	}

	// Verify it's a permission/socket error
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Logf("dial failed as expected with error: %v", err)
	}
}

func TestRawConnSendRecvICMP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TestRawConnSendRecvICMP: requires root privileges")
	}

	conn, err := DialRaw(1) // 1 = ICMP
	if err != nil {
		t.Fatalf("failed to dial raw socket: %v", err)
	}
	defer conn.Close()

	// Build an ICMP Echo Request payload
	icmp := layers.NewICMPEcho(0x9999, 1)
	// We need the raw payload for the ICMP layer.
	// Since we are sending via a raw socket (IP header automatically built by kernel),
	// the payload should start from the ICMP header.
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("failed to build ICMP payload: %v", err)
	}

	// Send to localhost
	err = conn.Send(payload, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}

	// Receive response
	deadline := time.Now().Add(2 * time.Second)
	var reply []byte
	var srcIP string

	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, ip, err := conn.Recv(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				t.Fatalf("timeout waiting for response")
			}
			t.Fatalf("recv error: %v", err)
		}

		// On SOCK_RAW, the received data includes the IP header (at least 20 bytes).
		// We need to parse or dissect it to check if it's our ICMP Echo Reply.
		if len(data) >= 20 {
			// Dissect received IPv4 packet starting from IP header
			pktReply, err := packet.Dissect(data, testIPStartFn)
			if err != nil {
				continue // not a valid IPv4 packet
			}
			icmpLayer := pktReply.GetLayer("ICMP")
			if icmpLayer != nil {
				icmpType, _ := icmpLayer.Get("type")
				icmpID, _ := icmpLayer.Get("id")
				// 0 is Echo Reply, and ID should match 0x9999
				if icmpType == uint8(0) && icmpID == uint16(0x9999) {
					reply = data
					srcIP = ip
					break
				}
			}
		}
	}

	if len(reply) == 0 {
		t.Fatal("failed to capture matching ICMP echo reply")
	}

	if srcIP != "127.0.0.1" {
		t.Errorf("expected source IP 127.0.0.1, got %s", srcIP)
	}
}

func TestSendRawRecvRawPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping TestSendRawRecvRawPermission: running as root")
	}

	err := SendRaw(1, []byte("test"), "127.0.0.1")
	if err == nil {
		t.Fatal("expected SendRaw to fail for non-root user")
	}

	_, _, err = RecvRaw(1, 1*time.Second)
	if err == nil {
		t.Fatal("expected RecvRaw to fail for non-root user")
	}
}

func TestSendRawRecvRawICMP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TestSendRawRecvRawICMP: requires root privileges")
	}

	// Build an ICMP Echo Request payload
	icmp := layers.NewICMPEcho(0x8888, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("failed to build ICMP payload: %v", err)
	}

	// Send to localhost
	err = SendRaw(1, payload, "127.0.0.1")
	if err != nil {
		t.Fatalf("SendRaw failed: %v", err)
	}

	// Receive response
	deadline := time.Now().Add(2 * time.Second)
	var reply []byte
	var srcIP string

	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, ip, err := RecvRaw(1, remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				t.Fatalf("timeout waiting for response")
			}
			t.Fatalf("RecvRaw error: %v", err)
		}

		if len(data) >= 20 {
			pktReply, err := packet.Dissect(data, testIPStartFn)
			if err != nil {
				continue
			}
			icmpLayer := pktReply.GetLayer("ICMP")
			if icmpLayer != nil {
				icmpType, _ := icmpLayer.Get("type")
				icmpID, _ := icmpLayer.Get("id")
				if icmpType == uint8(0) && icmpID == uint16(0x8888) {
					reply = data
					srcIP = ip
					break
				}
			}
		}
	}

	if len(reply) == 0 {
		t.Fatal("failed to capture matching ICMP echo reply using RecvRaw")
	}

	if srcIP != "127.0.0.1" {
		t.Errorf("expected source IP 127.0.0.1, got %s", srcIP)
	}
}

func TestRawConnAttachBPF(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TestRawConnAttachBPF: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("failed to dial raw socket: %v", err)
	}
	defer conn.Close()

	dropFilter := []BPFInstruction{
		{Code: 0x06, K: 0},
	}
	err = conn.AttachBPF(dropFilter)
	if err != nil {
		t.Fatalf("failed to attach BPF: %v", err)
	}
}

func TestRawConnRecvInto(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TestRawConnRecvInto: requires root privileges")
	}

	conn, err := DialRaw(1) // ICMP
	if err != nil {
		t.Fatalf("failed to dial raw socket: %v", err)
	}
	defer conn.Close()

	icmp := layers.NewICMPEcho(0x7777, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("failed to build ICMP payload: %v", err)
	}

	err = conn.Send(payload, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}

	// Use a caller-provided buffer for recv.
	buf := make([]byte, 65536)
	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		n, srcIP, err := conn.RecvInto(buf, remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				t.Fatalf("timeout waiting for response")
			}
			t.Fatalf("RecvInto error: %v", err)
		}

		if n == 0 {
			continue
		}

		data := buf[:n]
		if len(data) >= 20 {
			pktReply, err := packet.Dissect(data, testIPStartFn)
			if err != nil {
				continue
			}
			icmpLayer := pktReply.GetLayer("ICMP")
			if icmpLayer != nil {
				icmpType, _ := icmpLayer.Get("type")
				icmpID, _ := icmpLayer.Get("id")
				if icmpType == uint8(0) && icmpID == uint16(0x7777) {
					if srcIP != "127.0.0.1" {
						t.Errorf("expected source IP 127.0.0.1, got %s", srcIP)
					}
					return
				}
			}
		}
	}

	t.Fatal("failed to capture matching ICMP echo reply using RecvInto")
}

func TestDialRaw6Permission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping TestDialRaw6Permission: running as root")
	}

	conn, err := DialRaw6(58) // ICMPv6
	if err == nil {
		conn.Close()
		t.Fatal("expected DialRaw6 to fail for non-root user")
	}

	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Logf("dial6 failed as expected with error: %v", err)
	}
}

func TestDialRaw6Root(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TestDialRaw6Root: requires root privileges")
	}

	conn, err := DialRaw6(58) // ICMPv6
	if err != nil {
		t.Fatalf("DialRaw6 failed: %v", err)
	}
	defer conn.Close()
}

func TestSendL3v6Build(t *testing.T) {
	// Test that hasIPv6Layer and extractIPv6Info work correctly
	// without requiring root (just test the build/extract path).
	ipv6 := layers.NewIPv6()
	ipv6.Set("src", "::1")
	ipv6.Set("dst", "::1")
	ipv6.Set("nh", layers.IPv6NextHdrICMP)
	ipv6.Set("hlim", uint8(64))

	icmpv6 := layers.NewICMPv6()
	icmpv6Echo := layers.NewICMPv6Echo(0x1234, 1)

	pkt := packet.NewFrom(ipv6, icmpv6, icmpv6Echo)

	if !hasIPv6Layer(pkt) {
		t.Fatal("expected hasIPv6Layer to return true")
	}

	dst, nh, hlim, err := extractIPv6Info(pkt)
	if err != nil {
		t.Fatalf("extractIPv6Info: %v", err)
	}

	// ::1 in 16 bytes
	expected := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if dst != expected {
		t.Errorf("dst: expected %v, got %v", expected, dst)
	}
	if nh != layers.IPv6NextHdrICMP {
		t.Errorf("nh: expected %d, got %d", layers.IPv6NextHdrICMP, nh)
	}
	if hlim != 64 {
		t.Errorf("hlim: expected 64, got %d", hlim)
	}
}

