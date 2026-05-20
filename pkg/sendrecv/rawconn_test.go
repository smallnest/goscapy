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
