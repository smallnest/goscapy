//go:build linux || darwin

package sendrecv

import (
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// TestRecvmsgOOBInto verifies that RecvmsgOOBInto returns data and OOB bytes.
func TestRecvmsgOOBInto(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialRaw(1) // ICMP
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Enable software timestamps.
	if err := conn.EnableTimestamping(false); err != nil {
		t.Fatalf("EnableTimestamping: %v", err)
	}

	// Send ICMP echo.
	icmp := layers.NewICMPEcho(0xAAAA, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("build ICMP: %v", err)
	}
	if err := conn.Send(payload, "127.0.0.1"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Receive with OOB.
	buf := make([]byte, 65536)
	oobBuf := make([]byte, 256)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		n, oobn, src, err := conn.RecvmsgOOBInto(buf, oobBuf, remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			t.Fatalf("RecvmsgOOBInto: %v", err)
		}

		if n == 0 {
			continue
		}

		// Check we can parse the data as an IP packet.
		if n < 20 {
			continue
		}

		ipStartFn := func(_ []byte) (string, error) { return "IP", nil }
		pktReply, err := packet.Dissect(buf[:n], ipStartFn)
		if err != nil {
			continue
		}

		icmpLayer := pktReply.GetLayer("ICMP")
		if icmpLayer == nil {
			continue
		}
		icmpType, _ := icmpLayer.Get("type")
		icmpID, _ := icmpLayer.Get("id")
		if icmpType != uint8(0) || icmpID != uint16(0xAAAA) {
			continue
		}

		// Got our reply. Check source IP.
		if src != "127.0.0.1" {
			t.Errorf("expected src 127.0.0.1, got %s", src)
		}

		// Check OOB was populated.
		if oobn == 0 {
			t.Log("no OOB data received (timestamp may not be available on this platform)")
		} else {
			// Try to parse timestamp.
			ts, ok := ParseTimestamp(oobBuf[:oobn])
			if ok {
				t.Logf("kernel timestamp: %v (source=%v)", ts.Time, ts.Source)
				if ts.Time.IsZero() {
					t.Error("timestamp is zero")
				}
			} else {
				t.Logf("OOB data present (%d bytes) but no timestamp recognized", oobn)
			}
		}

		return
	}

	t.Fatal("failed to receive matching ICMP echo reply via RecvmsgOOBInto")
}

// TestRecvmsgOOB verifies the convenience wrapper.
func TestRecvmsgOOB(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.EnableTimestamping(false); err != nil {
		t.Fatalf("EnableTimestamping: %v", err)
	}

	icmp := layers.NewICMPEcho(0xBBBB, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("build ICMP: %v", err)
	}
	if err := conn.Send(payload, "127.0.0.1"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, oob, src, err := conn.RecvmsgOOB(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			t.Fatalf("RecvmsgOOB: %v", err)
		}

		if len(data) < 20 {
			continue
		}

		ipStartFn := func(_ []byte) (string, error) { return "IP", nil }
		pktReply, err := packet.Dissect(data, ipStartFn)
		if err != nil {
			continue
		}

		icmpLayer := pktReply.GetLayer("ICMP")
		if icmpLayer == nil {
			continue
		}
		icmpType, _ := icmpLayer.Get("type")
		icmpID, _ := icmpLayer.Get("id")
		if icmpType != uint8(0) || icmpID != uint16(0xBBBB) {
			continue
		}

		if src != "127.0.0.1" {
			t.Errorf("expected src 127.0.0.1, got %s", src)
		}

		t.Logf("RecvmsgOOB: %d bytes data, %d bytes OOB from %s", len(data), len(oob), src)

		if len(oob) > 0 {
			ts, ok := ParseTimestamp(oob)
			if ok {
				t.Logf("  timestamp: %v (source=%v)", ts.Time, ts.Source)
			}
		}

		return
	}

	t.Fatal("failed to receive matching ICMP echo reply via RecvmsgOOB")
}

// TestSendmsgOOB verifies SendmsgOOB with nil OOB (equivalent to Send).
func TestSendmsgOOB(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer func() { _ = conn.Close() }()

	icmp := layers.NewICMPEcho(0xCCCC, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("build ICMP: %v", err)
	}

	// SendmsgOOB with nil OOB should behave like Send.
	if err := conn.SendmsgOOB(payload, nil, "127.0.0.1"); err != nil {
		t.Fatalf("SendmsgOOB: %v", err)
	}

	// Receive the reply with regular Recv.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, src, err := conn.Recv(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			t.Fatalf("Recv: %v", err)
		}
		if len(data) < 20 {
			continue
		}

		ipStartFn := func(_ []byte) (string, error) { return "IP", nil }
		pktReply, err := packet.Dissect(data, ipStartFn)
		if err != nil {
			continue
		}
		icmpLayer := pktReply.GetLayer("ICMP")
		if icmpLayer == nil {
			continue
		}
		icmpType, _ := icmpLayer.Get("type")
		icmpID, _ := icmpLayer.Get("id")
		if icmpType == uint8(0) && icmpID == uint16(0xCCCC) {
			if src != "127.0.0.1" {
				t.Errorf("expected src 127.0.0.1, got %s", src)
			}
			return
		}
	}

	t.Fatal("failed to receive matching ICMP echo reply from SendmsgOOB")
}

// TestSendmsgOOBWithPktInfo verifies sending with IP_PKTINFO cmsg.
func TestSendmsgOOBWithPktInfo(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer func() { _ = conn.Close() }()

	icmp := layers.NewICMPEcho(0xDDDD, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("build ICMP: %v", err)
	}

	// Build IP_PKTINFO cmsg to specify source address 127.0.0.1.
	oob := buildPktInfoCmsg(t, "127.0.0.1", 1)

	if err := conn.SendmsgOOB(payload, oob, "127.0.0.1"); err != nil {
		t.Fatalf("SendmsgOOB with PKTINFO: %v", err)
	}

	// Verify we get a reply.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, _, err := conn.Recv(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			t.Fatalf("Recv: %v", err)
		}
		if len(data) < 20 {
			continue
		}

		ipStartFn := func(_ []byte) (string, error) { return "IP", nil }
		pktReply, err := packet.Dissect(data, ipStartFn)
		if err != nil {
			continue
		}
		icmpLayer := pktReply.GetLayer("ICMP")
		if icmpLayer == nil {
			continue
		}
		icmpType, _ := icmpLayer.Get("type")
		icmpID, _ := icmpLayer.Get("id")
		if icmpType == uint8(0) && icmpID == uint16(0xDDDD) {
			return
		}
	}

	t.Fatal("failed to receive reply from SendmsgOOB with PKTINFO")
}

// buildPktInfoCmsg constructs an IP_PKTINFO control message for testing.
func buildPktInfoCmsg(t *testing.T, srcIP string, ifindex int) []byte {
	t.Helper()

	// struct in_pktinfo: ifindex(4) + spec_dst(4) + addr(4) = 12 bytes
	pktInfoData := make([]byte, 12)
	binary.NativeEndian.PutUint32(pktInfoData[0:4], uint32(ifindex))
	ip := parseIP4(srcIP)
	copy(pktInfoData[4:8], ip[:])  // spec_dst
	copy(pktInfoData[8:12], ip[:]) // addr

	return buildCmsg(t, syscall.IPPROTO_IP, syscall.IP_PKTINFO, pktInfoData)
}

func parseIP4(s string) [4]byte {
	var result [4]byte
	var idx int
	var val byte
	for _, c := range s {
		if c == '.' {
			result[idx] = val
			idx++
			val = 0
		} else if c >= '0' && c <= '9' {
			val = val*10 + byte(c-'0')
		}
	}
	result[idx] = val
	return result
}
