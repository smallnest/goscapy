//go:build linux

package sendrecv

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestUringRecvOOB(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialUringRaw(1)
	if err != nil {
		t.Fatalf("DialUringRaw: %v", err)
	}
	defer conn.Close()

	if err := conn.EnableTimestamping(false); err != nil {
		t.Fatalf("EnableTimestamping: %v", err)
	}

	icmp := layers.NewICMPEcho(0xEEEE, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("build ICMP: %v", err)
	}
	if _, err := conn.Send(payload, "127.0.0.1"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, oob, src, err := conn.RecvOOB(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			t.Fatalf("RecvOOB: %v", err)
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
		if icmpType != uint8(0) || icmpID != uint16(0xEEEE) {
			continue
		}

		if src != "127.0.0.1" {
			t.Errorf("expected src 127.0.0.1, got %s", src)
		}

		if len(oob) > 0 {
			ts, ok := ParseTimestamp(oob)
			if ok {
				t.Logf("kernel timestamp: %v (source=%v)", ts.Time, ts.Source)
				if ts.Time.IsZero() {
					t.Error("timestamp is zero")
				}
			} else {
				t.Logf("OOB data present (%d bytes) but no timestamp recognized", len(oob))
			}
		}

		return
	}

	t.Fatal("failed to receive matching ICMP echo reply via RecvOOB")
}

func TestUringRecvmsgOOBInto(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialUringRaw(1)
	if err != nil {
		t.Fatalf("DialUringRaw: %v", err)
	}
	defer conn.Close()

	if err := conn.EnableTimestamping(false); err != nil {
		t.Fatalf("EnableTimestamping: %v", err)
	}

	icmp := layers.NewICMPEcho(0xEFF0, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("build ICMP: %v", err)
	}
	if _, err := conn.Send(payload, "127.0.0.1"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 65536)
	oobBuf := make([]byte, 256)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, oob, src, err := conn.RecvmsgOOBInto(buf, oobBuf, remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			t.Fatalf("RecvmsgOOBInto: %v", err)
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
		if icmpType != uint8(0) || icmpID != uint16(0xEFF0) {
			continue
		}

		if src != "127.0.0.1" {
			t.Errorf("expected src 127.0.0.1, got %s", src)
		}

		if len(oob) > 0 {
			ts, ok := ParseTimestamp(oob)
			if ok {
				t.Logf("kernel timestamp: %v (source=%v)", ts.Time, ts.Source)
			}
		}

		return
	}

	t.Fatal("failed to receive matching ICMP echo reply via RecvmsgOOBInto")
}

func TestUringSendRecvBatchOOB(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialUringRaw(1)
	if err != nil {
		t.Fatalf("DialUringRaw: %v", err)
	}
	defer conn.Close()

	if err := conn.EnableTimestamping(false); err != nil {
		t.Fatalf("EnableTimestamping: %v", err)
	}

	msgs := make([]BatchMsg, 3)
	ids := []uint16{0xF1F1, 0xF2F2, 0xF3F3}
	for i, id := range ids {
		icmp := layers.NewICMPEcho(id, uint16(i+1))
		pkt := packet.NewFrom(icmp)
		payload, err := pkt.Build()
		if err != nil {
			t.Fatalf("build ICMP %d: %v", i, err)
		}
		msgs[i] = BatchMsg{Data: payload, Dst: "127.0.0.1"}
	}

	results, err := conn.SendRecvBatchOOB(msgs)
	if err != nil {
		t.Fatalf("SendRecvBatchOOB: %v", err)
	}

	if len(results) != len(msgs) {
		t.Fatalf("expected %d results, got %d", len(msgs), len(results))
	}

	received := 0
	for _, r := range results {
		if len(r.Data) == 0 {
			continue
		}
		received++

		if len(r.OOB) > 0 {
			ts, ok := ParseTimestamp(r.OOB)
			if ok {
				t.Logf("batch result: %d bytes from %s, ts=%v (source=%v)", len(r.Data), r.Src, ts.Time, ts.Source)
			}
		}
	}

	if received == 0 {
		t.Fatal("no packets received in batch")
	}
	t.Logf("received %d/%d packets with OOB", received, len(msgs))
}

func TestUringOOBWithoutTimestamping(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}

	conn, err := DialUringRaw(1)
	if err != nil {
		t.Fatalf("DialUringRaw: %v", err)
	}
	defer conn.Close()

	// Do NOT call EnableTimestamping.

	icmp := layers.NewICMPEcho(0xF5F5, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		t.Fatalf("build ICMP: %v", err)
	}
	if _, err := conn.Send(payload, "127.0.0.1"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		data, oob, src, err := conn.RecvOOB(remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			t.Fatalf("RecvOOB: %v", err)
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
		if icmpType != uint8(0) || icmpID != uint16(0xF5F5) {
			continue
		}

		if src != "127.0.0.1" {
			t.Errorf("expected src 127.0.0.1, got %s", src)
		}

		// OOB should be empty or absent without timestamping enabled.
		t.Logf("RecvOOB without timestamping: %d bytes OOB", len(oob))
		return
	}

	t.Fatal("failed to receive matching ICMP echo reply without timestamping")
}
