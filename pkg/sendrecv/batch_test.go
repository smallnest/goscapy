package sendrecv

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestBatchConnPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping TestBatchConnPermission: running as root")
	}

	conn, err := DialRaw(1)
	if err == nil {
		defer conn.Close()
		t.Fatal("expected DialRaw to fail for non-root user")
	}
}

func TestBatchConnSendRecvICMP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping TestBatchConnSendRecvICMP: requires root privileges")
	}

	conn, err := DialRaw(1)
	if err != nil {
		t.Fatalf("failed to dial raw socket: %v", err)
	}
	defer conn.Close()

	batch := conn.Batch()

	// Build two different ICMP Echo Requests
	icmp1 := layers.NewICMPEcho(0xaaaa, 1)
	pkt1 := packet.NewFrom(icmp1)
	payload1, err := pkt1.Build()
	if err != nil {
		t.Fatalf("failed to build payload 1: %v", err)
	}

	icmp2 := layers.NewICMPEcho(0xbbbb, 1)
	pkt2 := packet.NewFrom(icmp2)
	payload2, err := pkt2.Build()
	if err != nil {
		t.Fatalf("failed to build payload 2: %v", err)
	}

	msgs := []BatchMsg{
		{Data: payload1, Dst: "127.0.0.1"},
		{Data: payload2, Dst: "127.0.0.1"},
	}

	nSent, err := batch.SendBatch(msgs)
	if err != nil {
		t.Fatalf("SendBatch failed: %v", err)
	}
	if nSent != len(msgs) {
		t.Errorf("expected to send %d packets, sent %d", len(msgs), nSent)
	}

	// Capture responses
	deadline := time.Now().Add(2 * time.Second)
	recvCount := 0
	matchedAAAA := false
	matchedBBBB := false

	for time.Now().Before(deadline) && recvCount < 2 {
		remaining := time.Until(deadline)
		results, err := batch.RecvBatch(2, remaining)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				t.Fatalf("timeout waiting for responses")
			}
			t.Fatalf("RecvBatch failed: %v", err)
		}

		for _, result := range results {
			if len(result.Data) >= 20 {
				pktReply, err := packet.Dissect(result.Data, testIPStartFn)
				if err != nil {
					continue
				}
				icmpLayer := pktReply.GetLayer("ICMP")
				if icmpLayer != nil {
					icmpType, _ := icmpLayer.Get("type")
					icmpID, _ := icmpLayer.Get("id")
					if icmpType == uint8(0) { // Echo Reply
						if icmpID == uint16(0xaaaa) {
							matchedAAAA = true
							recvCount++
						} else if icmpID == uint16(0xbbbb) {
							matchedBBBB = true
							recvCount++
						}
					}
				}
			}
		}
	}

	if recvCount < 2 {
		t.Errorf("expected to receive 2 responses, got %d (aaaa: %v, bbbb: %v)", recvCount, matchedAAAA, matchedBBBB)
	}
}
