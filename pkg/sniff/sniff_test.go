package sniff

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// skipIfNotRoot skips the test if not running as root.
func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: test requires root privileges")
	}
}

func sendICMPLoopback(t *testing.T, seq uint8) {
	t.Helper()
	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("127.0.0.1"))
	ip.Set("src", net.ParseIP("127.0.0.1"))
	icmp := layers.NewICMPEcho(uint16(seq), uint16(seq))
	pkt := ip.Over(icmp)

	if err := sendrecv.Send(pkt, sendrecv.LoopbackName()); err != nil {
		t.Logf("warning: Send failed: %v", err)
	}
}

func TestSniffCount(t *testing.T) {
	skipIfNotRoot(t)

	done := make(chan error, 1)
	var captured int32

	go func() {
		err := Sniff(SniffConfig{
			Iface:   sendrecv.LoopbackName(),
			Count:   3,
			Timeout: 5 * time.Second,
		}, func(pkt *packet.Packet) bool {
			atomic.AddInt32(&captured, 1)
			return true
		})
		done <- err
	}()

	// Give the sniffer time to open the receiver.
	time.Sleep(200 * time.Millisecond)

	// Send more packets than the count limit; sniffer should stop at 3.
	for i := 0; i < 5; i++ {
		sendICMPLoopback(t, uint8(i))
		time.Sleep(50 * time.Millisecond)
	}

	if err := <-done; err != nil {
		t.Fatalf("Sniff failed: %v", err)
	}

	got := atomic.LoadInt32(&captured)
	if got != 3 {
		t.Errorf("expected 3 captured packets, got %d", got)
	}
}

func TestSniffTimeout(t *testing.T) {
	skipIfNotRoot(t)

	start := time.Now()
	err := Sniff(SniffConfig{
		Iface:   sendrecv.LoopbackName(),
		Count:   0, // unlimited
		Timeout: 500 * time.Millisecond,
	}, func(pkt *packet.Packet) bool {
		return true
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Sniff failed: %v", err)
	}
	if elapsed < 400*time.Millisecond {
		t.Errorf("expected at least 400ms, got %v", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("expected less than 2s, got %v", elapsed)
	}
	t.Logf("timeout after %v (expected ~500ms)", elapsed)
}

func TestSniffHandlerStop(t *testing.T) {
	skipIfNotRoot(t)

	// Start sniffer that stops after first packet.
	go func() {
		time.Sleep(200 * time.Millisecond)
		sendICMPLoopback(t, 1)
	}()

	var captured int32
	err := Sniff(SniffConfig{
		Iface:   sendrecv.LoopbackName(),
		Timeout: 5 * time.Second,
	}, func(pkt *packet.Packet) bool {
		atomic.AddInt32(&captured, 1)
		return false // stop after first packet
	})

	if err != nil {
		t.Fatalf("Sniff failed: %v", err)
	}
	if atomic.LoadInt32(&captured) != 1 {
		t.Errorf("expected 1 captured packet, got %d", captured)
	}
}

func TestSniffChan(t *testing.T) {
	skipIfNotRoot(t)

	ch, stop := SniffChan(SniffConfig{
		Iface:   sendrecv.LoopbackName(),
		Count:   2,
		Timeout: 5 * time.Second,
	})
	defer stop()

	// Send packets in background.
	go func() {
		time.Sleep(200 * time.Millisecond)
		for i := 0; i < 3; i++ {
			sendICMPLoopback(t, uint8(i))
			time.Sleep(50 * time.Millisecond)
		}
	}()

	var received int
	for range ch {
		received++
	}

	if received != 2 {
		t.Errorf("expected 2 packets from channel, got %d", received)
	}
}

func TestSniffChanStop(t *testing.T) {
	skipIfNotRoot(t)

	ch, stop := SniffChan(SniffConfig{
		Iface:   sendrecv.LoopbackName(),
		Timeout: 10 * time.Second,
	})

	go func() {
		time.Sleep(500 * time.Millisecond)
		stop()
	}()

	// Channel should be closed after stop() is called.
	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed after stop()")
	}
}

func TestSniffEmptyInterface(t *testing.T) {
	err := Sniff(SniffConfig{
		Iface: "",
	}, func(pkt *packet.Packet) bool { return true })
	if err == nil {
		t.Fatal("expected error for empty interface")
	}
	t.Logf("got expected error: %v", err)
}

func TestSniffNilHandler(t *testing.T) {
	err := Sniff(SniffConfig{
		Iface: sendrecv.LoopbackName(),
	}, nil)
	if err == nil {
		t.Fatal("expected error for nil handler")
	}
	t.Logf("got expected error: %v", err)
}
