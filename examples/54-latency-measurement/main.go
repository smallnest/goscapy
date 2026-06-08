// Example 54: High-precision latency measurement using RecvmsgOOB
//
// Demonstrates using kernel timestamps from recvmsg OOB data to measure
// ICMP round-trip latency with nanosecond precision. Two approaches are shown:
//
//   1. Zero-allocation path (RecvmsgOOBInto) — caller provides buffers
//   2. Convenience path (RecvmsgOOB) — pooled OOB buffers internally
//
// Run: sudo go run main.go [-n count] [-t timeout]
//
// Requires root (sudo) or CAP_NET_RAW.

package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	count := flag.Int("n", 5, "number of pings to send")
	timeout := flag.Duration("t", 3*time.Second, "per-packet timeout")
	flag.Parse()

	if os.Getuid() != 0 {
		fmt.Println("This example requires root privileges.")
		fmt.Println("Run with: sudo go run main.go")
		os.Exit(1)
	}

	// Open ICMP raw socket.
	conn, err := sendrecv.DialRaw(1) // 1 = ICMP
	if err != nil {
		fmt.Fprintf(os.Stderr, "DialRaw: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Enable kernel software timestamps.
	// On Linux this uses SO_TIMESTAMPNS (nanosecond resolution).
	// On macOS this uses SO_TIMESTAMP (microsecond resolution).
	if err := conn.EnableTimestamping(false); err != nil {
		fmt.Fprintf(os.Stderr, "EnableTimestamping: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== High-Precision Latency Measurement ===")
	fmt.Println("Using kernel timestamps from RecvmsgOOB")
	fmt.Println()

	// --- Approach 1: Zero-allocation with RecvmsgOOBInto ---
	fmt.Println("--- Approach 1: RecvmsgOOBInto (zero-allocation) ---")
	runPingInto(conn, *count, *timeout)

	fmt.Println()

	// --- Approach 2: Convenience with RecvmsgOOB ---
	fmt.Println("--- Approach 2: RecvmsgOOB (pooled buffers) ---")
	runPingOOB(conn, *count, *timeout)
}

// runPingInto uses RecvmsgOOBInto for zero-allocation latency measurement.
func runPingInto(conn *sendrecv.RawConn, count int, timeout time.Duration) {
	buf := make([]byte, 65536)
	oobBuf := make([]byte, 256) // sufficient for timestamp cmsg

	for i := 0; i < count; i++ {
		icmp := layers.NewICMPEcho(0xFACE, uint16(i+1))
		pkt := packet.NewFrom(icmp)
		payload, err := pkt.Build()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  build: %v\n", err)
			continue
		}

		sendTime := time.Now()
		if err := conn.Send(payload, "127.0.0.1"); err != nil {
			fmt.Fprintf(os.Stderr, "  send: %v\n", err)
			continue
		}

		// Receive with OOB — zero allocation.
		n, oobn, src, err := conn.RecvmsgOOBInto(buf, oobBuf, timeout)
		if err != nil {
			if errors.Is(err, sendrecv.ErrTimeout) {
				fmt.Printf("  ping %d: timeout\n", i+1)
				continue
			}
			fmt.Fprintf(os.Stderr, "  recvmsg: %v\n", err)
			continue
		}

		userLatency := time.Since(sendTime)

		// Validate it's our ICMP reply.
		if !isOurReply(buf[:n], 0xFACE, uint16(i+1)) {
			i-- // not our packet, retry
			continue
		}

		// Parse kernel timestamp from OOB.
		var kernelLatency time.Duration
		ts, ok := sendrecv.ParseTimestamp(oobBuf[:oobn])
		if ok && !ts.Time.IsZero() {
			kernelLatency = time.Since(ts.Time)
			fmt.Printf("  ping %d: src=%s userRTT=%v kernel_recv_ago=%v ts=%v (%s)\n",
				i+1, src, userLatency, kernelLatency, ts.Time, tsSourceName(ts.Source))
		} else {
			fmt.Printf("  ping %d: src=%s userRTT=%v (no kernel timestamp, oob=%d bytes)\n",
				i+1, src, userLatency, oobn)
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// runPingOOB uses the convenience RecvmsgOOB wrapper.
func runPingOOB(conn *sendrecv.RawConn, count int, timeout time.Duration) {
	for i := 0; i < count; i++ {
		icmp := layers.NewICMPEcho(0xBEEF, uint16(i+1))
		pkt := packet.NewFrom(icmp)
		payload, err := pkt.Build()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  build: %v\n", err)
			continue
		}

		sendTime := time.Now()
		if err := conn.Send(payload, "127.0.0.1"); err != nil {
			fmt.Fprintf(os.Stderr, "  send: %v\n", err)
			continue
		}

		// RecvmsgOOB allocates internally (pooled OOB buffer).
		data, oob, src, err := conn.RecvmsgOOB(timeout)
		if err != nil {
			if errors.Is(err, sendrecv.ErrTimeout) {
				fmt.Printf("  ping %d: timeout\n", i+1)
				continue
			}
			fmt.Fprintf(os.Stderr, "  recvmsg: %v\n", err)
			continue
		}

		userLatency := time.Since(sendTime)

		if !isOurReply(data, 0xBEEF, uint16(i+1)) {
			i--
			continue
		}

		var kernelLatency time.Duration
		ts, ok := sendrecv.ParseTimestamp(oob)
		if ok && !ts.Time.IsZero() {
			kernelLatency = time.Since(ts.Time)
			fmt.Printf("  ping %d: src=%s userRTT=%v kernel_recv_ago=%v ts=%v (%s)\n",
				i+1, src, userLatency, kernelLatency, ts.Time, tsSourceName(ts.Source))
		} else {
			fmt.Printf("  ping %d: src=%s userRTT=%v (no kernel timestamp, oob=%d bytes)\n",
				i+1, src, userLatency, len(oob))
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// isOurReply checks if the raw IP packet is our ICMP echo reply.
func isOurReply(data []byte, wantID uint16, wantSeq uint16) bool {
	if len(data) < 28 { // 20 (IP) + 8 (ICMP min)
		return false
	}

	// Skip IP header.
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+8 {
		return false
	}

	icmpData := data[ihl:]
	// Echo reply = type 0, code 0.
	if icmpData[0] != 0 || icmpData[1] != 0 {
		return false
	}
	id := binary.BigEndian.Uint16(icmpData[4:6])
	seq := binary.BigEndian.Uint16(icmpData[6:8])
	return id == wantID && seq == wantSeq
}

// tsSourceName returns a human-readable timestamp source name.
func tsSourceName(src sendrecv.TimestampSource) string {
	switch src {
	case sendrecv.TimestampSoftware:
		return "software"
	case sendrecv.TimestampHardware:
		return "hardware"
	default:
		return "unknown"
	}
}
