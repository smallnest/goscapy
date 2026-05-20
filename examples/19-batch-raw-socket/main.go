package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	if os.Getuid() != 0 {
		fmt.Println("Warning: This example requires root privileges to open raw sockets.")
		fmt.Println("Please run with sudo: sudo go run examples/19-batch-raw-socket/main.go")
		os.Exit(1)
	}

	fmt.Printf("Running on %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// Dials a raw socket for ICMP
	conn, err := sendrecv.DialRaw(1)
	if err != nil {
		log.Fatalf("Failed to dial raw socket: %v", err)
	}
	defer conn.Close()

	// Prepare packets to send
	numPackets := 100
	msgs := make([]sendrecv.BatchMsg, numPackets)
	for i := range numPackets {
		icmp := layers.NewICMPEcho(uint16(0x7777+i), uint16(i))
		pkt := packet.NewFrom(icmp)
		payload, err := pkt.Build()
		if err != nil {
			log.Fatalf("Failed to build packet %d: %v", i, err)
		}
		msgs[i] = sendrecv.BatchMsg{
			Data: payload,
			Dst:  "127.0.0.1",
		}
	}

	// 1. Measure sequential Send
	fmt.Printf("Sending %d packets sequentially...\n", numPackets)
	startSeq := time.Now()
	for _, msg := range msgs {
		if err := conn.Send(msg.Data, msg.Dst); err != nil {
			log.Fatalf("Sequential send failed: %v", err)
		}
	}
	elapsedSeq := time.Since(startSeq)
	fmt.Printf("Sequential send took: %v\n", elapsedSeq)

	// 2. Measure batch SendBatch
	batch := conn.Batch()
	fmt.Printf("Sending %d packets using SendBatch...\n", numPackets)
	startBatch := time.Now()
	nSent, err := batch.SendBatch(msgs)
	if err != nil {
		log.Fatalf("Batch send failed: %v", err)
	}
	elapsedBatch := time.Since(startBatch)
	fmt.Printf("Batch send (n=%d) took: %v\n", nSent, elapsedBatch)

	// Output comparison
	fmt.Printf("\nPerformance comparison:\n")
	fmt.Printf("Sequential: %v\n", elapsedSeq)
	fmt.Printf("Batch:      %v\n", elapsedBatch)
	if elapsedBatch < elapsedSeq {
		improvement := float64(elapsedSeq-elapsedBatch) / float64(elapsedSeq) * 100
		fmt.Printf("Batch implementation is %.2f%% faster than sequential on this platform\n", improvement)
	} else {
		fmt.Printf("Performance is comparable (expected fallback behavior on non-Linux platforms like macOS)\n")
	}
}
