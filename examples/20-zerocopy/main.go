package main

import (
	"context"
	"errors"
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
		fmt.Println("Please run with sudo: sudo go run examples/20-zerocopy/main.go")
		os.Exit(1)
	}

	fmt.Printf("Running on %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// Dial ICMP raw socket
	conn, err := sendrecv.DialRaw(1)
	if err != nil {
		log.Fatalf("Failed to dial raw socket: %v", err)
	}
	defer conn.Close()

	// Build a large packet payload (e.g. 1400 bytes, safe for Ethernet MTU)
	payloadSize := 1400
	payloadData := make([]byte, payloadSize)
	for i := range payloadData {
		payloadData[i] = byte(i % 256)
	}

	// We wrap it in a raw packet.
	// Since raw sockets accept raw layer 3 payloads, we can build a packet with a dummy ICMP header and our large payload.
	icmp := layers.NewICMPEcho(0x1234, 1)
	pkt := packet.NewFrom(icmp)
	pktPayload, err := pkt.Build()
	if err != nil {
		log.Fatalf("Failed to build ICMP payload: %v", err)
	}
	// Append the large payload
	fullPayload := append(pktPayload, payloadData...)

	numSends := 500
	totalBytes := int64(len(fullPayload)) * int64(numSends)

	// 1. Benchmark normal copy send
	fmt.Printf("Sending %d packets of size %d bytes (Total: %.2f MB) using normal copy...\n",
		numSends, len(fullPayload), float64(totalBytes)/(1024*1024))

	startNormal := time.Now()
	for i := 0; i < numSends; i++ {
		err = conn.Send(fullPayload, "127.0.0.1")
		if err != nil {
			log.Fatalf("Normal send failed: %v", err)
		}
	}
	elapsedNormal := time.Since(startNormal)
	throughputNormal := float64(totalBytes) / (1024 * 1024) / elapsedNormal.Seconds()
	fmt.Printf("Normal send took: %v (%.2f MB/s)\n", elapsedNormal, throughputNormal)

	// 2. Try enabling ZeroCopy
	fmt.Println("\nAttempting to enable ZeroCopy...")
	err = conn.SetZeroCopy(true)
	if err != nil {
		if errors.Is(err, sendrecv.ErrNotSupported) {
			fmt.Println("ZeroCopy is not supported on this platform. (Expected fallback behavior on macOS).")
			return
		}
		log.Fatalf("SetZeroCopy failed: %v", err)
	}
	defer conn.SetZeroCopy(false)
	fmt.Println("ZeroCopy enabled successfully.")

	// 3. Benchmark ZeroCopy send
	fmt.Printf("Sending %d packets of size %d bytes (Total: %.2f MB) using ZeroCopy...\n",
		numSends, len(fullPayload), float64(totalBytes)/(1024*1024))

	startZero := time.Now()
	for i := 0; i < numSends; i++ {
		err = conn.Send(fullPayload, "127.0.0.1")
		if err != nil {
			log.Fatalf("ZeroCopy send failed: %v", err)
		}
	}

	// Wait for zero copy completions
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Println("Waiting for ZeroCopy completions...")
	err = conn.WaitZeroCopyCompletion(ctx)
	if err != nil {
		log.Fatalf("WaitZeroCopyCompletion failed: %v", err)
	}

	elapsedZero := time.Since(startZero)
	throughputZero := float64(totalBytes) / (1024 * 1024) / elapsedZero.Seconds()
	fmt.Printf("ZeroCopy send took: %v (%.2f MB/s)\n", elapsedZero, throughputZero)

	fmt.Printf("\nPerformance comparison:\n")
	fmt.Printf("Normal Copy: %.2f MB/s\n", throughputNormal)
	fmt.Printf("ZeroCopy:    %.2f MB/s\n", throughputZero)
}
