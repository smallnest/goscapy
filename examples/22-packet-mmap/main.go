package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	if os.Getuid() != 0 {
		fmt.Println("Warning: This example requires root privileges to open raw AF_PACKET sockets.")
		fmt.Println("Please run with sudo: sudo go run examples/22-packet-mmap/main.go <interface>")
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo go run examples/22-packet-mmap/main.go <interface>")
		fmt.Println("Example: sudo go run examples/22-packet-mmap/main.go eth0")
		os.Exit(1)
	}

	iface := os.Args[1]
	fmt.Printf("Initializing PacketMMAP (TPACKET_V3) on interface: %s...\n", iface)

	m, err := sendrecv.NewPacketMMAP(iface)
	if err != nil {
		fmt.Printf("Failed to create PacketMMAP: %v\n", err)
		fmt.Println("This feature is only supported on Linux kernels with TPACKET_V3 support.")
		return
	}
	defer m.Close()

	fmt.Println("PacketMMAP initialized successfully! Capturing packets...")
	fmt.Println("Press Ctrl+C to stop.")

	// Channel for graceful termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Go routine to periodically print stats
	statsTicker := time.NewTicker(2 * time.Second)
	defer statsTicker.Stop()

	go func() {
		for range statsTicker.C {
			stats := m.Stats()
			fmt.Printf("\r[Stats] Received: %d | Dropped: %d | Freeze: %d", stats.Received, stats.Dropped, stats.Freeze)
		}
	}()

	// Capture loop
	packetChan := make(chan string)
	errChan := make(chan error)

	go func() {
		for {
			pkt, err := m.Recv(1 * time.Second)
			if err != nil {
				if err.Error() == "sendrecv: recv timeout" {
					continue
				}
				errChan <- err
				return
			}
			packetChan <- pkt.String()
		}
	}()

	for {
		select {
		case pktStr := <-packetChan:
			fmt.Printf("\n[Packet Captured] %s\n", pktStr)
		case err := <-errChan:
			fmt.Printf("\nCapture error: %v\n", err)
			return
		case <-sigChan:
			fmt.Println("\nStopping capture...")
			return
		}
	}
}
