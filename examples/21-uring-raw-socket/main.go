package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Simple checksum calculation
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func buildICMPEcho(id, seq uint16) []byte {
	icmp := make([]byte, 8+32)
	icmp[0] = 8 // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], []byte("GOSCAPY IO_URING PING MATCH TEST"))

	cs := checksum(icmp)
	binary.BigEndian.PutUint16(icmp[2:4], cs)
	return icmp
}

func main() {
	if os.Getuid() != 0 {
		fmt.Println("Warning: This example requires root privileges to open raw sockets.")
		fmt.Println("Please run with sudo: sudo go run examples/21-uring-raw-socket/main.go")
		os.Exit(1)
	}

	fmt.Println("Starting io_uring Raw Socket example...")

	// 1. Dial io_uring raw socket for ICMP
	conn, err := sendrecv.DialUringRaw(1) // 1 = IPPROTO_ICMP
	if err != nil {
		fmt.Printf("Failed to dial io_uring raw socket: %v\n", err)
		fmt.Println("This might be because io_uring is unsupported on this system or kernel version.")
		return
	}
	defer conn.Close()

	dstIP := "127.0.0.1"
	payload := buildICMPEcho(1234, 1)

	// 2. Demo asynchronous send
	fmt.Printf("Submitting async send SQE to %s...\n", dstIP)
	opID, err := conn.Send(payload, dstIP)
	if err != nil {
		fmt.Printf("Send failed: %v\n", err)
		return
	}
	fmt.Printf("SQE submitted successfully! Operation ID: %d\n", opID)

	// 3. Demo receive
	fmt.Println("Waiting for ICMP Echo Reply CQE...")
	data, src, err := conn.Recv(3 * time.Second)
	if err != nil {
		fmt.Printf("Recv failed or timed out: %v\n", err)
	} else {
		fmt.Printf("Received %d bytes from %s\n", len(data), src)
	}

	// 4. Demo SendRecvBatch
	fmt.Println("\nTesting SendRecvBatch...")
	batchMsgs := []sendrecv.BatchMsg{
		{Data: buildICMPEcho(5678, 1), Dst: "127.0.0.1"},
		{Data: buildICMPEcho(5678, 2), Dst: "127.0.0.1"},
	}

	results, err := conn.SendRecvBatch(batchMsgs)
	if err != nil {
		fmt.Printf("SendRecvBatch failed: %v\n", err)
		return
	}

	fmt.Printf("Batch completed! Received %d results:\n", len(results))
	for i, r := range results {
		if len(r.Data) > 0 {
			fmt.Printf("  [%d] Received %d bytes from %s\n", i, len(r.Data), r.Src)
		} else {
			fmt.Printf("  [%d] Timed out or no response\n", i)
		}
	}
}
