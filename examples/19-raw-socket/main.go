package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	if os.Getuid() != 0 {
		fmt.Println("Warning: This example requires root privileges to open raw sockets.")
		fmt.Println("Please run with sudo: sudo go run examples/19-raw-socket/main.go")
		os.Exit(1)
	}

	// 1. Connection-oriented RawConn API
	fmt.Println("=== Testing RawConn connection-oriented API ===")
	fmt.Println("Dialing raw ICMP socket...")
	conn, err := sendrecv.DialRaw(1) // 1 = ICMP
	if err != nil {
		log.Fatalf("Failed to dial raw socket: %v", err)
	}
	defer conn.Close()

	// Build an ICMP Echo Request payload
	icmp := layers.NewICMPEcho(0x5555, 1)
	pkt := packet.NewFrom(icmp)
	payload, err := pkt.Build()
	if err != nil {
		log.Fatalf("Failed to build ICMP payload: %v", err)
	}

	fmt.Println("Sending ICMP Echo Request to 127.0.0.1...")
	err = conn.Send(payload, "127.0.0.1")
	if err != nil {
		log.Fatalf("Failed to send: %v", err)
	}

	fmt.Println("Waiting for response...")
	data, srcIP, err := conn.Recv(3 * time.Second)
	if err != nil {
		if errors.Is(err, sendrecv.ErrTimeout) {
			log.Fatalf("Timeout waiting for response")
		}
		log.Fatalf("Receive error: %v", err)
	}

	fmt.Printf("Received %d bytes from %s\n", len(data), srcIP)

	// 2. Using a second RawConn to send and receive
	fmt.Println("\n=== Testing Send / Recv with a second RawConn ===")
	// Build another ICMP Echo Request payload
	icmp2 := layers.NewICMPEcho(0x6666, 1)
	pkt2 := packet.NewFrom(icmp2)
	payload2, err := pkt2.Build()
	if err != nil {
		log.Fatalf("Failed to build ICMP payload 2: %v", err)
	}

	// Note: SendRaw and RecvRaw each create ephemeral sockets. On loopback,
	// the ICMP reply may arrive before RecvRaw opens its socket. Use a single
	// RawConn for send+recv to avoid this race.
	conn2, err := sendrecv.DialRaw(1)
	if err != nil {
		log.Fatalf("Failed to dial raw socket 2: %v", err)
	}
	defer conn2.Close()

	fmt.Println("Sending ICMP Echo Request to 127.0.0.1...")
	err = conn2.Send(payload2, "127.0.0.1")
	if err != nil {
		log.Fatalf("Send failed: %v", err)
	}

	fmt.Println("Waiting for response...")
	data2, srcIP2, err := conn2.Recv(3 * time.Second)
	if err != nil {
		if errors.Is(err, sendrecv.ErrTimeout) {
			log.Fatalf("Timeout waiting for response")
		}
		log.Fatalf("Recv error: %v", err)
	}

	fmt.Printf("Received %d bytes from %s using RecvRaw\n", len(data2), srcIP2)

	// Dissect response to inspect it
	ipStartFn := func(_ []byte) (string, error) {
		return "IP", nil
	}
	pktReply, err := packet.Dissect(data2, ipStartFn)
	if err != nil {
		log.Fatalf("Failed to dissect received packet: %v", err)
	}

	fmt.Println("Packet structure:", pktReply.String())
	icmpLayer := pktReply.GetLayer("ICMP")
	if icmpLayer != nil {
		icmpType, _ := icmpLayer.Get("type")
		icmpCode, _ := icmpLayer.Get("code")
		icmpID, _ := icmpLayer.Get("id")
		fmt.Printf("ICMP Layer details: type=%v, code=%v, id=0x%x\n", icmpType, icmpCode, icmpID)
	}
}
