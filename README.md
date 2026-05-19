# goscapy

[![Go Reference](https://pkg.go.dev/badge/github.com/smallnest/goscapy.svg)](https://pkg.go.dev/github.com/smallnest/goscapy)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.26-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-green)](LICENSE)

A pure Go library for crafting, dissecting, sending, receiving, and sniffing network packets. goscapy provides an idiomatic Go API with type-safe builders and one-liner shortcut functions.

## Features

- **Builder API** — fluent method chaining for type-safe, explicit packet construction
- **Shortcut Functions** — one-liners for common protocol stacks with sensible defaults
- **Packet Dissect** — parse raw bytes into structured packets with auto protocol detection
- **Send & Receive** — send and receive packets via raw sockets (L2 and L3)
- **Packet Sniffing** — capture live traffic with callback or channel-based APIs, plus BPF filter support
- **Auto Checksums** — IP, TCP, UDP, and ICMP checksums are computed automatically during serialization
- **Layer Binding** — automatic field inference between adjacent layers (e.g., IP over Ethernet → EtherType=0x0800)
- **Cross-Platform** — Darwin (macOS) and Linux with platform-specific raw socket implementations

## Supported Protocols

| Layer | Protocols |
|-------|-----------|
| Link | Ethernet, ARP |
| Network | IPv4 |
| Transport | TCP, UDP, ICMP |
| Payload | Raw |

## Installation

```bash
go get github.com/smallnest/goscapy
```

## Quick Start

### Build a Packet (Builder API)

```go
// Ethernet + IP + ICMP Echo Request
pkt, err := goscapy.NewEthernet().
    SrcMAC("aa:bb:cc:dd:ee:ff").
    DstMAC("ff:ff:ff:ff:ff:ff").
    Over(goscapy.NewIP().SrcIP("192.168.1.1").DstIP("8.8.8.8")).
    Over(goscapy.NewICMP().Type(8).Code(0)).
    Build()
```

### Build a Packet (Shortcut)

```go
// Same as above, in one line
pkt, err := goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
```

### Dissect a Packet

```go
raw := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, ...} // raw bytes
pkt, err := packet.Dissect(raw, packet.DissectEthernet)
fmt.Println(pkt.String()) // "Ethernet / IP / ICMP"
```

### Send a Packet

```go
pkt, _ := goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
sendrecv.Send(pkt, "eth0")  // send at L3 (IP level)
sendrecv.Sendp(pkt, "eth0") // send at L2 (Ethernet)
```

### Sniff Packets

```go
// Callback-based
sniff.Sniff(sniff.SniffConfig{
    Iface:   "eth0",
    Filter:  "icmp",
    Timeout: 10 * time.Second,
}, func(pkt *packet.Packet) bool {
    fmt.Println(pkt)
    return true // continue sniffing
})

// Channel-based
ch, stop := sniff.SniffChan(sniff.SniffConfig{Iface: "eth0", Count: 5})
defer stop()
for pkt := range ch {
    fmt.Println(pkt)
}
```

## Documentation

Full documentation is available at [pkg.go.dev/github.com/smallnest/goscapy](https://pkg.go.dev/github.com/smallnest/goscapy).

### Packages

| Package | Description |
|---------|-------------|
| `pkg/goscapy` | Builder API and shortcut functions |
| `pkg/packet` | Core packet/layer types, build, dissect, field binding |
| `pkg/layers` | Protocol layer definitions (Ethernet, ARP, IP, TCP, UDP, ICMP, Raw) |
| `pkg/sendrecv` | Raw socket send/receive (Send, Sendp, Recv, SendRecv) |
| `pkg/sniff` | Packet sniffing with BPF filter support |
| `pkg/fields` | Field type system (serialization, deserialization) |

### Shortcut Functions

| Function | Protocol Stack |
|----------|---------------|
| `EtherIP` | Ethernet + IPv4 + Payload |
| `EtherIPICMP` | Ethernet + IPv4 + ICMP |
| `EtherIPTCP` | Ethernet + IPv4 + TCP |
| `EtherIPUDP` | Ethernet + IPv4 + UDP |
| `EtherARP` | Ethernet + ARP |
| `IPICMP` | IPv4 + ICMP (no Ethernet) |
| `IPTCP` | IPv4 + TCP (no Ethernet) |
| `IPUDP` | IPv4 + UDP (no Ethernet) |

### Builders

| Builder | Key Methods |
|---------|-------------|
| `EthernetBuilder` | `SrcMAC`, `DstMAC`, `Type` |
| `IPBuilder` | `SrcIP`, `DstIP`, `TTL`, `Proto`, `ID` |
| `ICMPBuilder` | `Type`, `Code`, `ID`, `Seq` |
| `TCPBuilder` | `SrcPort`, `DstPort`, `Flags`, `Seq`, `Ack`, `Window` |
| `UDPBuilder` | `SrcPort`, `DstPort` |
| `ARPBuilder` | `Op`, `SrcMAC`, `SrcIP`, `DstMAC`, `DstIP` |

## Platform Support

| Platform | L2 Send/Recv | L3 Send/Recv | BPF Filter | Loopback |
|----------|:------------:|:------------:|:----------:|:--------:|
| macOS (Darwin) | BPF | AF_INET | kernel BPF | lo0 |
| Linux | AF_PACKET | AF_INET | SO_ATTACH_FILTER | lo |

## Requirements

- Go 1.26+
- macOS or Linux
- Root/administrator privileges for raw socket operations
- `tcpdump` (optional, for BPF filter string compilation via `sniff.CompileFilter`)

## Makefile

```bash
make build         # Build all packages
make test          # Run all tests
make test-race     # Run tests with race detector
make test-cover    # Run tests with coverage profile
make bench         # Run benchmarks
make lint          # Run golangci-lint
make fmt           # Format code
make vet           # Run go vet
make check         # Run fmt + vet + lint + test
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.