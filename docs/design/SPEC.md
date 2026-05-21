# SPEC: goscapy

> Reverse-engineered specification — generated 2026-05-21 from commit `f93567b`

## 1. Overview

### 1.1 Purpose

goscapy is a pure-Go library for crafting, dissecting, sending, receiving, and sniffing network packets — the Go equivalent of Python's Scapy. It provides an idiomatic, type-safe API with fluent builders and one-liner shortcut functions. The target audience is network engineers, security researchers, and Go developers building network tools (port scanners, packet generators, network monitors, protocol test harnesses).

### 1.2 Key Capabilities

- **Build** arbitrary protocol stacks via fluent Builder API or one-liner shortcut functions
- **Dissect** raw bytes into structured, typed packet objects with automatic protocol detection
- **Send** packets at L2 (full Ethernet frames) or L3 (IP-level, OS handles framing) via raw sockets
- **Receive** packets from network interfaces with BPF filtering
- **Sniff** live traffic with callback or channel-based APIs, BPF filter support
- **Read/write pcap/pcapng** files in pure Go (no libpcap dependency)
- **Reassemble** IP fragments into complete packets
- **Rate-limit** packet transmission with token bucket algorithm
- **Zero-copy** send support (MSG_ZEROCOPY on Linux)
- **Batch** send/receive via sendmmsg/recvmmsg
- **io_uring** raw socket I/O (Linux)
- **AF_PACKET Fanout** multi-core parallel capture (Linux)
- **AF_XDP (XSK)** zero-copy/copy-mode packet I/O (Linux)
- **Packet MMAP** TPACKET_V3 ring buffer (Linux)
- **Auto-compute** IP/TCP/UDP/ICMP checksums, lengths, and inter-layer bindings

### 1.3 Architecture Style

Single-module Go library with layered internal architecture: **Field types → Layer definitions → Packet assembly/dissection → Builder/Shortcut API → Platform-specific I/O**. The public API surface is split across 8 packages: `goscapy` (builders/shortcuts), `packet` (core types), `layers` (protocol definitions), `fields` (field type system), `sendrecv` (raw socket I/O), `sniff` (capture), `pcap` (file I/O), and `reassembly` (IP fragment reassembly).

---

## 2. Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Go | 1.26+ |
| External Dependency | golang.org/x/sys | v0.44.0 |
| Build | `go build` | — |
| Test | `go test` (standard library) | — |
| Lint | golangci-lint | — |
| Format | gofmt + goimports | — |
| Optional Tool | tcpdump (BPF filter compilation) | any |
| License | MIT | — |

---

## 3. Project Structure

```
goscapy/
├── pkg/
│   ├── fields/            # Field type system — serialization/deserialization primitives
│   │   ├── field.go       #   Field interface, Desc metadata
│   │   ├── types.go       #   Byte/Short/Int/Long fields, MAC/IP/IPv6, Str, BitField, etc.
│   │   ├── tlv.go         #   TLV option parsing (DHCP, NDP, DNS EDNS)
│   │   └── *_test.go      #   Unit tests
│   ├── packet/            # Core packet/layer abstraction
│   │   ├── packet.go      #   Packet (ordered layer stack), Push/Insert/GetLayer/Build
│   │   ├── layer.go       #   Layer (proto name + field definitions + values map)
│   │   ├── build.go       #   BuildHook system — 4-phase serialization with derived fields
│   │   ├── dissect.go     #   Dissect engine — recursive protocol parsing with heuristics
│   │   ├── binding.go     #   Inter-layer field binding (auto-set lower-layer protocol type)
│   │   └── *_test.go      #   Unit tests
│   ├── layers/            # Protocol layer definitions and build/dissect registrations
│   │   ├── init.go        #   Central registration: bindings, build hooks, dissectors, heuristics
│   │   ├── ethernet.go    #   Ethernet frame (dst, src, type)
│   │   ├── arp.go         #   ARP message (hwtype, ptype, op, hwsrc/psrc, hwdst/pdst)
│   │   ├── ip.go          #   IPv4 header (verihl, tos, len, id, frag, ttl, proto, chksum, src, dst)
│   │   ├── ipv6.go        #   IPv6 header + extension headers (Hop-by-Hop, Routing, Fragment, DestOpts)
│   │   ├── tcp.go         #   TCP header (ports, seq/ack, dataofs, flags, window, chksum, urgptr)
│   │   ├── tcp_options.go #   TCP option parsing/construction (MSS, WScale, SACK, Timestamp, NOP)
│   │   ├── udp.go         #   UDP header (ports, len, chksum)
│   │   ├── icmp.go        #   ICMP header (type, code, chksum, id, seq)
│   │   ├── icmpv6.go      #   ICMPv6 base header + Echo sub-layer
│   │   ├── ndp.go         #   NDP messages (RS, RA, NS, NA, Redirect) with TLV options
│   │   ├── raw.go         #   Raw payload layer
│   │   ├── checksum.go    #   IP/TCP/UDP/ICMP/ICMPv6 checksum computations
│   │   ├── helpers.go     #   IP address resolution helpers for checksums
│   │   ├── dns/           #   DNS message layer (header + question/resource record sections)
│   │   ├── dhcp/          #   DHCP/BOOTP layer with TLV options
│   │   ├── dot1q/         #   802.1Q VLAN tag (TPID, PCP, DEI, VID)
│   │   ├── vxlan/         #   VXLAN encapsulation (flags, VNI)
│   │   ├── gre/           #   GRE tunnel (flags, version, protocol, optional key/seq/chksum)
│   │   ├── lldp/          #   LLDP (structured LLDPDU with Chassis/Port/TTL/System TLVs)
│   │   ├── erspan/        #   ERSPAN v3 encapsulation
│   │   ├── ospf/          #   OSPFv2 header
│   │   ├── bgp/           #   BGP common header
│   │   └── quic/          #   QUIC Long Header
│   ├── goscapy/           # Top-level public API — Builders and Shortcuts
│   │   ├── goscapy.go     #   Builder types: EthernetBuilder, IPBuilder, TCPBuilder, etc.
│   │   ├── shortcuts.go   #   One-liner functions: EtherIPICMP, EtherARP, IPTCPBGP, etc.
│   │   └── goscapy_test.go
│   ├── sendrecv/          # Raw socket packet I/O (platform-specific)
│   │   ├── sendrecv.go    #   Public API: Send, Sendp, Recv, SendRecv, Sr, Sr1, Srp, Srp1
│   │   ├── sendrecv_darwin.go  # macOS: BPF for L2, AF_INET/AF_INET6 for L3, IPv6 unicast hops
│   │   ├── sendrecv_linux.go   # Linux: AF_PACKET for L2, AF_INET/AF_INET6+HDRINCL for L3
│   │   ├── rawconn.go     #   RawConn — direct raw socket with optional zero-copy, RecvInto
│   │   ├── batch.go       #   BatchConn — sendmmsg/recvmmsg batch operations
│   │   ├── ratelimit.go   #   TokenBucketLimiter — rate-controlled send
│   │   ├── fanout_linux.go    # AF_PACKET Fanout (PACKET_FANOUT) multi-core capture
│   │   ├── iface.go       #   Interface lookup helper
│   │   ├── zerocopy_*.go  #   MSG_ZEROCOPY support (Linux)
│   │   ├── mmap_*.go      #   TPACKET_V3 ring buffer (Linux)
│   │   ├── uring_*.go     #   io_uring raw socket (Linux)
│   │   ├── xdp_*.go       #   AF_XDP XSK (Linux)
│   │   ├── batch_*.go     #   Platform-specific batch implementations
│   │   ├── filter_*.go    #   Platform-specific BPF filter attachment
│   │   ├── doc.go         #   Package documentation
│   │   └── *_test.go
│   ├── sniff/             # Packet capture with BPF filtering
│   │   ├── sniff.go       #   Sniff (callback), SniffChan (channel), SniffConfig
│   │   ├── filter.go      #   CompileFilter via tcpdump -dd, parseDDOutput
│   │   └── *_test.go
│   ├── pcap/              # Pure-Go pcap/pcapng file reader and writer
│   │   ├── reader.go      #   Reader: auto-detect format, read pcap/pcapng, link-type dispatch
│   │   ├── writer.go      #   Writer: write pcap global header + per-packet records
│   │   └── pcap_test.go
│   └── reassembly/        # IP fragment reassembly
│       ├── reassembly.go  #   Reassembler: Submit fragments, tryReassemble, GC, DoS protection
│       └── reassembly_test.go
├── examples/              # 40 example programs (01 through 40)
├── docs/                  # Project website (HTML/CSS/JS, English + Chinese)
├── tasks/                 # PRD documents for feature planning
├── go.mod / go.sum
├── Makefile
├── README.md / README_CN.md
└── LICENSE (MIT)
```

---

## 4. Data Model

### 4.1 Core Entities

#### 4.1.1 Field (`fields.Field` interface)

The fundamental building block. Each field represents a single piece of a protocol header and knows how to serialize/deserialize itself.

```
Field interface {
    Name() string
    FixedSize() int      // 0 for variable-length fields
    DefaultVal() any
    Pack(val any) ([]byte, error)
    Unpack(b []byte) (val any, consumed int, err error)
}
```

**Concrete field types (19 total):**

| Type | Wire Size | Go Type | Notes |
|------|-----------|---------|-------|
| `ByteField` | 1 | `uint8` | Unsigned byte |
| `XByteField` | 1 | `uint8` | Hex-display byte |
| `ShortField` | 2 | `uint16` | Big-endian |
| `LEShortField` | 2 | `uint16` | Little-endian |
| `ThreeBytesField` | 3 | `uint32` | Big-endian, max 0xFFFFFF |
| `IntField` | 4 | `uint32` | Big-endian unsigned |
| `SignedIntField` | 4 | `int32` | Big-endian signed |
| `LEIntField` | 4 | `uint32` | Little-endian unsigned |
| `LongField` | 8 | `uint64` | Big-endian |
| `LELongField` | 8 | `uint64` | Little-endian |
| `BitField` | 0 | `uint8` | 1-8 bits; packed by outer bit-group |
| `MACField` | 6 | `net.HardwareAddr` / `string` / `[]byte` | MAC address |
| `IPField` | 4 | `net.IP` / `string` | IPv4 address |
| `IPv6Field` | 16 | `net.IP` / `string` / `[]byte` | IPv6 address |
| `StrField` | 0 | `string` / `[]byte` | Variable-length, consumes remainder |
| `StrLenField` | 0 | `string` / `[]byte` | Length from another field |
| `StrFixedField` | N | `string` / `[]byte` | Fixed N bytes, zero-padded |
| `PacketField` | 0 | `[]byte` | Nested sub-packet |
| `ConditionalField` | varies | wraps any Field | Active based on runtime values |

#### 4.1.2 Layer (`packet.Layer`)

A protocol header instance. Holds a protocol name, ordered field definitions, and runtime field values.

```
Layer {
    proto  string           // e.g. "Ethernet", "IP", "TCP"
    fields []fields.Field   // ordered field definitions
    values map[string]any   // runtime field name → value
}
```

Key operations:
- `Get(name) / Set(name, val)` — read/write field values
- `SerializeFields()` — pack all active fields into bytes (naive pass)
- `ParseFields(data)` — unpack bytes into field values (dissect pass)
- `Over(upper)` — stack an upper layer, apply bindings, return Packet

#### 4.1.3 Packet (`packet.Packet`)

An ordered stack of Layers forming a complete network packet.

```
Packet {
    layers []*Layer   // [Ethernet, IP, TCP, Raw]
}
```

Key operations:
- `Push(layer)` — add layer on top
- `Insert(layer)` — add layer at bottom
- `InsertAfter(proto, layer)` — insert after matching layer
- `GetLayer(proto) / HasLayer(proto)` — layer lookup
- `Sync()` — re-apply all binding rules
- `Build() / BuildFrom(startIdx)` — 4-phase serialization
- `Copy()` — shallow copy

#### 4.1.4 TCPOption (`layers.TCPOption`)

Represents a single TCP option in Kind-Length-Value format.

```
TCPOption {
    Kind   uint8    // IANA-assigned: MSS(2), WScale(3), SACKPerm(4), SACK(5), Timestamp(8), NOP(1), EOL(0)
    Length uint8    // Total length including Kind and Length
    Data   []byte   // Option-specific payload (Length - 2 bytes)
}
```

#### 4.1.5 TLVOption (`fields.TLVOption`)

Generic Type-Length-Value option for protocols like DHCP, NDP, DNS EDNS.

```
TLVOption {
    Type   uint8
    Length uint8
    Value  []byte
}
```

#### 4.1.6 BPFInstruction (`sendrecv.BPFInstruction`)

A single classic BPF instruction matching `struct bpf_insn` / `struct sock_filter`.

```
BPFInstruction {
    Code uint16
    Jt   uint8
    Jf   uint8
    K    uint32
}
```

#### 4.1.7 PacketRecord (`pcap.PacketRecord`)

A captured packet with metadata from pcap/pcapng files.

```
PacketRecord {
    Timestamp  time.Time
    CaptureLen uint32
    OrigLen    uint32
    Data       []byte
    LinkType   uint32
}
```

#### 4.1.8 FragGroup / Fragment (`reassembly`)

Internal structures for IP fragment reassembly. Keyed by `(src_ip, dst_ip, id, proto)`. Tracks fragments via coverage bitmap, expires groups after timeout (default 30s), limits concurrent groups (default 1024) as DoS protection.

### 4.2 State Transitions

**Packet Build (4-phase serialization):**

```
Phase 1: Naive-serialize all layers (checksums at zero, lengths at defaults)
Phase 2: Compute cumulative byte sizes (bottom-up)
Phase 3: Call BuildHooks bottom-to-top for derived fields (checksums, lengths)
         Each hook receives upper-layer bytes, sets computed fields, re-serializes
Phase 4: Return concatenated wire-format bytes
```

**Packet Dissect (recursive protocol parsing):**

```
1. Start with known protocol (from startFn or previous layer's key field)
2. Create layer via registered factory, call ParseFields
3. Compute actual header size (fixed or via HeaderSizeFunc)
4. Call PostParseHook for variable-length fields (e.g., TCP options)
5. Push layer onto packet
6. If tunnel protocol → recursively dissect inner payload
7. Resolve next protocol via key field → next-layer map
8. Leftover bytes become Raw payload
9. Max recursion depth: 8 (tunnel nesting protection)
```

---

## 5. API Surface

### 5.1 Builder API (package `goscapy`)

Each protocol has a `*Builder` type with fluent setter methods returning the builder for chaining. All builders implement `LayerBuilder` (exposes `.Layer()`). Chain terminates with `.Build()` returning `([]byte, error)`.

| Builder | Factory | Key Setters | Protocol Stack Depth |
|---------|---------|-------------|---------------------|
| `EthernetBuilder` | `NewEthernet()` | `DstMAC`, `SrcMAC`, `Type`, `Over` | Base |
| `IPBuilder` | `NewIP()` | `SrcIP`, `DstIP`, `TTL`, `Proto`, `ID`, `Over` | Base |
| `IPv6Builder` | `NewIPv6()` | `SrcIP`, `DstIP`, `NH`, `HLim`, `TC`, `FL`, `Over` | Base |
| `ICMPBuilder` | `NewICMP()` | `Type`, `Code`, `ID`, `Seq` | Upper |
| `ICMPv6Builder` | `NewICMPv6()` | `Type`, `Code` | Upper |
| `TCPBuilder` | `NewTCP()` | `SrcPort`, `DstPort`, `Flags`, `Seq`, `Ack`, `Window`, `Over` | Upper |
| `UDPBuilder` | `NewUDP()` | `SrcPort`, `DstPort`, `Over` | Upper |
| `ARPBuilder` | `NewARP()` | `Op`, `SrcMAC`, `SrcIP`, `DstMAC`, `DstIP`, `Over` | Upper |
| `DNSBuilder` | `NewDNS()` | `ID`, `Flags`, `Questions`, `Data` | Upper |
| `DHCPBuilder` | `NewDHCP()` | `Op`, `XID`, `CIAddr`, `YIAddr`, `MessageType`, `Options` | Upper |
| `Dot1QBuilder` | `NewDot1Q()` | `VID`, `PCP`, `DEI`, `Type`, `TPID`, `Over` | Middle |
| `VXLANBuilder` | `NewVXLAN()` | `VNI`, `Flags`, `Over` | Middle |
| `GREBuilder` | `NewGRE()` | `ProtocolType`, `Key`, `Seq`, `SetChecksum`, `Over` | Middle |
| `LLDPBuilder` | `NewLLDPLayer()` | `TLVData`, `LLDPDU` | Upper |
| `ERSPANBuilder` | `NewERSPANLayer()` | `FromERSPAN` | Middle |
| `OSPFBuilder` | `NewOSPFLayer()` | `RouterID`, `AreaID`, `Type`, `Over` | Upper |
| `BGPBuilder` | `NewBGPLayer()` | `Type`, `Over` | Upper |
| `QUICBuilder` | `NewQUICLayer()` | `Version`, `DCID`, `SCID`, `Over` | Upper |

Builder stacking example:
```go
pkt, _ := goscapy.NewEthernet().
    SrcMAC("aa:bb:cc:dd:ee:ff").DstMAC("ff:ff:ff:ff:ff:ff").
    Over(goscapy.NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2")).
    Over(goscapy.NewTCP().SrcPort(1234).DstPort(80).Flags(layers.TCPSyn)).
    Build()
```

### 5.2 Shortcut Functions (package `goscapy`)

One-liner functions that build and serialize common protocol stacks with sensible defaults.

| Function | Stack | Signature |
|----------|-------|-----------|
| `EtherIP` | Eth + IP + Raw | `(srcMAC, dstMAC, srcIP, dstIP string, payload []byte) ([]byte, error)` |
| `EtherIPICMP` | Eth + IP + ICMP | `(dstMAC, dstIP string, icmpType, icmpCode uint8) ([]byte, error)` |
| `EtherIPTCP` | Eth + IP + TCP | `(srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, flags uint8) ([]byte, error)` |
| `EtherIPUDP` | Eth + IP + UDP | `(srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16) ([]byte, error)` |
| `EtherARP` | Eth + ARP | `(srcMAC, dstMAC, psrc, pdst string, op uint16) ([]byte, error)` |
| `IPICMP` | IP + ICMP | `(srcIP, dstIP string, icmpType, icmpCode uint8) ([]byte, error)` |
| `IPTCP` | IP + TCP | `(srcIP, dstIP string, srcPort, dstPort uint16, flags uint8) ([]byte, error)` |
| `IPUDP` | IP + UDP | `(srcIP, dstIP string, srcPort, dstPort uint16) ([]byte, error)` |
| `IPv6ICMPv6Echo` | IPv6 + ICMPv6 Echo | `(srcIP, dstIP string, id, seq uint16) ([]byte, error)` |
| `EtherDot1QIP` | Eth + Dot1Q + IP | `(srcMAC, dstMAC, srcIP, dstIP string, vid uint16) ([]byte, error)` |
| `EtherIPUDPVXLAN` | Eth + IP + UDP + VXLAN | `(srcMAC, dstMAC, srcIP, dstIP string, vni uint32, innerPayload []byte) ([]byte, error)` |
| `EtherIPGRE` | Eth + IP + GRE | `(srcMAC, dstMAC, srcIP, dstIP string, protoType uint16, key uint32, innerPayload []byte) ([]byte, error)` |
| `EtherIPUDPDNS` | Eth + IP + UDP + DNS | `(srcMAC, dstMAC, srcIP, dstIP string, dnsPort uint16, questions []dns.DNSQuestion) ([]byte, error)` |
| `EtherIPUDPDHCP` | Eth + IP + UDP + DHCP | `(srcMAC, dstMAC string, xid uint32, msgType uint8) ([]byte, error)` |
| `EtherLLDP` | Eth + LLDP | `(srcMAC string, du *lldp.LLDPDU) ([]byte, error)` |
| `EtherIPGREERSPAN` | Eth + IP + GRE + ERSPAN | `(srcMAC, dstMAC, srcIP, dstIP string, e *erspan.ERSPAN, innerPayload []byte) ([]byte, error)` |
| `IPOSPF` | IP + OSPF | `(srcIP, dstIP, routerID, areaID string, msgType uint8) ([]byte, error)` |
| `IPTCPBGP` | IP + TCP + BGP | `(srcIP, dstIP string, srcPort, dstPort uint16, msgType uint8) ([]byte, error)` |
| `IPUDPQUIC` | IP + UDP + QUIC | `(srcIP, dstIP string, srcPort, dstPort uint16, dcid, scid []byte) ([]byte, error)` |

### 5.3 Dissect API (package `packet`)

| Function | Description |
|----------|-------------|
| `Dissect(raw []byte, startFn func([]byte) (string, error)) (*Packet, error)` | Parse from unknown start protocol |
| `DissectByProto(raw []byte, firstProto string) (*Packet, error)` | Parse from known protocol name |

**Dissect entry points:**
- `packet.DissectEthernet` — start from Ethernet (for `Dissect` compat)
- `"Ethernet"`, `"IP"`, `"IPv6"`, `"ARP"`, etc. — for `DissectByProto`

### 5.4 Send/Recv API (package `sendrecv`)

#### Core Functions

| Function | Layer | Description |
|----------|-------|-------------|
| `Send(pkt, iface)` | L3 | Send at IP level (OS handles L2) |
| `Sendp(pkt, iface)` | L2 | Send full Ethernet frame |
| `Recv(iface, timeout)` | — | Open receiver, read one packet, close |
| `SendRecv(pkt, iface, timeout)` | L3 | Send then collect all responses |
| `SendRecv1(pkt, iface, timeout)` | L3 | Send then return first response |
| `SendRecvFiltered(pkt, iface, timeout, instructions)` | L3 | SendRecv with BPF filter |
| `SendRecvFiltered1(pkt, iface, timeout, instructions)` | L3 | SendRecv1 with BPF filter |
| `Sr(pkt, iface, timeout, match)` | L3 | Send + match responses (Scapy sr()) |
| `Sr1(pkt, iface, timeout, match)` | L3 | Send + first match (Scapy sr1()) |
| `Srp(pkt, iface, timeout, match)` | L2 | Sendp + match responses (Scapy srp()) |
| `Srp1(pkt, iface, timeout, match)` | L2 | Sendp + first match (Scapy srp1()) |

#### Receiver Interface

```go
type Receiver interface {
    Recv(timeout time.Duration) (*packet.Packet, error)
    RecvInto(buf []byte, timeout time.Duration) (*packet.Packet, int, error)
    Close() error
}
```

#### Advanced I/O

| Type | Description |
|------|-------------|
| `RawConn` | Direct raw socket connection; `Send(data, dst)`, `Recv(timeout)`, `RecvInto(buf, timeout)` |
| `BatchConn` | Batch send/receive via sendmmsg/recvmmsg |
| `TokenBucketLimiter` | Rate control: `Wait(ctx)`, used with `SendWithLimiter`/`SendpWithLimiter` |
| `SendRaw(proto, data, dst)` | One-shot raw socket send |
| `RecvRaw(proto, timeout)` | One-shot raw socket receive |

#### Match API

```go
type MatchFunc func(sent, received *packet.Packet) bool

// DefaultMatch returns a MatchFunc with protocol-specific heuristics:
//   ICMP: Echo Reply with matching id, or error types from the target IP
//   TCP:  swapped ports, SYN→SYN-ACK with ack==seq+1
//   UDP:  swapped ports
//   DNS:  matching transaction ID
//   ARP:  is-at reply with swapped IPs
//   DHCP: matching xid, BOOTREPLY
func DefaultMatch(sent *packet.Packet) MatchFunc
```

### 5.5 Sniff API (package `sniff`)

```go
type SniffConfig struct {
    Iface        string
    Filter       string                    // BPF expression (e.g. "tcp port 80")
    Instructions []sendrecv.BPFInstruction // Pre-compiled BPF
    Count        int                       // Max packets (0=unlimited)
    Timeout      time.Duration             // Total duration (0=no timeout)
}

type SniffHandler func(pkt *packet.Packet) bool

func Sniff(cfg SniffConfig, handler SniffHandler) error
func SniffChan(cfg SniffConfig) (<-chan *packet.Packet, func())
func CompileFilter(filter string) ([]sendrecv.BPFInstruction, error)
func CompileFilterOnIface(filter, iface string) ([]sendrecv.BPFInstruction, error)
```

### 5.6 Pcap API (package `pcap`)

```go
// Reading
func NewReader(r io.Reader) (*Reader, error)
func (rd *Reader) ReadPacket() (*PacketRecord, error)
func (rd *Reader) Packets(errp *error) <-chan *PacketRecord
func (rd *Reader) LinkType() uint32
func (r *PacketRecord) Packet() (*packet.Packet, error)

// Writing
func NewWriter(w io.Writer, linkType uint32, snapLen uint32) (*Writer, error)
func (wr *Writer) WritePacket(data []byte, ts time.Time) error
func (wr *Writer) WriteRecord(rec *PacketRecord) error
func (wr *Writer) WritePkt(pkt *packet.Packet) error
```

Link types: `LinkTypeNull` (0), `LinkTypeEthernet` (1), `LinkTypeRaw` (101), `LinkTypeIPv4` (228), `LinkTypeIPv6` (229).

Supports both pcap (magic-based byte order + nano/micro precision detection) and pcapng (SHB/IDB/EPB/SPB blocks, multiple interfaces, auto-detection).

### 5.7 Reassembly API (package `reassembly`)

```go
type Reassembler struct { ... }

func New(opts ...Option) *Reassembler
func WithTimeout(d time.Duration) Option
func WithMaxGroups(n int) Option
func (r *Reassembler) Submit(pkt *packet.Packet) *packet.Packet
func (r *Reassembler) Stats() int
func (r *Reassembler) Close()
```

`Submit` returns nil when waiting for more fragments, or the reassembled packet when a group is complete. Non-fragmented packets pass through unchanged.

### 5.8 Layer Definitions (package `layers`)

All protocol layer constructors return `*packet.Layer`:

| Constructor | Protocol | Fields |
|-------------|----------|--------|
| `NewEthernet()` | Ethernet | dst(MAC), src(MAC), type(uint16) |
| `NewARP()` | ARP | hwtype, ptype, hwlen, plen, op, hwsrc, psrc, hwdst, pdst |
| `NewIP()` | IPv4 | verihl, tos, len, id, frag, ttl, proto, chksum, src, dst |
| `NewIPv6()` | IPv6 | ver_tc_fl, plen, nh, hlim, src, dst |
| `NewICMP()` | ICMP | type, code, chksum, id, seq |
| `NewTCP()` | TCP | sport, dport, seq, ack, dataofs, flags, window, chksum, urgptr, options |
| `NewUDP()` | UDP | sport, dport, len, chksum |
| `NewICMPv6()` | ICMPv6 | type, code, chksum, body |
| `NewRaw()` | Raw | load |

Plus extension headers (`NewIPv6HopByHop`, `NewIPv6Routing`, `NewIPv6Fragment`, `NewIPv6DestOpts`), NDP messages (5 types), and sub-protocols (DNS, DHCP, Dot1Q, VXLAN, GRE, LLDP, ERSPAN, OSPF, BGP, QUIC) — each in their own sub-package under `layers/`.

### 5.9 Field Constructors (package `fields`)

19 field constructors: `NewByteField`, `NewXByteField`, `NewShortField`, `NewLEShortField`, `NewThreeBytesField`, `NewIntField`, `NewSignedIntField`, `NewLEIntField`, `NewLongField`, `NewLELongField`, `NewBitField`, `NewMACField`, `NewIPField`, `NewIPv6Field`, `NewStrField`, `NewStrLenField`, `NewStrFixedField`, `NewPacketField`, `NewConditionalField`.

### 5.10 TLV Utilities (package `fields`)

```go
func ParseTLV(data []byte) ([]TLVOption, error)
func BuildTLV(opts []TLVOption) []byte
func (o *TLVOption) Nested() ([]TLVOption, error)
func GetTLV(opts []TLVOption, typ uint8) *TLVOption
func GetAllTLV(opts []TLVOption, typ uint8) []TLVOption
```

---

## 6. Supported Protocols

| Layer | Protocols | Build | Dissect |
|-------|-----------|:-----:|:-------:|
| Link | Ethernet | Y | Y |
| Link | 802.1Q VLAN (Dot1Q) | Y | Y |
| Link | ARP | Y | Y |
| Link | LLDP | Y | Y |
| Network | IPv4 | Y | Y |
| Network | IPv6 | Y | Y |
| Network | IPv6 Hop-by-Hop Options | Y | Y |
| Network | IPv6 Routing Header | Y | Y |
| Network | IPv6 Fragment Header | Y | Y |
| Network | IPv6 Destination Options | Y | Y |
| Network | ICMP | Y | Y |
| Network | ICMPv6 | Y | Y |
| Network | ICMPv6 Echo | Y | Y |
| Network | NDP (RS/RA/NS/NA/Redirect) | Y | Y |
| Network | GRE | Y | Y |
| Network | VXLAN | Y | Y |
| Network | ERSPAN v3 | Y | Y |
| Network | OSPFv2 | Y | Y |
| Transport | TCP (with options) | Y | Y |
| Transport | UDP | Y | Y |
| Transport | QUIC Long Header | Y | Y |
| Application | DNS | Y | Y |
| Application | DHCP/BOOTP | Y | Y |
| Application | BGP | Y | Y |
| Payload | Raw | Y | Y |

---

## 7. Configuration

goscapy has minimal configuration — no config files or environment variables. All configuration is programmatic:

| Parameter | Type | Default | Where |
|-----------|------|---------|-------|
| `SniffConfig.Iface` | `string` | **(required)** | `sniff.Sniff()` |
| `SniffConfig.Filter` | `string` | `""` (no filter) | `sniff.Sniff()` |
| `SniffConfig.Instructions` | `[]BPFInstruction` | `nil` | `sniff.Sniff()` |
| `SniffConfig.Count` | `int` | `0` (unlimited) | `sniff.Sniff()` |
| `SniffConfig.Timeout` | `time.Duration` | `0` (no timeout) | `sniff.Sniff()` |
| `Reassembler.timeout` | `time.Duration` | `30s` | `reassembly.WithTimeout()` |
| `Reassembler.maxGroups` | `int` | `1024` | `reassembly.WithMaxGroups()` |
| `TokenBucketLimiter.pps` | `int` | **(required)** | `NewTokenBucketLimiter()` |
| `TokenBucketLimiter.burst` | `int` | `max(1, min(pps/10, 100))` | `NewTokenBucketLimiter()` |
| `pcap.Writer.snapLen` | `uint32` | `65535` (if 0) | `pcap.NewWriter()` |
| BPF buffer size (Darwin) | `uint32` | `32768` (32 KB) | hardcoded in `openBPFDevice()` |
| Max tunnel depth | `int` | `8` | hardcoded in `dissect()` |
| Max reassembly size | `int` | `65535` | hardcoded in `reassembly` |

### External Dependencies

| Service/Tool | Purpose | Failure Impact |
|-------------|---------|----------------|
| `tcpdump` | BPF filter string compilation (`sniff.CompileFilter`) | Optional; pre-compiled BPF instructions can be passed directly |
| `golang.org/x/sys` | Unix syscall wrappers (`unix.Poll`, `unix.IPV6_HDRINCL`) | Required for Linux platform |
| Root/Admin privileges | Raw socket operations | Required for all send/recv/sniff operations |
| `/dev/bpf*` (macOS) | BPF device for L2 packet capture/send | Required on macOS for L2 operations |
| Network interface | Target for send/recv | Required for all I/O |

---

## 8. Platform Support

| Feature | macOS (Darwin) | Linux |
|---------|:---:|:---:|
| L3 Send (IPv4) | AF_INET + IP_HDRINCL | AF_INET + IP_HDRINCL |
| L3 Send (IPv6) | AF_INET6 + IPV6_UNICAST_HOPS (no HDRINCL) | AF_INET6 + IPV6_HDRINCL |
| L2 Send | BPF write to /dev/bpf* | AF_PACKET sendto |
| Receive | BPF read from /dev/bpf* (select, immediate mode) | AF_PACKET recvfrom (poll) |
| BPF Filter | BIOCSETF ioctl | SO_ATTACH_FILTER setsockopt |
| Promiscuous Mode | BIOCPROMISC ioctl | Not explicitly set |
| Loopback Name | `lo0` | `lo` |
| MSG_ZEROCOPY | Not supported | Supported |
| Batch sendmmsg/recvmmsg | Not supported | Supported |
| io_uring | Not supported | Supported |
| TPACKET_V3 MMAP | Not supported | Supported |
| AF_PACKET Fanout | Not supported | Supported |
| AF_XDP XSK | Not supported | Supported |

---

## 9. Registration / Extension System

The library is extensible via a registration pattern. All registrations happen in `init()` functions.

### 9.1 Build Hook Registration

```go
packet.RegisterBuildHook(proto string, hook BuildHook)
```

Build hooks compute derived fields (checksums, lengths) during `Packet.Build()`. Currently registered: `IP`, `IPv6`, `ICMPv6`, `ICMP`, `TCP`, `UDP`.

### 9.2 Layer Registration (for Dissect)

```go
packet.RegisterLayer(proto string, factory LayerFactory)           // factory creates empty layer
packet.RegisterKeyField(proto, fieldName string)                   // which field identifies upper layer
packet.RegisterNextLayer(proto string, keyValue uint64, nextProto) // field value → next protocol
packet.RegisterHeuristic(lowerProto, field string, value any, nextProto) // convenience combo
packet.RegisterHeaderSizeFunc(proto string, fn HeaderSizeFunc)     // variable header size (IP, TCP, ext hdrs)
packet.RegisterPostParseHook(proto string, hook PostParseHook)     // parse extra header bytes (TCP options)
packet.RegisterDissector(proto string, fn DissectorFunc)           // identify protocol from raw bytes
packet.RegisterTunnelPayload(proto, innerProto string)             // tunnel → recursive dissection
```

### 9.3 Binding Registration

```go
packet.RegisterBinding(upper, lower, field string, value any)
```

When `upper` is stacked on `lower`, `lower.field` is automatically set to `value`. Example: `RegisterBinding("IP", "Ethernet", "type", 0x0800)`.

---

## 10. Build/Dissect Protocol Chain

### 10.1 Registered Next-Layer Mappings

**Ethernet.type → upper:**
- `0x0800` → IP
- `0x0806` → ARP
- `0x8035` → RARP
- `0x86DD` → IPv6
- `0x8100` → Dot1Q
- `0x88A8` → Dot1Q (QinQ)
- `0x88CC` → LLDP

**IP.proto → upper:**
- `1` → ICMP
- `6` → TCP
- `17` → UDP
- `47` → GRE
- `89` → OSPF

**IPv6.nh → upper:**
- `0` → IPv6 Hop-by-Hop
- `6` → TCP
- `17` → UDP
- `43` → IPv6 Routing
- `44` → IPv6 Fragment
- `58` → ICMPv6
- `60` → IPv6 DestOpts

**ICMPv6.type → sub-layer:**
- `128` → ICMPv6 Echo
- `129` → ICMPv6 Echo Reply
- `133` → NDP Router Solicitation
- `134` → NDP Router Advertisement
- `135` → NDP Neighbor Solicitation
- `136` → NDP Neighbor Advertisement
- `137` → NDP Redirect

**Port-based heuristics:**
- UDP:53 → DNS
- UDP:67/68 → DHCP
- UDP:443 → QUIC
- UDP:4789 → VXLAN
- TCP:179 → BGP

**Tunnel payloads:**
- VXLAN → Ethernet (recursive inner dissection)

---

## 11. Business Rules & Constraints

1. **Checksums are auto-computed.** Setting a checksum field explicitly is overwritten during `Build()` — the build hook zeroes it, computes over header+payload, and re-serializes. For UDP, a computed zero checksum is replaced with 0xFFFF (RFC 768).

2. **Layer bindings are auto-applied.** Stacking IP on Ethernet automatically sets EtherType=0x0800. `Sync()` re-applies all bindings. Users can override after stacking by calling `Set()`.

3. **IPv4 total length, UDP length, IPv6 payload length** are computed from upper-layer bytes during Build.

4. **TCP dataofs** is computed from the serialized options length during Build.

5. **Darwin IPv4 raw sockets** require `ip_len` and `ip_off` in host byte order (byteswapped on little-endian). The Darwin send implementation handles this automatically.

6. **Darwin IPv6 raw sockets** do not support IPV6_HDRINCL. The kernel fills the IPv6 header; only the payload is sent. Hop limit is set via IPV6_UNICAST_HOPS.

7. **Linux IPv6 raw sockets** support IPV6_HDRINCL — the full IPv6 header + payload is sent.

8. **BPF on macOS** uses `/dev/bpf*` devices (tries 0-255). BIOCIMMEDIATE is set so reads return immediately. BPF returns batches of `[bpf_hdr + data]`; the receiver parses all packets in a batch and queues extras.

9. **Fragment reassembly** uses a coverage bitmap to detect gaps. Groups expire after a configurable timeout (default 30s). Max concurrent groups is configurable (default 1024). Groups exceeding 65535 total bytes are dropped as DoS protection.

10. **Dissect wraps leftover bytes as Raw layer.** If a next-layer protocol can't be resolved, remaining bytes become a Raw payload layer automatically.

11. **Tunnel dissection is recursive** up to 8 levels deep to prevent stack overflow on malformed packets.

12. **ConditionalField** only serializes/deserializes when its condition function returns true based on current field values. Used for GRE optional fields (key, seq, checksum).

13. **TCP options** are parsed in the PostParseHook (after fixed fields + header size). During build, options are serialized by a custom field type.

14. **Rate limiter** uses a spin-loop for waits under 500μs (burning CPU for precision) and a timer for longer waits.

---

## 12. Non-Functional Characteristics

### 12.1 Performance

- **Zero-allocation recv path:** `RecvInto` allows caller-provided buffers, avoiding per-packet allocations for the first packet in a BPF batch.
- **Batch parsing:** BPF receiver on Darwin parses all packets in a single `read()` into a queue, amortizing syscall cost.
- **Coverage bitmap** for fragment reassembly uses `[]bool` for O(1) gap detection per byte.
- **Rate limiter spin-loop** under 500μs avoids timer syscall overhead for high-rate sends.
- **MSG_ZEROCOPY** (Linux) avoids kernel→userspace copies on send.
- **sendmmsg/recvmmsg** (Linux) batch multiple messages per syscall.
- **TPACKET_V3** (Linux) uses mmap'd ring buffer for zero-copy receive.
- **AF_XDP** (Linux) provides zero-copy or copy-mode packet I/O via XSK.
- Peak reassembled size is capped at 65535 bytes. Pcap capture length capped at 0x100000 (1MB).

### 12.2 Security

- **Root privileges required** for all raw socket operations — stated in README.
- **DoS protection in reassembly:** max 1024 concurrent fragment groups, max 65535 bytes per group. Exceeding either silently drops the fragment.
- **Max tunnel depth of 8** prevents stack overflow from maliciously nested tunnel headers.
- **Input validation** on all field types — type assertions with clear error messages for wrong Go types.
- **Suspicious pcap capture length** check: values > 0x100000 are rejected.
- No secrets management — the library doesn't handle credentials or authentication.

### 12.3 Error Handling

- All public functions return `error`. Errors use `fmt.Errorf` with `%w` wrapping for `errors.Is` support.
- `ErrTimeout` sentinel allows callers to distinguish timeouts from fatal errors via `errors.Is(err, sendrecv.ErrTimeout)`.
- BPF batch parsing silently skips malformed packets (logs nothing) and continues to the next one.
- Dissect errors include the layer name and field name in the error message chain.
- Build hook errors wrap the protocol name. Mismatched byte counts from hooks are caught and reported.

### 12.4 Thread Safety

- `Reassembler` uses a `sync.Mutex` for all group operations. Background GC goroutine runs periodically and is stopped via channel close.
- `TokenBucketLimiter` uses a `sync.Mutex` for token state.
- `SniffChan` uses `sync.OnceFunc` for idempotent stop.
- `RawConn` zero-copy state protected by `sync.Mutex`.

---

## 13. Testing Strategy

| Type | Framework | Coverage Pattern |
|------|-----------|-----------------|
| Unit | `go test` (standard) | Each package has `*_test.go` files. 40 test files, ~12K lines of test code across ~75K total lines (~16% test ratio). |
| Integration | `go test` | Platform-specific tests exist for sendrecv (Darwin/Linux), sniff (loopback tests), batch, zerocopy, mmap, uring. Sub-packages (DNS, DHCP, Dot1Q, VXLAN, GRE, LLDP, ERSPAN, OSPF, BGP, QUIC) each have their own tests. |
| Race | `make test-race` | Explicit Makefile target using `-race` flag. |
| Coverage | `make test-cover` | Generates `coverage.out` and optional HTML report. |
| Benchmarks | `make bench` | `-bench=. -benchmem` across all packages. |
| Lint | `make lint` | golangci-lint. |
| Build-only | `make vet` | `go vet ./...`. |

---

## 14. Examples Overview

40 example programs demonstrate every feature:

| # | Example | What It Demonstrates |
|---|---------|---------------------|
| 01 | ethernet-ip | Building Eth+IP packets |
| 02 | tcp-udp | TCP/UDP packet construction |
| 03 | icmp-ping | ICMP Echo Request construction |
| 04 | arp | ARP request/reply building |
| 05 | ipv6 | IPv6 packet construction |
| 06 | dns | DNS query building |
| 07 | dhcp | DHCP discover/request building |
| 08 | vlan | 802.1Q VLAN tagging |
| 09 | gre-vxlan | GRE and VXLAN tunneling |
| 10 | dissect | Packet dissection from raw bytes |
| 11 | send | L3 send over raw socket |
| 12 | sendrecv | Send and receive response |
| 13 | tcp-syn-scan | TCP SYN port scanner |
| 14 | sniff | Live packet capture |
| 15 | bpf-filter | BPF filter compilation and use |
| 16 | shortcuts | All one-liner shortcut functions |
| 17 | ping | ICMP ping with Sr1 matching |
| 18 | traceroute | UDP traceroute implementation |
| 19 | raw-socket | RawConn send/receive |
| 20 | batch-raw-socket | BatchConn batch operations |
| 21 | zerocopy | MSG_ZEROCOPY send |
| 22 | uring-raw-socket | io_uring raw socket I/O |
| 23 | packet-mmap | TPACKET_V3 ring buffer |
| 24 | dns-client | DNS client using sendrecv |
| 25 | ntp-client | NTP client using sendrecv |
| 26 | dhcp-client | DHCP client using sendrecv |
| 27 | arp-scanner | ARP network scanner |
| 31 | port-scanner | TCP port scanner |
| 32 | fishfinder | Network device discovery |
| 33 | ipv6-ping | IPv6 ping |
| 34 | fanout | AF_PACKET Fanout multi-core |
| 35 | xdp | AF_XDP zero-copy I/O |
| 36 | ratelimit | Token bucket rate limiting |
| 37 | tcp-options | TCP options construction/parsing |
| 38 | pcap-rw | Pcap file read/write |
| 39 | reassembly | IP fragment reassembly |
| 40 | recvinto | Zero-allocation receive |

---

## 15. Build & Development

### 15.1 Local Setup

```bash
git clone https://github.com/smallnest/goscapy
cd goscapy
go mod download
make build    # go build ./...
make test     # go test ./...
make check    # fmt + vet + lint + test
```

### 15.2 Key Make Targets

| Target | Command |
|--------|---------|
| `build` | `go build ./...` |
| `test` | `go test ./...` |
| `test-race` | `go test -race ./...` |
| `test-cover` | `go test -coverprofile=coverage.out ./...` |
| `bench` | `go test -bench=. -benchmem ./...` |
| `lint` | `golangci-lint run ./...` |
| `fmt` | `gofmt -s -w . && goimports -w .` |
| `vet` | `go vet ./...` |
| `check` | `fmt vet lint test` |

---

## 16. Known Gaps & Assumptions

- **No IPv6 fragment reassembly.** The reassembly package only handles IPv4 fragments.
- **No TCP stream reassembly.** Only IP-layer fragment reassembly is implemented.
- **No ICMPv6 checksum for extension headers.** The ICMPv6 checksum is computed over the message body only; extension header pseudo-header logic is not implemented.
- **Limited NDP option parsing.** NDP messages expose raw TLV options rather than fully typed option structs.
- **No runtime configuration files.** All behavior is controlled programmatically; there is no YAML/JSON/TOML configuration.
- **No structured logging.** The library uses only `fmt.Errorf` — no log levels, no structured output.
- **Darwin BPF is the only macOS receiver.** There is no AF_PACKET equivalent on macOS; all L2 receive goes through BPF.
- **tcpdump is optional but recommended** for BPF filter compilation. Pre-compiled instructions work without it.
- **No HTTP/gRPC server.** This is a pure library — no network services to deploy.
- **Testing coverage is uneven.** The core packet/layers/fields packages have thorough unit tests. Some advanced features (zerocopy, uring, xdp) have minimal test coverage due to hardware/kernel requirements.
- **No fuzz testing infrastructure** is present in the codebase.
- **The docs/ directory contains a static website** (HTML/CSS/JS with English/Chinese versions), not API documentation. API docs are on pkg.go.dev.
- **tasks/ directory contains PRD documents** for feature planning, not implementation artifacts.

---

## 17. Appendix

### A. Dependency Graph (Internal)

```
goscapy (builders, shortcuts)
  ├── packet (Packet, Layer, Build, Dissect, Binding)
  │     └── fields (Field interface, types, TLV)
  ├── layers (protocol definitions, checksums, helpers)
  │     ├── packet, fields
  │     └── sub-packages: dns, dhcp, dot1q, vxlan, gre, lldp, erspan, ospf, bgp, quic
  ├── sendrecv (raw socket I/O)
  │     ├── packet
  │     └── golang.org/x/sys (Linux only)
  ├── sniff (capture)
  │     ├── sendrecv
  │     └── packet
  ├── pcap (file I/O)
  │     └── packet
  └── reassembly (fragment reassembly)
        ├── packet
        └── layers
```

### B. Git History Summary

- First commit: appears to be around 2025 (not visible in tail)
- Active development with ~30 visible commits
- Recent feature additions (most recent first): AF_XDP, AF_PACKET Fanout, IP fragment reassembly, IPv6 send, pcap reader/writer, token bucket rate limiter, TCP options, RecvInto
- Single contributor: `chaoyuepan`
- Repository: `github.com/smallnest/goscapy`

### C. Protocol Number Constants

**EtherType:** `EtherTypeIPv4` (0x0800), `EtherTypeARP` (0x0806), `EtherTypeRARP` (0x8035), `EtherTypeIPv6` (0x86DD)

**IP Protocol:** `IPProtoICMP` (1), `IPProtoTCP` (6), `IPProtoUDP` (17)

**ARP Operations:** `ARPWhoHas` (1), `ARPIsAt` (2), `RARPWhoIs` (3), `RARPIsAt` (4)

**TCP Flags:** `TCPSyn` (0x02), `TCPAck` (0x10), `TCPFin` (0x01), `TCPRst` (0x04), `TCPPsh` (0x08), `TCPUrg` (0x20), `TCPEce` (0x40), `TCPCwr` (0x80)

**ICMP Types:** `ICMPEchoReply` (0), `ICMPDestUnreach` (3), `ICMPEchoRequest` (8), `ICMPTimeExceed` (11)

**IPv6 Next Headers:** Extension: 0 (Hop-by-Hop), 43 (Routing), 44 (Fragment), 60 (DestOpts); Upper: 6 (TCP), 17 (UDP), 58 (ICMPv6), 59 (No Next Header)

**ICMPv6 Types:** 128 (Echo Request), 129 (Echo Reply), 133-137 (NDP)

### D. Word Count / Code Metrics

- ~75,000 lines of Go source code across all packages
- ~12,000 lines of test code in 40 test files (~16% test ratio)
- 8 public packages
- 40 example programs
- 25+ supported protocols/sub-protocols
- 19 field types
- 19 shortcut functions
- 18 builder types