# PRD: LLDP, ERSPAN, OSPF, BGP, QUIC Protocol Support

## Introduction

Add wire-level protocol support for 5 community-contributed protocols — LLDP, ERSPAN v3, OSPF, BGP, and QUIC — to the goscapy library. LLDP/ERSPAN/OSPF/BGP come from scapy/contrib; QUIC comes from scapy/layers. Implementation is packet-level only (parse/serialize header fields and message subtypes), without state machines or session logic.

## Goals

- Provide parse/serialize support for LLDP (basic TLVs), ERSPAN v3, OSPF (5 message types), BGP (4 message types), and QUIC (initial/crypto handshake and short header packets)
- Follow existing goscapy conventions (field system, layer registry, Builder API, shortcut functions)
- Achieve Scapy-level wire-format compatibility for each protocol
- **Reference implementation**: Use official Scapy contrib & layers source as the canonical spec for field layouts, byte offsets, default values, and TLV encodings:
  - [LLDP](https://github.com/secdev/scapy/blob/master/scapy/contrib/lldp.py)
  - [ERSPAN](https://github.com/secdev/scapy/blob/master/scapy/contrib/erspan.py)
  - [OSPF](https://github.com/secdev/scapy/blob/master/scapy/contrib/ospf.py)
  - [BGP](https://github.com/secdev/scapy/blob/master/scapy/contrib/bgp.py)
  - [QUIC](https://github.com/secdev/scapy/blob/master/scapy/layers/quic.py)
  - [Full contrib directory](https://github.com/secdev/scapy/tree/master/scapy/contrib)
- Maintain full backward compatibility — no regressions in existing test suite

## User Stories

### US-001: LLDP Basic TLV Layer
**Description:** As a network engineer, I want to construct and parse LLDP (IEEE 802.1AB) frames with basic mandatory TLVs so I can discover directly connected neighbors.

**Acceptance Criteria:**
- [ ] LLDP layer: Chassis ID TLV (type 1), Port ID TLV (type 2), TTL TLV (type 3), End TLV (type 0)
- [ ] Each TLV is a TLV-encoded field (type/len/value) serialized in order
- [ ] `NewLLDPLayer()` constructor returns a `*packet.Layer`
- [ ] `NewLLDP()` builder with chainable setters: `ChassisID()`, `PortID()`, `TTL()`
- [ ] `LLDPBuilder` implements `LayerBuilder` with `Over()` method
- [ ] Register to layer registry, key field "type", next-layer mapping
- [ ] Tests: defaults, setter/getter, serialize, parse, round-trip, builder
- [ ] `go vet ./...` clean

### US-002: ERSPAN v3 Tunnel Layer
**Description:** As a network engineer, I want to construct and parse ERSPAN v3 (GRE protocol 0x88BE) encapsulated mirrored packets so I can work with Cisco SPAN traffic.

**Acceptance Criteria:**
- [ ] ERSPAN v3 layer: header(ver/pri/gra/VLAN/business), timestamp(2-bit), Frame Dir + Sequence(optional), SGT + VRFID(optional)
- [ ] Use GRE layer as base (ERSPAN is GRE with proto=0x88BE + sequence)
- [ ] `NewERSPANBuilder()` with setters: `Version()`, `SessionID()`, `Timestamp()`, `Direction()`, `HardwareID()`
- [ ] Serialize produces valid ERSPAN v3 wire format; parse reconstructs all fields
- [ ] Register as heuristic on GRE (proto 0x88BE)
- [ ] Tests: ERSPAN-only serialize/parse, GRE/ERSPAN stack, shortcut Ethernet/IP/GRE/ERSPAN/Inner
- [ ] `go vet ./...` clean

### US-003: OSPF Message Layer
**Description:** As a network engineer, I want to construct and parse OSPF (RFC 2328) Hello/DBD/LSR/LSU/LSAck messages so I can analyze and build OSPF routing traffic.

**Acceptance Criteria:**
- [ ] OSPF common header: version(1), type(1), len(2), router_id(4), area_id(4), chksum(2), auth_type(2), auth_data(8)
- [ ] Hello: mask(4), hello_interval(2), options(1), priority(1), dead_interval(4), dr(4), bdr(4), neighbors([]4B)
- [ ] DBD: mtu(2), options(1), flags(1), seq(4), LSA headers([]20B)
- [ ] LSR: LS type(4), LS ID(4), Adv Router(4)
- [ ] LSU: count(4), LSAs([]variable)
- [ ] LSAck: LSA headers([]20B)
- [ ] `LSAHeader` struct: age(2), options(1), type(1), lsid(4), adv_router(4), seq(4), chksum(2), len(2)
- [ ] `NewOSPF()` builder: `Type()`, `RouterID()`, `AreaID()`, `Auth()`, sub-type specific setters
- [ ] Register OSPF as IP protocol 89
- [ ] Tests: each message type serialize/parse/round-trip
- [ ] `go vet ./...` clean

### US-004: BGP Message Layer
**Description:** As a network engineer, I want to construct and parse BGP-4 (RFC 4271) Open/Update/Keepalive/Notification messages so I can analyze BGP routing traffic.

**Acceptance Criteria:**
- [ ] BGP common header: marker(16B), len(2), type(1)
- [ ] Open: version(1), ASN(2), hold_time(2), router_id(4), opt_len(1), options([]TLV)
- [ ] Update: withdrawn_len(2), withdrawn_routes, path_attr_len(2), path_attrs, NLRI
- [ ] Keepalive: empty body (header only)
- [ ] Notification: error_code(1), error_subcode(1), data(variable)
- [ ] Path attribute TLV encoding (flag/type/len/value)
- [ ] `NewBGP()` builder: `Type()`, `RouterID()`, `ASN()`, `HoldTime()`, sub-type specific setters
- [ ] Register BGP as TCP port 179 heuristic
- [ ] Tests: Open/Update/Keepalive/Notification serialize/parse/round-trip
- [ ] `go vet ./...` clean

### US-005: QUIC Packet Layer
**Description:** As a network engineer, I want to construct and parse QUIC (RFC 9000) long/short header packets so I can analyze QUIC traffic including initial and crypto handshakes.

**Acceptance Criteria:**
- [ ] Common header: 1-byte initial octet with header-form bit + fixed bit + type bits
- [ ] Long Header: version(4B), dcid_len(1B), DCID, scid_len(1B), SCID; variation for Initial(variable length + token), Handshake, Retry, 0-RTT
- [ ] Short Header: spin/reserved/key_phase bits, DCID(variable)
- [ ] Implement Initial packet: token_len(vlq), token, length(vlq), frames[]
- [ ] CRYPTO frame: offset(vlq), length(vlq), data
- [ ] `NewQUIC()` builder: `DCID()`, `SCID()`, `Version()`, `PacketType()`, `Token()`, `CRYPTOFrame()`
- [ ] Register QUIC as UDP port 443 heuristic (or VLAN/port based)
- [ ] Tests: Long header Initial, Short header, CRYPTO frame serialize/parse/round-trip
- [ ] `go vet ./...` clean

### US-006: Builder API & Shortcut Functions
**Description:** As a Go developer, I want fluent Builder API and convenience shortcut functions for all 5 new protocols so I can construct packets with one-liners.

**Acceptance Criteria:**
- [ ] `LLDPBuilder`, `ERSPANBuilder`, `OSPFBuilder`, `BGPBuilder`, `QUICBuilder` in `pkg/goscapy/goscapy.go`
- [ ] Each implements `LayerBuilder` interface with `Over()` method
- [ ] Shortcut functions: `EtherLLDP()`, `EtherIPGREERSPAN()`, `IPOSPF()`, `IPTCPBGP()`, `IPUDPQUIC()`
- [ ] All builders verify via `TestBuilderLayerBuilderInterface` assertion
- [ ] `go vet ./...` clean

### US-007: Dissector Integration & Integration Tests
**Description:** As a developer, I want all 5 protocols integrated into the dissector pipeline and end-to-end integration tests so the full stack works in real scenarios.

**Acceptance Criteria:**
- [ ] LLDP: register dissector (Ethernet type 0x88CC), register key field "type"
- [ ] ERSPAN: register GRE next-layer (proto 0x88BE), heuristic
- [ ] OSPF: register as IP proto 89, key field "type" for sub-types
- [ ] BGP: register as TCP port 179 heuristic
- [ ] QUIC: register as UDP port 443 heuristic (or initial DCID key field)
- [ ] Integration tests in `pkg/layers/dissect_test.go`: Ether/LLDP, IP/GRE/ERSPAN/Inner, IP/OSPF/Hello, IP/TCP/BGP/Open, IP/UDP/QUIC/Initial
- [ ] All existing tests continue to pass
- [ ] `go vet ./...` clean

## Functional Requirements

- FR-1: System must implement LLDP with 4 mandatory TLV types (Chassis ID=1, Port ID=2, TTL=3, End=0)
- FR-2: System must implement ERSPAN v3 header atop GRE (proto 0x88BE): ver/sub-ver(10b), BSO(2b), session_id(10b), timestamp(32b), SGT(16b), frame_type/port_index/hw_id fields
- FR-3: System must implement OSPF common header + 5 message types (Hello=1, DBD=2, LSR=3, LSU=4, LSAck=5) per RFC 2328 type codes
- FR-4: System must implement BGP common header + 4 message types (Open=1, Update=2, Keepalive=3, Notification=4) per RFC 4271
- FR-5: System must implement QUIC long header (Initial/Handshake/Retry/0-RTT) and short header per RFC 9000, with CRYPTO frame encoding
- FR-6: Each protocol must serialize/parse with field-level fidelity matching Scapy output
- FR-7: Each protocol must register into the layer registry with key-field and next-layer mappings
- FR-8: Each protocol must expose a Builder API and at least one shortcut function
- FR-9: All test suites must pass and `go vet ./...` must be clean

## Non-Goals (Out of Scope)

- **No state machines** — OSPF adjacency (Down/Init/2-way/ExStart/Exchange/Loading/Full) and BGP FSM are out of scope
- **No LSDB / RIB management** — no link-state database, no routing table computation
- **No complex TLV parsing** — LLDP optional TLVs (802.1/802.3/MED), BGP capability negotiation beyond basic encoding are out of scope
- **No ERSPAN v1/v2** — only v3
- **No reactive protocol behavior** — no packet-response logic, no keepalive timers, no retransmission
- **No QUIC connection migration** — connection ID rotation, NAT rebinding, path validation out of scope

## Technical Considerations

- **Reuse existing infrastructure**: `fields.TLVOption` for OSPF LSA headers, `fields.ConditionalField` for optional ERSPAN fields, `NewConditionalField` for flag-gated fields
- **GRE-based ERSPAN**: ERSPAN v3 reuses the existing GRE layer infrastructure. ERSPAN is parsed as a sub-layer atop GRE when proto=0x88BE.
- **Directory structure**: `pkg/layers/lldp/`, `pkg/layers/erspan/`, `pkg/layers/ospf/`, `pkg/layers/bgp/` — each with `layer.go`, `init.go`, `layer_test.go`
- **Integration tests** go in `pkg/layers/dissect_test.go` to avoid circular imports
- **Build hooks**: OSPF checksum auto-computation via `RegisterBuildHook`
- **BGP is TCP-based**: dissector resolves BGP via heuristic on TCP port 179, not IP protocol number

## Protocol-Specific Field Layouts

### LLDP (IEEE 802.1AB)
```
Chassis ID TLV:  type(7b=0)/len(9b=1-255) + subtype(1B) + chassisID(variable)
Port ID TLV:     type(7b=0)/len(9b=1-255) + subtype(1B) + portID(variable)
TTL TLV:         type(7b=0)/len(9b=2) + ttl(2B)
End TLV:         type(7b=0)/len(9b=0)
```
Total: dynamic, minimum 4 TLVs. Key field: not needed (end-of-dissect).

### ERSPAN v3 (over GRE, proto=0x88BE)
```
ver(4b) | sub_ver(4b) | vlan(2b) | pri(2b) | gra(2b)=0 | BSO(2b)=0 | session_id(10b)
timestamp(4B): 32-bit nanosecond fractional timestamp
platform_specific(optional): frame_type(6b)/port_index(20b)/hw_id(6b)
SGT(optional 2B): Security Group Tag
VRF_ID(optional variable)
```
Key field: not needed (uses tunnel payload or GRE key field). Total: 8 bytes (minimum base) + optional fields.

### OSPF (RFC 2328, IP proto 89)
```
Common Header (24B):
  version(1B)=2, type(1B), len(2B), router_id(4B), area_id(4B), chksum(2B), auth_type(2B), auth_data(8B)

Hello (20B body): mask(4B), hello_interval(2B), options(1B), priority(1B), dead_interval(4B), dr(4B), bdr(4B), neighbors[]
DBD (8B body): mtu(2B), options(1B), flags(1B), seq(4B), LSA_headers[]
LSR (4B per request): ls_type(4B), ls_id(4B), adv_router(4B)
LSU (4B body): count(4B), LSAs[]
LSAck: LSA_headers[]
```
Key field: "type" for sub-type resolution. OSPF type codes: 1-5.

### BGP-4 (RFC 4271)
```
Common Header (19B):
  marker(16B, all-ones), len(2B), type(1B)

Open (10B body): version(1B=4), asn(2B), hold_time(2B), router_id(4B), opt_len(1B), options[]
Update (4B body + variable): withdrawn_len(2B), withdrawn_routes[], path_attr_len(2B), path_attrs[], NLRI[]
Keepalive: empty body
Notification (2B body): error_code(1B), error_subcode(1B), data[]
```
Key field: "type" for sub-type resolution (1-4).

## File Creation Plan

```
pkg/layers/lldp/layer.go        — LLDP layer + builder + getters
pkg/layers/lldp/init.go         — registry (next: 0x88CC → LLDP on Ethernet heuristic)
pkg/layers/lldp/layer_test.go   — tests

pkg/layers/erspan/layer.go      — ERSPAN v3 layer + builder + getters
pkg/layers/erspan/init.go       — registry (GRE next-layer for 0x88BE)
pkg/layers/erspan/layer_test.go — tests

pkg/layers/ospf/layer.go        — OSPF header + 5 message types + LSAHeader + builder + getters
pkg/layers/ospf/init.go         — registry (IP proto 89, key field "type")
pkg/layers/ospf/layer_test.go   — tests

pkg/layers/bgp/layer.go         — BGP header + 4 message types + path attrs + builder + getters
pkg/layers/bgp/init.go          — registry (TCP port 179 heuristic, key field "type")
pkg/layers/bgp/layer_test.go    — tests

pkg/layers/quic/layer.go        — QUIC long/short header + CRYPTO frame + vlq encoding + builder + getters
pkg/layers/quic/init.go         — registry (UDP port 443 heuristic, key field "version")
pkg/layers/quic/layer_test.go   — tests

pkg/layers/init.go              — Add imports, heuristics, bindings, dissectors
pkg/layers/dissect_test.go      — Add integration tests
pkg/goscapy/goscapy.go          — Add 5 Builders
pkg/goscapy/shortcuts.go        — Add 5 shortcuts
pkg/goscapy/goscapy_test.go     — Add builder + shortcut tests
```

## Success Metrics

- 4 new protocol packages with parse/serialize/round-trip tests
- 100% test pass rate (`go test ./...`)
- `go vet ./...` zero issues
- Wire output verified against Scapy reference output

## Open Questions

- BGP Update NLRI encoding: should we implement AS_PATH, NEXT_HOP, LOCAL_PREF, etc. as typed path attributes, or treat path_attrs as raw TLV bytes initially? (Recommend: typed path attributes for core types, raw fallback)
- OSPF LSU LSA body: should we parse into typed LSAs (Router=1, Network=2, Summary=3/4, AS-External=5) or treat as raw byte overlay? (Recommend: typed LSA structs for core types)
- ERSPAN platform_specific: should this be conditional based on BSO field or always present in v3? (Per scapi: conditional on gra flag)