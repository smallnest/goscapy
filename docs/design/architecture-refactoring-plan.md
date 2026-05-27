# Architecture Refactoring Plan — goscapy pkg/

## Context

The smell report identified 3 critical, 6 warning, and 2 suggestion-level issues in `pkg/`. This plan addresses all critical and warning issues, plus the naming inconsistency suggestion. The changes are non-breaking (all existing APIs preserved as thin wrappers) and focused on structural improvements only.

## Changes

### 1. sendrecv: Extract `collectResponses` + Config-Driven API (Critical #2, Warnings #4, #5)

**File:** `pkg/sendrecv/sendrecv.go`

- Extract a private `collectResponses(rx Receiver, deadline time.Time, match MatchFunc) []*packet.Packet` helper used by all variants (eliminates 4× code duplication)
- Extract a private `collectFirstResponse(rx Receiver, deadline time.Time, match MatchFunc) (*packet.Packet, bool)` helper
- Add `SendRecvConfig` struct and a single `SendRecvWithConfig(pkt *packet.Packet, cfg SendRecvConfig) (*packet.Packet, []*packet.Packet, error)` function
- Respin all 8 existing public functions as thin wrappers around the config-driven one (preserves backward compatibility)
- Note: `Sr`, `Sr1`, `Srp`, `Srp1` take MatchFunc parameter instead of Filter; `SendRecv`, `SendRecv1`, `SendRecvFiltered`, `SendRecvFiltered1` use BPF filter. These are different axes and must remain separate entry points for API compatibility.

### 2. sendrecv: Split match.go from sendrecv.go (Warning #6)

**New file:** `pkg/sendrecv/match.go`
**File:** `pkg/sendrecv/sendrecv.go`

- Move `MatchFunc`, `DefaultMatch`, protocol constants (icmp*, arp*, boot*), and DefaultMatch's internal logic to `match.go`
- sendrecv.go retains only: `Receiver` interface, `OpenReceiver`, `OpenFilteredReceiver`, `Send`, `Sendp`, `Recv`, all SendRecv variants, Sr/Srp variants, config struct, and helpers
- Both files remain in `package sendrecv` — zero import changes

### 3. goscapy: Split builder catalog into per-group files (Warning #1)

**Files to create (all in `pkg/goscapy/`):**

| New File | Builders |
|----------|----------|
| `builder_core.go` | PacketBuilder, LayerBuilder (retained in main file) |
| `builder_l2.go` | EthernetBuilder, Dot1QBuilder |
| `builder_l3.go` | IPBuilder, IPv6Builder, ICMPBuilder, ICMPv6Builder, ARPBuilder |
| `builder_l4.go` | TCPBuilder, UDPBuilder |
| `builder_tunnel.go` | GREBuilder, VXLANBuilder, ERSPANBuilder |
| `builder_app.go` | DNSBuilder, DHCPBuilder, HTTPBuilder, NTPBuilder, TLSBuilder |
| `builder_routing.go` | OSPFBuilder, BGPBuilder, LLDPBuilder |
| `builder_wireless.go` | Dot11Builder, RadioTapBuilder, HCIBuilder, L2CAPBuilder, ATTBuilder |
| `builder_advanced.go` | QUICBuilder, NetflowV5Builder, NetflowV9Builder, IPFIXBuilder, RTPBuilder, RTCPBuilder, SIPBuilder |

**File to reduce:** `pkg/goscapy/goscapy.go` → keep only `PacketBuilder`, `LayerBuilder` interface, `EthernetBuilder` (most commonly used, as anchor)

All files in `package goscapy` — no import changes needed. Types/methods are file-local to the package, not importable individually.

### 4. Naming: Rename inconsistent builder constructors (Suggestion #1)

**File:** `pkg/goscapy/goscapy.go` (and corresponding new files)

| Old Name | New Name |
|----------|----------|
| `NewLLDPLayer()` | `NewLLDP()` |
| `NewERSPANLayer()` | `NewERSPAN()` |
| `NewOSPFLayer()` | `NewOSPF()` |
| `NewBGPLayer()` | `NewBGP()` |
| `NewQUICLayer()` | `NewQUIC()` |

**Also update callers:**
- `pkg/goscapy/shortcuts.go` — 3 call sites (NewOSPFLayer, NewBGPLayer, NewQUICLayer)
- `pkg/goscapy/goscapy_test.go` — check for any references

### 5. sendrecv_darwin.go: Remove commented-out ioctl constants (Warning #3)

**File:** `pkg/sendrecv/sendrecv_darwin.go` lines 18-22

Remove the 5-line comment block that shows ioctl derivation. The resolved constants are already defined as named constants on the following lines.

### 6. Documentation: Add init-time-only contracts to global registries (Critical #3)

**Files:**
- `pkg/packet/build.go` — add comment on `buildHooks` and `RegisterBuildHook` documenting "must be called during init only; not safe for concurrent use after program startup"
- `pkg/packet/binding.go` — add comment on `bindingRules` and `RegisterBinding` with same contract
- `pkg/packet/dissect.go` — add comment on `dissectRegistry` documenting init-only write contract

No code changes — documentation only.

## Verification

1. `cd /Users/chaoyuepan/ai/goscapy && go build ./pkg/...` — must compile cleanly
2. `go test ./pkg/...` — all tests must pass
3. `go vet ./pkg/...` — no warnings
4. Specifically verify builder renaming doesn't break shortcuts.go compilation
5. Verify goscapy_test.go compiles after file split (types remain in same package)

## Files Modified Summary

| File | Change Type |
|------|-------------|
| `pkg/sendrecv/sendrecv.go` | Refactor — extract helpers, add config struct, thin wrappers |
| `pkg/sendrecv/match.go` | **New** — extract match logic |
| `pkg/sendrecv/sendrecv_darwin.go` | Delete 5 comment lines |
| `pkg/goscapy/goscapy.go` | Reduce to core + EthernetBuilder only |
| `pkg/goscapy/builder_l2.go` | **New** |
| `pkg/goscapy/builder_l3.go` | **New** |
| `pkg/goscapy/builder_l4.go` | **New** |
| `pkg/goscapy/builder_tunnel.go` | **New** |
| `pkg/goscapy/builder_app.go` | **New** |
| `pkg/goscapy/builder_routing.go` | **New** |
| `pkg/goscapy/builder_wireless.go` | **New** |
| `pkg/goscapy/builder_advanced.go` | **New** |
| `pkg/goscapy/shortcuts.go` | Rename 3 builder calls |
| `pkg/packet/build.go` | Add documentation comment |
| `pkg/packet/binding.go` | Add documentation comment |
| `pkg/packet/dissect.go` | Add documentation comment |