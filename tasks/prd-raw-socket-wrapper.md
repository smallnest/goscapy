# PRD: Raw Socket 发送/接收系统调用包装

## Introduction

当前 goscapy 的 `sendrecv` 包提供基于 BPF/AF_PACKET 的 L2/L3 收发能力，但在某些场景下（如 ICMP ping）BPF 无法可靠捕获回复包。用户需要直接使用 `syscall.Sendto` / `syscall.Recvfrom` 操作 raw socket，但原始 syscall 参数繁琐（fd 管理、地址构造、超时设置、跨平台差异）。

此外，Linux 提供了更高性能的系统调用（sendmmsg/recvmmsg 批量收发、MSG_ZEROCOPY 零拷贝、io_uring 异步 IO、PACKET_MMAP 环形缓冲区），Go 标准库未封装这些能力。本 PRD 在 `sendrecv` 包中提供统一、简洁的 API，覆盖从基础 raw socket 到高性能内核旁路的完整层次。

## Goals

- 用最少参数调用 raw socket 的 Sendto/Recvfrom（基础层）
- 封装 sendmmsg/recvmmsg 批量系统调用（批量层）
- 支持 MSG_ZEROCOPY 零拷贝发送（零拷贝层）
- 提供 io_uring 异步 IO 接口（异步层）
- 实现 PACKET_MMAP (TPACKET_V3) 环形缓冲区收包（高性能捕获层）
- 跨平台兼容 macOS + Linux（高性能特性仅 Linux）
- 解决 ping 示例的样板代码问题
- 每个功能实现后必须配备可运行的示例代码（examples/ 目录）
- 每个功能实现后必须更新中英文文档（docs/zh/ 和 docs/en/）

## User Stories

### US-001: RawConn — 封装 raw socket 连接（基础层）

**Description:** As a 开发者，我希望创建一个 raw socket 连接对象，之后只需调用该对象的 Send/Recv 方法，不再关心 fd、地址转换、超时等底层细节。

**Acceptance Criteria:**
- [ ] 可通过 `sendrecv.DialRaw(proto int) (*RawConn, error)` 创建连接（proto=1 为 ICMP，6 为 TCP，17 为 UDP）
- [ ] `RawConn.Send(data []byte, dst string) error` 发送数据，参数仅需数据和目标 IP 字符串
- [ ] `RawConn.Recv(timeout time.Duration) ([]byte, string, error)` 接收数据，返回原始数据和来源 IP
- [ ] `RawConn.Close() error` 关闭 socket
- [ ] 平台文件：`rawconn_darwin.go` 和 `rawconn_linux.go`
- [ ] 示例代码：`examples/18-raw-socket/main.go`，演示 Send/Recv 完整流程
- [ ] 文档更新：`docs/zh/` 和 `docs/en/` 添加 RawConn API 说明
- [ ] Typecheck/lint 通过

### US-002: SendRaw/RecvRaw — 单函数便捷 API

**Description:** As a 开发者，对于一次性操作，我想直接调用一个函数而无需创建连接对象。

**Acceptance Criteria:**
- [ ] `sendrecv.SendRaw(proto int, data []byte, dst string) error`
- [ ] `sendrecv.RecvRaw(proto int, timeout time.Duration) ([]byte, string, error)`
- [ ] 基于 `RawConn` 实现
- [ ] 示例：在 `examples/18-raw-socket/main.go` 中演示便捷函数用法
- [ ] 文档更新：`docs/zh/` 和 `docs/en/` 添加 SendRaw/RecvRaw 说明
- [ ] Typecheck/lint 通过

### US-003: BatchConn — sendmmsg/recvmmsg 批量收发（批量层，仅 Linux）

**Description:** As a 开发者，我想在一次系统调用中发送或接收多个报文，减少上下文切换次数，提升批量 ping/扫描等场景的性能。

**Acceptance Criteria:**
- [ ] `sendrecv.DialRaw(proto).Batch()` 返回 `*BatchConn`（嵌入 RawConn）
- [ ] `BatchConn.SendBatch(msgs []BatchMsg) (int, error)` — 一次 `sendmmsg` 发送多个报文
  - `BatchMsg{Data []byte, Dst string}`
  - 返回成功发送数
- [ ] `BatchConn.RecvBatch(n int, timeout time.Duration) ([]BatchResult, error)` — 一次 `recvmmsg` 接收多个报文
  - `BatchResult{Data []byte, Src string}`
  - 返回实际接收的报文列表
- [ ] Linux 平台通过 `syscall.RawSyscall` 调用 `__NR_sendmmsg` / `__NR_recvmmsg`
- [ ] macOS 平台降级为循环调用 Send/Recv（功能兼容，性能无优化）
- [ ] 示例：`examples/19-batch-raw-socket/main.go`，对比批量 vs 循环的性能差异
- [ ] 文档更新：`docs/zh/` 和 `docs/en/` 添加 BatchConn API 说明
- [ ] Typecheck/lint 通过

### US-004: ZeroCopy — MSG_ZEROCOPY 零拷贝发送（零拷贝层，仅 Linux）

**Description:** As a 开发者，发送大报文（如巨型帧、文件传输）时，我希望使用零拷贝避免内核在用户态和内核态之间拷贝数据。

**Acceptance Criteria:**
- [ ] `RawConn.SetZeroCopy(enable bool) error` — 启用/禁用零拷贝模式（设置 SO_ZEROCOPY socket option）
- [ ] 启用零拷贝后，`RawConn.Send` 自动使用 `sendmsg` + `MSG_ZEROCOPY` 标志
- [ ] 零拷贝发送先返回成功，完成后通过 `SO_EE_ORIGIN_ZEROCOPY` 错误队列通知——API 需提供 `WaitZeroCopyCompletion(ctx) error` 等待完成确认
- [ ] Linux 平台通过 `setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one)` 启用
- [ ] macOS 平台 `SetZeroCopy` 和 `WaitZeroCopyCompletion` 直接返回 `ErrNotSupported`
- [ ] 示例：`examples/20-zerocopy/main.go`，对比零拷贝 vs 普通拷贝的吞吐量
- [ ] 文档更新：`docs/zh/` 和 `docs/en/` 添加 ZeroCopy API 说明
- [ ] Typecheck/lint 通过

### US-005: UringConn — io_uring 异步 IO（异步层，仅 Linux 5.1+）

**Description:** As a 高性能场景开发者，我希望使用 Linux io_uring 进行异步网络 IO，获得最高的吞吐量和最低的延迟。

**Acceptance Criteria:**
- [ ] `sendrecv.DialUringRaw(proto int) (*UringConn, error)` 创建基于 io_uring 的连接
- [ ] `UringConn.Send(data []byte, dst string) (uint64, error)` — 提交发送 SQE，返回操作 ID
- [ ] `UringConn.Recv(timeout time.Duration) ([]byte, string, error)` — 等待接收 CQE，返回数据
- [ ] `UringConn.SendRecvBatch(msgs []BatchMsg) ([]BatchResult, error)` — 批量提交多个发送和接收 SQE，批量等待 CQE
- [ ] 内部通过 `golang.org/x/sys/unix` 的 `io_uring` 支持实现（Go 1.23+ 官方支持）
- [ ] `UringConn.Close()` 关闭 io_uring 实例
- [ ] macOS 平台 `DialUringRaw` 返回 `ErrNotSupported`
- [ ] 示例：`examples/21-uring-raw-socket/main.go`，演示 io_uring 异步收发
- [ ] 文档更新：`docs/zh/` 和 `docs/en/` 添加 UringConn API 说明
- [ ] Typecheck/lint 通过

### US-006: PacketMMAP — PACKET_MMAP/TPACKET_V3 链路层捕获（仅 Linux）

**Description:** As a 高性能抓包场景开发者，我希望通过内存映射环形缓冲区捕获链路层报文，替代 BPF 获得更高吞吐量。

**Acceptance Criteria:**
- [ ] `sendrecv.NewPacketMMAP(iface string) (*PacketMMAP, error)` 创建基于 TPACKET_V3 的环形缓冲区
- [ ] `PacketMMAP.Recv(timeout time.Duration) (*packet.Packet, error)` — 从环形缓冲区读取下一个报文（阻塞）
- [ ] `PacketMMAP.RecvBatch(n int, timeout time.Duration) ([]*packet.Packet, error)` — 批量读取
- [ ] `PacketMMAP.Stats() PacketMMAPStats` — 返回丢包统计（`{Received, Dropped, Freeze}`）
- [ ] `PacketMMAP.Close() error` — 解除映射，关闭 socket
- [ ] 内部使用 `AF_PACKET + SOCK_RAW` + `setsockopt(PACKET_RX_RING)` + `mmap`
- [ ] macOS 平台 `NewPacketMMAP` 返回 `ErrNotSupported`
- [ ] 示例：`examples/22-packet-mmap/main.go`，演示环形缓冲区捕获 + 统计
- [ ] 文档更新：`docs/zh/` 和 `docs/en/` 添加 PacketMMAP API 说明
- [ ] Typecheck/lint 通过

### US-007: 更新 ping 示例使用新 API

**Description:** As a 开发者，我希望 ping 示例使用新的包装函数替代原始 syscall 调用，验证 API 设计的可用性。

**Acceptance Criteria:**
- [ ] `examples/17-ping/main.go` 用 `RawConn` 替代 raw `syscall.Socket` + `syscall.Sendto` + `syscall.Recvfrom`
- [ ] 代码行数减少（参数更少）
- [ ] `sudo go run main.go 127.0.0.1` 正常输出 ping 结果
- [ ] `sudo go run main.go 8.8.8.8` 正常输出 ping 结果
- [ ] 文档更新：`docs/zh/` 和 `docs/en/` 更新 ping 示例说明，反映新 API 用法

### US-008: 示例代码 — 各功能独立示例

**Description:** As a 开发者，我希望每个新增的 sendrecv 功能都有独立可运行的示例，方便快速上手和理解用法。

**Acceptance Criteria:**
- [ ] `examples/18-raw-socket/main.go` — RawConn + SendRaw/RecvRaw 完整示例（ICMP ping 简化版）
- [ ] `examples/19-batch-raw-socket/main.go` — BatchConn 批量收发示例（仅 Linux 有效，macOS 降级提示）
- [ ] `examples/20-zerocopy/main.go` — ZeroCopy 零拷贝发送示例（仅 Linux 有效，macOS 提示不支持）
- [ ] `examples/21-uring-raw-socket/main.go` — UringConn io_uring 异步 IO 示例（仅 Linux 5.1+ 有效）
- [ ] `examples/22-packet-mmap/main.go` — PacketMMAP 环形缓冲区捕获示例（仅 Linux 有效）
- [ ] 每个示例包含清晰的注释说明用法和平台要求
- [ ] Typecheck/lint 通过

### US-009: 文档更新 — 中英文 API 文档

**Description:** As a 开发者，我希望 sendrecv 包的新 API 有完整的中英文文档，包括 API 参考、使用示例和平台兼容性说明。

**Acceptance Criteria:**
- [ ] `docs/zh/` 添加 sendrecv 包中文文档，覆盖所有新增 API（RawConn, SendRaw/RecvRaw, BatchConn, ZeroCopy, UringConn, PacketMMAP）
- [ ] `docs/en/` 添加 sendrecv 包英文文档，与中文内容一致
- [ ] 文档包含：API 签名、参数说明、返回值、平台兼容性矩阵、简单代码示例
- [ ] 文档格式与现有 docs/ 风格一致
- [ ] Typecheck/lint 通过

## Functional Requirements

### 基础层 (US-001, US-002)

- FR-1: `DialRaw(proto)` 创建 raw socket（AF_INET, SOCK_RAW, proto），返回 `*RawConn`
- FR-2: `RawConn.Send(data, dst)` 内部完成 IP 地址解析和 `sendto` 系统调用
- FR-3: `RawConn.Recv(timeout)` 内部设置 SO_RCVTIMEO，分配 1500 字节 buffer，执行 `recvfrom`，返回原始数据和来源 IP
- FR-4: macOS 和 Linux 各自实现
- FR-5: `SendRaw` / `RecvRaw` 作为便捷函数，每次调用创建新 socket、操作、关闭

### 批量层 (US-003)

- FR-6: `BatchConn` 继承 `RawConn`，增加 `SendBatch` / `RecvBatch` 方法
- FR-7: Linux 使用 `sendmmsg(2)` / `recvmmsg(2)` 系统调用；macOS 降级为循环调用
- FR-8: `BatchMsg` 结构体包含 `Data []byte` 和 `Dst string`
- FR-9: `BatchResult` 结构体包含 `Data []byte` 和 `Src string`

### 零拷贝层 (US-004)

- FR-10: `SetZeroCopy(enable)` 启用 `SO_ZEROCOPY` socket option
- FR-11: 零拷贝模式下 `Send` 使用 `sendmsg` + `MSG_ZEROCOPY` 标志
- FR-12: `WaitZeroCopyCompletion(ctx)` 从 socket 错误队列读取 `SO_EE_ORIGIN_ZEROCOPY` 确认消息
- FR-13: macOS 返回 `ErrNotSupported`

### 异步层 (US-005)

- FR-14: `DialUringRaw(proto)` 创建 io_uring 实例并初始化 raw socket
- FR-15: `Send`/`Recv`/`SendRecvBatch` 通过 io_uring submission queue 提交操作
- FR-16: 通过 completion queue 等待结果，支持超时
- FR-17: macOS 返回 `ErrNotSupported`

### 高性能捕获层 (US-006)

- FR-18: `NewPacketMMAP(iface)` 创建 AF_PACKET socket + TPACKET_V3 环形缓冲区
- FR-19: `Recv`/`RecvBatch` 从 mmap 区域读取报文，用 goscapy Dissect 解析
- FR-20: `Stats()` 返回环形缓冲区统计（接收数、丢包数、freeze 次数）
- FR-21: macOS 返回 `ErrNotSupported`

### 示例代码 (US-008)

- FR-22: 每个功能对应一个独立示例文件，位于 `examples/` 目录
- FR-23: 每个示例包含平台检测，Linux-only 功能在 macOS 上给出明确提示
- FR-24: 示例注释清晰说明用法、参数和平台要求

### 文档更新 (US-009)

- FR-25: `docs/zh/` 添加 sendrecv 中文 API 文档
- FR-26: `docs/en/` 添加 sendrecv 英文 API 文档
- FR-27: 文档包含平台兼容性矩阵，标注各功能的 macOS/Linux 支持状态

## 整体 API 层次

```
┌─────────────────────────────────────────────────────┐
│  Layer 4: 异步层                                      │
│  UringConn (io_uring)              [仅 Linux 5.1+]   │
├─────────────────────────────────────────────────────┤
│  Layer 3: 批量层 & 零拷贝层                            │
│  BatchConn (sendmmsg/recvmmsg)     [仅 Linux]         │
│  RawConn.SetZeroCopy (MSG_ZEROCOPY) [仅 Linux]       │
├─────────────────────────────────────────────────────┤
│  Layer 2: 高性能捕获层                                 │
│  PacketMMAP (TPACKET_V3)           [仅 Linux]         │
├─────────────────────────────────────────────────────┤
│  Layer 1: 基础层                                      │
│  RawConn (sendto/recvfrom)        [macOS + Linux]    │
│  SendRaw / RecvRaw                                   │
└─────────────────────────────────────────────────────┘
```

## Non-Goals

- **不**提供 `SendRecv` 组合函数——用户可通过 RawConn 的 Send + Recv 自行组合
- **不**内置 ICMP 校验和计算——上层协议逻辑
- **不**支持 IPv6（本次范围仅 IPv4）
- **不**支持 Windows
- **不**提供 DPDK/AF_XDP 内核旁路——需要独立运行时环境
- **不**提供内核模块代码——纯用户态 Go 实现

## Technical Considerations

### 平台差异矩阵

| 功能 | macOS | Linux |
|------|-------|-------|
| RawConn (sendto/recvfrom) | ✓ | ✓ |
| SendRaw / RecvRaw | ✓ | ✓ |
| BatchConn (sendmmsg/recvmmsg) | 降级为循环 | ✓ native |
| ZeroCopy (MSG_ZEROCOPY) | ErrNotSupported | ✓ (kernel 4.14+) |
| UringConn (io_uring) | ErrNotSupported | ✓ (kernel 5.1+) |
| PacketMMAP (TPACKET_V3) | ErrNotSupported | ✓ |

### 技术要点

- **RawConn:** `AF_INET + SOCK_RAW + proto`；地址转换 `net.ParseIP → [4]byte → SockaddrInet4`
- **sendmmsg/recvmmsg:** 需要手动构造 `syscall.Msghdr` 数组，通过 `RawSyscall` 调用 `SYS_SENDMMSG` / `SYS_RECVMMSG`
- **MSG_ZEROCOPY:** 发送后需从 `recvmsg(..., MSG_ERRQUEUE)` 读取 `sock_extended_err` 确认完成
- **io_uring:** 使用 Go 1.23+ 的 `unix.IORingSetup` / `unix.IORingEnter` 等 API
- **TPACKET_V3:** 需要 `setsockopt(PACKET_VERSION, TPACKET_V3)` → `setsockopt(PACKET_RX_RING)` → `mmap` → 轮询 `tp_status`
- **Recvfrom 行为差异:** macOS 返回 IP header + protocol data；Linux 仅返回 protocol data

### 依赖

- `golang.org/x/sys/unix` — io_uring 和高级 socket flags
- Go 1.23+ — io_uring 官方支持

## Success Metrics

- ping 示例代码行数减少 30%+
- `BatchConn.SendBatch(100)` 比循环调用 `Send 100` 次减少 ~99% 系统调用次数
- `PacketMMAP` 收包吞吐量达到 BPF 方案的 2-5 倍（无上下文切换）
- 所有 Linux 特性在 macOS 上优雅降级（返回 `ErrNotSupported`）
- 每个功能提供独立可运行的示例代码（`go run` 即可启动）
- 中英文文档覆盖全部新增 API

## Open Questions

- io_uring 是否需要支持多线程共享 submission queue？（建议 v1 单线程，后续扩展）
- TPACKET_V3 缓冲区大小是否需要可配置？（建议 v1 固定 4MB × 4 blocks）
- `SendRaw` 是否应该合并为 `SendRecvRaw` 避免 socket 重复创建？（已在 US-001 RawConn 中解决）
- 文档是内联在代码中（Go doc）还是独立 Markdown 文件？（建议独立 Markdown 文件，与现有 docs/ 结构一致）
- 示例文件编号规则？现有 17-ping 占用 17，新示例从 18 开始递增