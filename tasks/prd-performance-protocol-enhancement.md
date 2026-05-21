# PRD: goscapy 性能优化与协议栈增强

## Introduction

goscapy 已具备完整的 packet build/dissect/send/recv/sniff 能力，并提供了 io_uring、TPACKET_V3、sendmmsg 等高性能路径。本 PRD 旨在解决当前实现中的性能瓶颈、补全协议栈缺失能力、并增强工具生态支持，使 goscapy 能够胜任高 pps 网络监控、安全扫描、协议仿真和离线分析等综合场景。

## Goals

- 降低高 pps 场景下收包路径的 GC 压力，提升吞吐量
- 减少不必要的 syscall 开销（SO_RCVTIMEO 重复设置）
- 支持多核并行抓包（AF_PACKET fanout）
- 提供 AF_XDP 零拷贝收包路径，达到接近线速的处理能力
- 支持 pcap/pcapng 文件的读写，实现离线分析能力
- 补全 TCP Options 字段的解析与构造能力
- 实现 IP 分片重组，支持完整流量分析
- 提供发送端速率控制能力
- 支持 IPv6 原始套接字发送

## User Stories

### US-001: 收包路径 Buffer Pool
**Description:** As a developer building a high-pps scanner, I want the recv path to reuse buffers so that GC pressure is reduced under heavy packet load.

**Acceptance Criteria:**
- [ ] `afPacketReceiver.Recv()` 和 `RawConn.Recv()` 使用 `sync.Pool` 复用 65536 字节 buffer
- [ ] 提供 `ReleaseBuffer` 或自动回收机制，buffer 在 dissect 后归还 pool
- [ ] 基准测试（BenchmarkRecv）显示 allocs/op 降低 ≥ 50%
- [ ] 不影响现有 API 的向后兼容性
- [ ] 所有现有测试通过

### US-002: 消除 SO_RCVTIMEO 重复设置
**Description:** As a developer, I want the receiver to avoid redundant setsockopt calls so that each recv loop iteration saves one syscall.

**Acceptance Criteria:**
- [ ] `afPacketReceiver` 和 `RawConn` 记录上一次设置的 timeout 值
- [ ] 仅在 timeout 变化时调用 `SetsockoptTimeval`
- [ ] 或替代方案：使用 `unix.Poll` + deadline 代替 SO_RCVTIMEO（与 TPACKET_V3 路径一致）
- [ ] 基准测试中 syscall 次数减半（通过 strace 验证）
- [ ] 所有现有测试通过

### US-003: AF_PACKET Fanout 支持
**Description:** As a developer building a multi-core traffic monitor, I want to distribute packets across multiple goroutines via PACKET_FANOUT so that I can achieve per-core parallel processing.

**Acceptance Criteria:**
- [ ] 新增 `FanoutReceiver` 类型，支持创建 N 个 AF_PACKET socket 并加入同一 fanout group
- [ ] 支持 fanout mode 配置（hash、lb、cpu、rollover）
- [ ] 提供 `RecvParallel(n int, handler func(*packet.Packet))` 启动 N 个接收 goroutine
- [ ] 示例程序（examples/）验证多核抓包性能
- [ ] Linux-only，Darwin 编译不报错（stub）

### US-004: AF_XDP (XSK) 零拷贝收发
**Description:** As a performance engineer, I want AF_XDP support so that packets bypass the kernel stack for near-line-rate processing.

**Acceptance Criteria:**
- [ ] 实现 `XDPConn` 类型，支持 UMEM ring 的 setup/fill/completion
- [ ] 支持 Recv（从 RX ring 读包）和 Send（写入 TX ring）
- [ ] 支持 attach 简单 XDP 程序（redirect to XSK）
- [ ] 提供 `XDP_COPY` 和 `XDP_ZEROCOPY` 两种模式
- [ ] 基准测试：在标准硬件上达到 > 1Mpps 的单核收包速率
- [ ] 示例程序演示基本用法
- [ ] Linux >= 5.4 only，Darwin 编译不报错（stub）

### US-005: pcap/pcapng 文件读写
**Description:** As a network analyst, I want to read and write pcap files so that I can analyze captured traffic offline and export packets for sharing.

**Acceptance Criteria:**
- [ ] 新增 `pkg/pcap` 包，纯 Go 实现（不依赖 libpcap）
- [ ] 支持读取 pcap 格式（magic number 0xa1b2c3d4，little/big endian）
- [ ] 支持读取 pcapng 格式（Section Header Block + Interface Description Block + Enhanced Packet Block）
- [ ] 支持写入 pcap 格式
- [ ] Reader 返回 `*packet.Packet`（自动调用 Dissect）
- [ ] Writer 接收 `*packet.Packet` 或 `[]byte`
- [ ] 支持按时间戳过滤、按 count 限制读取
- [ ] 单元测试覆盖各格式的标准样本文件

### US-006: TCP Options 解析与构造
**Description:** As a security researcher doing OS fingerprinting, I want to parse and construct TCP Options so that I can analyze and craft packets with MSS, Window Scale, SACK, and Timestamps.

**Acceptance Criteria:**
- [ ] TCP 层支持可变长 Options 字段（基于 dataofs 计算 options 长度）
- [ ] 解析常见 option 类型：MSS (2)、Window Scale (3)、SACK Permitted (4)、SACK (5)、Timestamps (8)
- [ ] dissect 时自动解析 options 到结构化列表
- [ ] build 时支持通过 builder API 添加 options，自动更新 dataofs
- [ ] 单元测试覆盖含 options 的真实抓包数据

### US-007: IP 分片重组
**Description:** As a traffic analyzer, I want IP fragment reassembly so that fragmented packets can be correctly dissected into complete upper-layer protocols.

**Acceptance Criteria:**
- [ ] 新增 `pkg/reassembly` 包或在 `pkg/packet` 中实现 `Reassembler` 类型
- [ ] 支持按 (src, dst, id, proto) 四元组聚合分片
- [ ] 支持超时机制：未完成的分片组在可配置超时后丢弃
- [ ] 重组完成后自动对完整 payload 执行 upper-layer dissect
- [ ] 处理乱序到达、重叠分片、过大报文（DoS 防护限制）
- [ ] 提供 sniff 集成示例：`sniff.SniffWithReassembly`

### US-008: 发送端速率控制
**Description:** As a scanner developer, I want rate limiting on send paths so that I don't overwhelm the network or trigger security alerts.

**Acceptance Criteria:**
- [ ] 新增 `RateLimiter` 接口：`Wait(ctx context.Context) error`
- [ ] 提供 `NewTokenBucketLimiter(pps int)` 实现
- [ ] `sendrecv` 包中支持 `SendWithLimiter(pkt, iface, limiter)` 函数
- [ ] 支持 burst 配置（允许短时突发）
- [ ] 更新 fishfinder 示例使用 rate limiter
- [ ] 不影响不使用 limiter 的现有 API

### US-009: IPv6 原始套接字发送
**Description:** As a developer, I want to send raw IPv6 packets so that the IPv6 layers I can already build are actually transmittable.

**Acceptance Criteria:**
- [ ] `sendL3` 检测 packet 是否包含 IPv6 层，自动选择 AF_INET6 路径
- [ ] Linux: 使用 AF_INET6 + SOCK_RAW + IPV6_HDRINCL
- [ ] Darwin: 使用 AF_INET6 + SOCK_RAW（macOS 不支持 IPV6_HDRINCL，需通过 ancillary data）
- [ ] 支持 IPv6 extension headers 的正确发送
- [ ] 提供 IPv6 ping 示例（ICMPv6 Echo Request/Reply）
- [ ] 现有 IPv4 send 路径不受影响

## Functional Requirements

- FR-1: recv 路径的 buffer 必须通过 sync.Pool 复用，而非每次 make([]byte, 65536)
- FR-2: SO_RCVTIMEO 仅在 timeout 值变化时调用 setsockopt
- FR-3: FanoutReceiver 必须支持 PACKET_FANOUT_HASH、PACKET_FANOUT_LB、PACKET_FANOUT_CPU、PACKET_FANOUT_ROLLOVER 四种模式
- FR-4: XDPConn 必须支持 UMEM 的 fill ring 和 completion ring 管理
- FR-5: pcap reader 必须支持 little-endian 和 big-endian 两种字节序的 pcap 文件
- FR-6: pcapng reader 必须解析 SHB、IDB、EPB 三种必需 block 类型
- FR-7: TCP Options 解析必须处理 EOL (0)、NOP (1) 和所有定义的 option kind
- FR-8: IP 分片重组必须拒绝总大小超过 65535 字节的重组结果（防止 DoS）
- FR-9: RateLimiter 必须基于 token bucket 算法，精度不低于 1ms
- FR-10: IPv6 send 路径必须正确处理 next header chain（extension headers）

## Non-Goals (Out of Scope)

- 不实现完整的 TCP 状态机或连接跟踪
- 不实现 BGP/OSPF 等路由协议的 FSM
- 不实现 libpcap 兼容的 C API
- 不提供 GUI 或 TUI 界面
- 不支持 Windows 平台
- AF_XDP 不实现自定义 eBPF 程序加载（仅使用标准 redirect-to-xsk 程序）
- pcap 写入不实现 pcapng 格式的写入（仅读取）

## Technical Considerations

- Buffer pool 的 `sync.Pool` 回收时机需要考虑 dissect 后 packet 对 raw bytes 的引用关系
- AF_XDP 需要 Linux >= 5.4，编译时通过 build tags 隔离
- IP 分片重组的内存上限需要可配置，防止 OOM
- pcap 读取需要处理 nanosecond timestamp（pcapng 默认）和 microsecond timestamp（legacy pcap）
- Rate limiter 应使用 `time.Timer` 而非 sleep loop，避免精度问题
- IPv6 send 在 macOS 上的限制：无 IPV6_HDRINCL，需要通过 setsockopt + ancillary data 设置 hop limit 等字段

## Success Metrics

- Buffer pool: BenchmarkRecv allocs/op 降低 ≥ 50%
- SO_RCVTIMEO: sendrecv 循环中 syscall 数量减少 ~50%
- Fanout: N 核并行时吞吐量接近 N 倍（线性扩展）
- AF_XDP: 单核 > 1Mpps
- pcap: 读取 1GB pcap 文件耗时 < 10s
- TCP Options: 正确解析 tcpdump 抓取的真实 SYN 包 options
- IP reassembly: 正确重组标准 fragmented ping (size > MTU)
- Rate limiter: 实际 pps 误差 < 5%
- IPv6 send: 成功 ping6 到本机 loopback

## Open Questions

- Buffer pool 中 dissect 后的 packet 是否需要持有 raw buffer 的引用？如果是，pool 回收时机如何确定？
- AF_XDP 是否需要自带一个最小的 eBPF loader，还是要求用户通过 `ip link set dev xxx xdp obj prog.o` 预加载？
- IP 分片重组是否应该集成到 sniff 的 callback 流水线中（自动重组），还是作为独立的 post-processing 步骤？
- pcapng 是否需要支持 Name Resolution Block (NRB) 等可选 block？
