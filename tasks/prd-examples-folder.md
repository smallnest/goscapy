# PRD: goscapy Examples 文件夹

## Introduction

在 goscapy 项目根目录创建 `examples/` 文件夹，为核心特性提供独立可运行的 Go 示例程序。每个示例针对一个具体特性（协议构建、发包、嗅探、解析等），帮助 Go 网络编程新手快速上手 goscapy 库。示例代码附带详细中文注释，解释每一步的含义和目的。

## Goals

- 覆盖 goscapy 所有核心特性，每个特性至少一个独立示例
- 每个示例都是独立的 `main` 包，用户可直接 `go run` 运行
- 注释面向 Go 网络编程新手，详细解释网络概念和 goscapy 用法
- 需要 root 权限的示例在代码中用醒目注释标注
- 提供统一的 README.md 索引，按学习路径排列示例

## User Stories

### US-001: 创建 examples 基础目录结构和 README
**Description:** 作为项目维护者，我需要一个有序的 examples 目录结构，每个示例都有独立的子目录，方便用户按需查阅。

**Acceptance Criteria:**
- [ ] 创建 `examples/` 目录，每个示例一个子目录（如 `examples/01-ethernet-ip-icmp/`）
- [ ] 每个子目录包含 `main.go` 和独立的 `go.mod`（通过 replace 指令引用父项目）
- [ ] 创建 `examples/README.md`，按学习路径列出所有示例的名称、描述和运行命令
- [ ] 示例编号前缀按学习难度递增排列（01-xx, 02-xx, ...）

### US-002: Ethernet + IPv4 基础包构建示例
**Description:** 作为新手用户，我想学习如何使用 Builder API 构建最基础的 Ethernet + IPv4 数据包，理解分层构建的概念。

**Acceptance Criteria:**
- [ ] 示例展示 Ethernet Builder 的用法（设置源/目 MAC、EtherType）
- [ ] 示例展示 IP Builder 的用法（设置源/目 IP、TTL、协议号）
- [ ] 注释解释 Builder API 的链式调用风格和 `Over()` 方法的作用
- [ ] 输出构建后的原始字节（hex dump）
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-003: TCP/UDP 传输层包构建示例
**Description:** 作为新手用户，我想学习如何在 IP 层上叠加 TCP 和 UDP 传输层协议。

**Acceptance Criteria:**
- [ ] 示例展示 TCP Builder 用法（设置源/目端口、标志位 SYN/ACK、序列号）
- [ ] 示例展示 UDP Builder 用法（设置源/目端口）
- [ ] 注释解释 TCP 标志位含义和自动校验和机制
- [ ] 对比 Builder API 和 Shortcut 函数两种写法
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-004: ICMP Echo Request 构建示例
**Description:** 作为新手用户，我想学习如何构建 ICMP Echo Request（Ping）数据包。

**Acceptance Criteria:**
- [ ] 示例展示 ICMP Builder 用法（设置类型 Echo、Code、ID、Seq）
- [ ] 展示使用 Shortcut 函数 `EtherIPICMP()` 快速构建的对比
- [ ] 注释解释 ICMP 协议在 Ping 中的作用
- [ ] 输出完整的 ICMP 包 hex dump
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-005: ARP 包构建示例
**Description:** 作为新手用户，我想学习如何构建 ARP 请求和应答包。

**Acceptance Criteria:**
- [ ] 示例展示 ARP Builder 用法（设置操作码、源/目 MAC/IP）
- [ ] 同时展示 ARP 请求和 ARP 应答两种类型的构建
- [ ] 注释解释 ARP 协议在局域网中的作用（IP 到 MAC 的映射）
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-006: IPv6 包构建示例
**Description:** 作为新手用户，我想学习如何构建 IPv6 数据包及其扩展头。

**Acceptance Criteria:**
- [ ] 示例展示 IPv6 Builder 用法（设置源/目 IPv6 地址、Next Header、Hop Limit）
- [ ] 展示 IPv6 扩展头（Hop-by-Hop、Routing 等）的添加方式
- [ ] 注释解释 IPv6 与 IPv4 的关键区别
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-007: DNS 查询包构建与解析示例
**Description:** 作为新手用户，我想学习如何构建 DNS 查询包并解析 DNS 响应。

**Acceptance Criteria:**
- [ ] 示例展示 DNS Builder 用法（设置查询域名、查询类型 A/AAAA）
- [ ] 展示 DNS 包的序列化和 hex dump 输出
- [ ] 注释解释 DNS 协议的查询/响应模型和记录类型
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-008: DHCP 包构建示例
**Description:** 作为新手用户，我想学习如何构建 DHCP Discover/Request/Offer/ACK 包。

**Acceptance Criteria:**
- [ ] 示例展示 DHCP Builder 用法（设置消息类型、客户端 MAC、请求 IP 等）
- [ ] 展示 DHCP 选项（Option 53 消息类型、Option 50 请求 IP 等）的添加
- [ ] 注释解释 DHCP 四步交互流程（DORA）
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-009: VLAN (802.1Q) 标签包构建示例
**Description:** 作为新手用户，我想学习如何在 Ethernet 帧上添加 VLAN 标签。

**Acceptance Criteria:**
- [ ] 示例展示 VLAN (Dot1Q) Builder 用法（设置 VID、PCP、DEI）
- [ ] 展示带 VLAN 标签的完整 Ethernet + VLAN + IP + TCP 包构建
- [ ] 注释解释 VLAN 在网络隔离中的作用
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-010: GRE/VXLAN 隧道包构建示例
**Description:** 作为新手用户，我想学习如何构建 GRE 和 VXLAN 隧道封装包。

**Acceptance Criteria:**
- [ ] 示例展示 GRE Builder 用法（设置协议类型、Key、序列号）
- [ ] 示例展示 VXLAN Builder 用法（设置 VNI、源/目 IP）
- [ ] 展示隧道内层和外层的完整包结构
- [ ] 注释解释隧道技术在网络叠加中的用途
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-011: 数据包解析（Dissect）示例
**Description:** 作为新手用户，我想学习如何使用 goscapy 将原始字节解析为结构化的数据包。

**Acceptance Criteria:**
- [ ] 示例使用 `packet.Dissect()` 解析原始字节为 Packet 结构
- [ ] 展示如何访问各层字段（Ethernet MAC、IP 地址、TCP 端口等）
- [ ] 展示自动协议检测如何工作（从 Ethernet → IP → TCP 的逐层解析）
- [ ] 注释解释解析引擎的自动协议推断机制
- [ ] 示例可直接 `go run` 运行，无需 root 权限

### US-012: 发送数据包示例（Send/Sendp）
**Description:** 作为新手用户，我想学习如何使用 goscapy 发送构建好的数据包到网络。

**Acceptance Criteria:**
- [ ] 示例展示 `sendrecv.Send()` 发送 L3（IP 层）数据包
- [ ] 示例展示 `sendrecv.Sendp()` 发送 L2（Ethernet 层）数据包
- [ ] 代码顶部用醒目注释标注 "需要 root 权限：sudo go run main.go"
- [ ] 注释解释 L2 和 L3 发送的区别（是否包含 Ethernet 帧）
- [ ] 展示网络接口选择和错误处理

### US-013: 发送并接收示例（SendRecv/SendRecv1）
**Description:** 作为新手用户，我想学习如何发送数据包并等待响应（类似 Ping 的请求/响应模式）。

**Acceptance Criteria:**
- [ ] 示例展示 `sendrecv.SendRecv1()` 发送一个 ICMP Echo 并等待一个响应
- [ ] 示例展示 `sendrecv.SendRecv()` 发送并收集多个响应
- [ ] 展示如何解析收到的响应包并提取 ICMP 字段
- [ ] 代码顶部用醒目注释标注 "需要 root 权限：sudo go run main.go"
- [ ] 注释解释超时设置和 BPF 过滤在响应匹配中的作用

### US-014: TCP SYN 扫描示例
**Description:** 作为新手用户，我想学习如何使用 goscapy 实现 TCP SYN 端口扫描（半开放扫描）。

**Acceptance Criteria:**
- [ ] 示例展示构建 TCP SYN 包并发送到目标端口
- [ ] 展示接收 SYN-ACK（端口开放）和 RST（端口关闭）响应的判断逻辑
- [ ] 代码顶部用醒目注释标注 "需要 root 权限：sudo go run main.go"
- [ ] 注释解释 TCP 三次握手原理和 SYN 扫描的原理
- [ ] 包含错误处理和超时控制

### US-015: 包嗅探（Sniff）示例
**Description:** 作为新手用户，我想学习如何使用 goscapy 捕获网络上的实时流量。

**Acceptance Criteria:**
- [ ] 示例展示 `sniff.Sniff()` 回调方式的包捕获
- [ ] 示例展示 `sniff.SniffChan()` 通道方式的包捕获
- [ ] 展示 BPF 过滤器的使用（如 "tcp port 80"）
- [ ] 代码顶部用醒目注释标注 "需要 root 权限：sudo go run main.go"
- [ ] 注释解释 BPF 过滤表达式语法和常见用法

### US-016: BPF 过滤器示例
**Description:** 作为新手用户，我想学习如何使用 BPF 过滤器精确控制要捕获的数据包类型。

**Acceptance Criteria:**
- [ ] 示例展示常见 BPF 过滤表达式（host、port、proto、net 等）
- [ ] 展示 BPF 过滤器的编译和使用
- [ ] 注释解释 BPF 过滤语法和常用组合模式
- [ ] 示例可直接 `go run` 运行（仅编译过滤器，不实际捕获）

### US-017: Shortcut 快捷函数综合示例
**Description:** 作为新手用户，我想学习 goscapy 提供的所有 Shortcut 函数，快速构建常见协议栈。

**Acceptance Criteria:**
- [ ] 示例展示所有 Shortcut 函数的用法：`EtherIPICMP()`, `EtherIPTCP()`, `EtherIPUDP()`, `IPICMP()`, `IPTCP()`, `IPUDP()` 等
- [ ] 对比 Shortcut 函数和 Builder API 的代码量差异
- [ ] 注释解释何时用 Shortcut、何时用 Builder
- [ ] 示例可直接 `go run` 运行，无需 root 权限

## Functional Requirements

- FR-1: 在项目根目录创建 `examples/` 目录，包含 15-17 个独立子目录
- FR-2: 每个子目录包含 `main.go` 文件，package 声明为 `main`
- FR-3: 每个子目录包含 `go.mod` 文件，通过 replace 指令引用父项目的 `github.com/smallnest/goscapy`
- FR-4: 每个示例代码必须有详细中文注释，面向网络编程新手
- FR-5: 需要 root 权限的示例必须在文件顶部用醒目注释标注运行方式
- FR-6: 不需要 root 权限的示例（仅构建/解析）可直接 `go run main.go` 运行
- FR-7: 创建 `examples/README.md` 索引文件，按学习路径列出所有示例
- FR-8: 所有示例代码必须能通过 Go 编译（`go build` 成功）
- FR-9: 覆盖以下核心特性：Builder API、Shortcut 函数、所有支持的协议、发包、收包、嗅探、解析、BPF 过滤
- FR-10: 每个示例保持简洁，核心代码控制在 50-150 行以内

## Non-Goals

- 不创建集成测试或自动化 CI 测试
- 不实现性能基准测试示例
- 不包含可视化 GUI 工具
- 不创建交互式教程或 Web 教学平台
- 不处理 Windows 平台兼容性（goscapy 仅支持 macOS/Linux）

## Design Considerations

- 示例编号使用两位数字前缀（01-xx, 02-xx），按难度递增排列
- 基础构建示例在前（无需 root），发送/嗅探示例在后（需要 root）
- 每个示例的注释风格统一：文件头说明目的 → 关键步骤注释 → 运行说明
- go.mod 使用 replace 指令确保示例引用本地最新代码

## Technical Considerations

- Go 1.21+ 兼容
- 部分示例需要 root 权限（raw socket 操作），在 macOS 上需要 sudo，Linux 上需要 root 或 CAP_NET_RAW
- BPF 过滤器在 macOS 和 Linux 上的实现不同，示例应兼容两者
- 每个示例独立 go.mod，不与主项目共享依赖

## Success Metrics

- 新用户可在 5 分钟内运行第一个示例
- 覆盖 goscapy 100% 的核心特性（Builder、Shortcut、所有协议、发包、嗅探、解析、BPF）
- 每个示例代码量控制在 50-150 行，保持简洁易读

## Open Questions

- 是否需要在主项目 README 中添加指向 examples 文件夹的链接？
- 示例注释语言是否需要同时支持中英文？
- 是否需要添加一个 "综合实战" 示例（如简单的网络扫描器）？
