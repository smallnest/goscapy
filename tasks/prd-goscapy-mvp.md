# PRD: GoScapy — Scapy 核心能力 Go 语言移植

## 1. 概述

将 [Scapy](https://github.com/secdev/scapy) 的核心包操作能力移植到 Go 语言，打造一个**纯 Go、零外部依赖**的网络包构造与解析库。目标用户是需要将包分析/构造能力嵌入 Go 微服务的网络工程师。

GoScapy 不追求 1:1 复制 Scapy 的全部协议生态，而是先建立核心框架（Packet/Field 系统、序列化/反序列化、发送/接收、基础协议），后续增量扩展。API 以 Builder 模式为主，同时提供简化的函数式快捷方式，兼顾 Go 惯用法和 Scapy 的使用便利性。

## 2. 目标

- 纯 Go 标准库 + syscall 实现，零外部依赖
- 提供灵活的 Packet/Field 元编程框架，便于扩展新协议
- 支持 Layer 2/3 的原始套接字收发
- 支持网络接口嗅探（sniffing）
- 内置基础协议：Ethernet、IP、TCP、UDP、ICMP、ARP、Raw
- Builder API 为主 + 函数式快捷方式，兼顾强类型安全和编码效率
- 功能正确性对标 Scapy，性能不低于 Scapy 同等场景

## 3. 用户故事

### US-001: 核心 Packet 与 Field 系统
**描述:** 作为库的使用者，我需要一个通用的 Packet 抽象和 Field 系统，使得定义新协议只需声明字段列表，框架自动处理类型转换、默认值和校验。

**验收标准:**
- [ ] 定义 `Packet` 接口/结构体，包含 `fields_desc` 元数据驱动的字段定义
- [ ] 定义 `Field` 接口，支持 `BitField`、`ByteField`、`ShortField`、`IntField`、`IPField`、`MACField` 等常用字段类型
- [ ] 字段支持默认值、自动长度计算、条件存在（根据其他字段值决定是否出现）
- [ ] `Packet` 支持字段值的 get/set，支持通过字段名和索引两种方式访问
- [ ] `go test ./pkg/fields/...` 通过
- [ ] `go vet ./...` 通过

### US-002: 协议层叠加与组合
**描述:** 作为库的使用者，我需要将多个协议层（如 Ethernet/IP/TCP）组合为一个完整包，并自动解析上下层关系（如 IP 层自动填入 Ethernet 的 type 字段）。

**验收标准:**
- [ ] 实现层叠加操作，下层自动绑定上层协议类型字段
- [ ] 支持 `Packet.GetLayer(layerType)` 按类型查找层
- [ ] 支持 `Packet.HasLayer(layerType)` 判断是否包含指定层
- [ ] 层之间字段绑定：上层协议变更时自动同步下层的 type/dst 字段
- [ ] `go test ./pkg/packet/...` 通过
- [ ] `go vet ./...` 通过

### US-003: 基础协议实现
**描述:** 作为库的使用者，我需要开箱即用的基础网络协议定义：Ethernet、ARP、IP、ICMP、TCP、UDP、Raw（自定义负载）。

**验收标准:**
- [ ] 实现 `Ethernet`：src/dst MAC、type 字段，自动处理 MAC 地址格式化
- [ ] 实现 `ARP`：硬件/协议类型、地址长度、操作码、发送方/目标地址
- [ ] 实现 `IP`：version、ihl、tos、len、id、flags、frag、ttl、proto、checksum、src/dst，支持 checksum 自动计算
- [ ] 实现 `ICMP`：type、code、checksum、id、seq，支持 Echo Request/Reply
- [ ] 实现 `TCP`：src/dst port、seq、ack、dataofs、flags、window、checksum、urgptr、options
- [ ] 实现 `UDP`：src/dst port、len、checksum
- [ ] 实现 `Raw`：任意负载数据
- [ ] 每个协议与 Wireshark/Scapy 生成的等价包逐字节对账
- [ ] `go test ./pkg/layers/...` 通过
- [ ] `go vet ./...` 通过

### US-004: 包构建（序列化）
**描述:** 作为库的使用者，我需要将构造好的 Packet 对象序列化为原始字节流，以便发送到网络。

**验收标准:**
- [ ] `Packet.Build()` 递归构建所有层，输出 `[]byte`
- [ ] 构建过程中自动计算 checksum、length 等派生字段
- [ ] 构建结果与 Scapy `bytes(pkt)` 输出逐字节一致（同协议同参数）
- [ ] 支持构建部分层（从指定层开始构建）
- [ ] `go test ./pkg/packet/...` 包含序列化对账用例
- [ ] `go vet ./...` 通过

### US-005: 包解析（反序列化）
**描述:** 作为库的使用者，我需要将原始字节流解析为结构化的 Packet 对象，自动识别各协议层。

**验收标准:**
- [ ] `Packet.Dissect(raw []byte)` 从字节流自动识别并解析协议层
- [ ] 解析基于下层协议字段（如 Ethernet.type → 上层是 IP 还是 ARP，IP.proto → 上层是 TCP/UDP/ICMP）
- [ ] 失败时返回明确错误，指出哪个层、哪个字段解析失败
- [ ] 解析结果与 Scapy `Ether(raw_bytes).show()` 输出字段值一致
- [ ] `go test ./pkg/packet/...` 包含反序列化对账用例
- [ ] `go vet ./...` 通过

### US-006: 原始套接字发送与接收
**描述:** 作为库的使用者，我需要通过原始套接字发送和接收网络包，支持 Layer 2（数据链路层）和 Layer 3（网络层）两种模式。

**验收标准:**
- [ ] `Send(pkt, iface)` 发送包，Layer 3 模式
- [ ] `Sendp(pkt, iface)` 发送包，Layer 2 模式（直接写入数据链路层）
- [ ] `Recv(iface, timeout)` 接收单个包，返回 `Packet`
- [ ] `SendRecv(pkt, iface, timeout)` 发送并等待响应，返回 `(sent, received)`
- [ ] `SendRecv1(pkt, iface, timeout)` 发送并等待第一个响应
- [ ] 支持指定网络接口和超时
- [ ] macOS/Linux 均可通过测试（Linux AF_PACKET, macOS BPF）
- [ ] `go test ./pkg/sendrecv/...` 通过（需要 root/sudo 权限的用例跳过或标记）
- [ ] `go vet ./...` 通过

### US-007: 包嗅探
**描述:** 作为库的使用者，我需要持续监听网络接口并实时捕获经过的包。

**验收标准:**
- [ ] `Sniff(iface, filter, count, timeout)` 捕获包，可指定数量或超时自动停止
- [ ] 支持 BPF 过滤器（如 `"tcp port 80"`）
- [ ] 支持回调函数模式 `Sniff(iface, filter, func(pkt Packet) { ... })`
- [ ] 支持 channel 模式 `for pkt := range SniffChan(iface, filter) { ... }`
- [ ] `go test ./pkg/sniff/...` 通过
- [ ] `go vet ./...` 通过

### US-008: Builder API 与快捷函数
**描述:** 作为库的使用者，我需要符合 Go 惯用法的人机接口——Builder 模式用于需要完整类型安全的场景，函数式快捷方式用于快速原型和脚本。

**验收标准:**
- [ ] Builder API：`goscapy.NewEthernet().DstMAC("ff:ff:ff:ff:ff:ff").Over(goscapy.NewIP().DstIP("8.8.8.8")).Over(goscapy.NewICMP().Type(8)).Build()`
- [ ] 函数式快捷：`goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)` 一行生成完整三层包
- [ ] 快捷函数覆盖常用组合：EtherIP、EtherIPTCP、EtherIPUDP、EtherARP、IPICMP、IPTCP、IPUDP
- [ ] `go test ./pkg/goscapy/...` 通过
- [ ] `go vet ./...` 通过

## 4. 功能需求

- **FR-1:** 系统必须提供 `Packet` 接口和 `BasePacket` 默认实现，所有协议通过嵌入 `BasePacket` 并声明 `fields_desc` 来定义
- **FR-2:** 系统必须提供 `Field` 接口和至少 8 种内置字段类型（BitField、ByteField、ShortField、LEShortField、ThreeBytesField、IntField、MACField、IPField、StrField、PacketField）
- **FR-3:** 字段必须支持 `default`、`length_from`（从其他字段推导长度）、`depends_on`（条件存在）三种元属性
- **FR-4:** 系统必须支持层自动绑定：将 Layer N+1 放到 Layer N 之上时，Layer N 的协议类型字段自动设置为对应值
- **FR-5:** `Packet.Build()` 必须递归序列化所有层，并在构建过程中自动填充 checksum、length 等可计算字段
- **FR-6:** `Packet.Dissect(raw []byte)` 必须基于链路层协议类型字段（如 Ethernet.type、IP.proto）自动识别上层协议，递归解析全部层
- **FR-7:** 系统必须通过原始套接字支持 Layer 2 (`ETH_P_ALL`) 和 Layer 3 (`AF_INET`) 两种发送模式
- **FR-8:** `Sniff()` 必须支持 Linux BPF 和 macOS BPF 过滤器语法
- **FR-9:** 包嗅探必须同时支持回调函数模式和 Go channel 模式
- **FR-10:** Builder API 的每个层设置方法必须返回 `*Builder` 自身以支持链式调用
- **FR-11:** 系统必须提供至少 8 个常用协议组合的快捷构造函数
- **FR-12:** 所有导出 API 必须有完整的 Go doc 注释

## 5. 非目标（Out of Scope）

- 不提供交互式 REPL Shell（Scapy 的 `scapy` 命令）
- 不提供图形化抓包分析界面
- 不实现 `scapy/contrib` 下的社区贡献协议（如 BGP、OSPF、MQTT 等）
- 不支持 IPv6 协议族（IPv6、ICMPv6、NDP 等，作为 v2 目标）
- 不提供 DHCP、DNS、HTTP、TLS 等应用层协议（可在框架稳定后以 contrib 方式添加）
- 不实现 Scapy 的 `traceroute`、`arping`、`nmap` 等自动化工具模块
- 不实现 `.pdf()` / `.ps()` / `.svg()` 等包可视化输出
- 不支持 Windows 平台（v1 仅 Linux + macOS）
- 不实现 `fuzz()` 模糊测试功能

## 6. 设计考虑

### API 设计原则
- **类型安全优于魔法:** 不试图用 `/` 操作符模拟 Python DSL，用 Builder 模式明确表达意图
- **简洁但不简陋:** 函数式快捷方式覆盖 80% 场景，Builder 覆盖剩余 20% 复杂场景
- **Go 惯例优先:** 错误通过 `error` 返回值传递，不使用 panic；导出符号以协议名为前缀避免冲突
- **零值即默认:** 协议结构体的零值就是合理的默认配置（如 IP.version 默认 4，TCP.window 默认 65535）

### 包结构设计
```
goscapy/
├── pkg/
│   ├── fields/        # Field 类型定义（US-001）
│   ├── packet/        # Packet 接口和基础实现（US-001, US-002, US-004, US-005）
│   ├── layers/        # 协议实现（US-003）
│   ├── sendrecv/      # 原始套接字收发（US-006）
│   ├── sniff/         # 嗅探（US-007）
│   └── goscapy/       # 顶层 Builder API 和快捷函数（US-008）
├── examples/          # 使用示例
└── tests/             # 集成测试
```

## 7. 技术考虑

### 零依赖实现路径
- **原始套接字:** Linux 使用 `syscall.Socket(AF_PACKET, ...)`, macOS 使用 BPF（`/dev/bpf*` 设备）
- **IP/TCP/UDP checksum:** 纯 Go 实现，利用 `encoding/binary` 做 16 位累加
- **网络接口枚举:** 通过 `net.Interfaces()` 获取接口列表，无需 `libpcap`
- **BPF 过滤:** 手动构造 BPF 指令或使用固定常用过滤器（"tcp", "udp", "port 80" 等），完整 BPF 编译器列为 v2 目标

### 性能目标
- 单包构建/解析延迟在微秒级（与 Scapy Python 持平或更优）
- Go 的并发优势不在此版本重点利用（`Sniff` 的 channel 模式已提供基础并发）

### 测试策略
- 每个协议实现必须有与 Scapy 的对账测试（构造 → 序列化 → 逐字节比对）
- 反序列化对账：用 Scapy 生成的 pcap 文件作为测试夹具（test fixtures）
- 集成测试需要 root 权限的操作标记 `t.Short()` 跳过，CI 中可选择性执行

## 8. 成功指标

- 8 个用户故事全部验收通过
- 基础协议（Ethernet/IP/TCP/UDP/ICMP/ARP）序列化输出与 Scapy 逐字节一致
- 反序列化后字段值与 Scapy 解析结果一致
- Wireshark 能正确识别和展示 GoScapy 构造并发送的包
- `go test ./...` 和 `go vet ./...` 全绿
- Go doc 覆盖所有导出符号

## 9. 未决问题

- 是否需要支持 VLAN (802.1Q) 标签？作为基础协议还是 v2？
- TCP options 的覆盖范围——是否只需 MSS、WindowScale、SACKPermitted、Timestamp 四种最常用选项？
- Layer 自动绑定的粒度——ARP 请求中发送方 IP 是否应自动填入 ARP 层的源地址？
- macOS BPF 设备的权限问题——是否需要文档说明 `sudo chmod` 或 `devfs` 配置方式？