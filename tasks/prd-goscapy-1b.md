# PRD: GoScapy Phase 1B — 协议扩展与框架增强

## 1. 概述

在 Phase 1A MVP（核心 Packet/Field 框架 + Ethernet/IP/TCP/UDP/ICMP/ARP/Raw 基础协议 + 收发嗅探）基础上，Phase 1B 补齐网络基础设施协议（DNS、DHCP）和数据中心基础设施协议（IPv6 协议族、VLAN/VXLAN/GRE 隧道），同时增强框架能力以支持这些协议所需的解析特性（TLV/选项解析、名称压缩、隧道封装等）。

目标用户：需要分析或构造 DNS/DHCP/隧道流量的网络工程师、需要支持 IPv6 环境的服务开发者、需要通过 Go 编写自定义网络工具的 SRE/安全工程师。

## 2. 目标

- 新增 4 类协议支持：DNS、DHCP、IPv6 协议族（IPv6/ICMPv6/NDP）、隧道/标签协议（VLAN/VXLAN/GRE）
- 增强框架层：TLV/选项解析器、DNS 名称压缩、隧道协议层嵌套支持
- 所有新协议支持解析（Dissect）和构造（Build），并与 Wireshark/tcpdump 解析结果逐字节对账
- 保持零外部依赖（纯 Go 标准库 + syscall）
- 向后兼容 Phase 1A 的 API，不破坏现有 Builder/快捷函数

## 3. 用户故事

---

### US-001: DNS 协议支持（解析 + 构造）

**描述:** 作为网络分析工具的开发者，我需要解析和构造 DNS 查询/响应报文，以便诊断 DNS 解析故障、审计 DNS 流量或编写 DNS 探测工具。

**验收标准:**
- [ ] 实现 DNS 头部字段：Transaction ID、Flags（QR/Opcode/AA/TC/RD/RA/Z/Rcode）、QDCount、ANCount、NSCount、ARCount
- [ ] 实现 DNS 资源记录（RR）解析：NAME、TYPE、CLASS、TTL、RDLENGTH、RDATA
- [ ] 支持 DNS 名称压缩指针（0xC0 前缀）的正确解引用，防止无限循环
- [ ] 支持常见 RR 类型：A (1)、AAAA (28)、NS (2)、CNAME (5)、PTR (12)、MX (15)、SOA (6)、TXT (16)
- [ ] 支持 Question Section 解析和构造
- [ ] 支持 EDNS(0) OPT 伪资源记录的解析和构造
- [ ] 支持构造 DNS 查询报文和 DNS 响应报文
- [ ] 构造输出与 `dig` 生成的等价查询报文逐字节一致
- [ ] 解析结果与 Wireshark 解析结果字段值一致
- [ ] `go test ./pkg/layers/dns/...` 通过
- [ ] `go vet ./...` 通过

---

### US-002: DHCP 协议支持（解析 + 构造）

**描述:** 作为网络工具开发者，我需要解析和构造 DHCP 报文（Discovery/Offer/Request/ACK 四步握手），以便分析 IP 分配过程、检测 DHCP 劫持或编写 DHCP 压力测试工具。

**验收标准:**
- [ ] 实现 DHCP 头部字段：op、htype、hlen、hops、xid、secs、flags、ciaddr、yiaddr、siaddr、giaddr、chaddr（16 字节）、sname、file、magic cookie
- [ ] 实现 DHCP Options 的 TLV 解析器（Type-Length-Value），支持选项数组遍历
- [ ] 支持常见 DHCP Options：Subnet Mask (1)、Router (3)、DNS Server (6)、Hostname (12)、Domain (15)、Requested IP (50)、Lease Time (51)、Message Type (53)、Server ID (54)、Param Request List (55)、Renewal Time (58)、Rebinding Time (59)、End (255)
- [ ] 支持 DHCP Message Type 的自动识别（DHCPDISCOVER/DHCPOFFER/DHCPREQUEST/DHCPACK 等）
- [ ] 支持构造完整 DHCP 报文（UDP 承载，sport=68, dport=67）
- [ ] 构造输出与 Scapy `BOOTP/DHCP` 生成的报文逐字节一致
- [ ] 解析结果与 Wireshark 解析结果字段值一致
- [ ] `go test ./pkg/layers/dhcp/...` 通过
- [ ] `go vet ./...` 通过

---

### US-003: IPv6 协议族（IPv6 + ICMPv6 + NDP）

**描述:** 作为需要支持 IPv6 环境的服务开发者，我需要解析和构造 IPv6 报文、ICMPv6 消息和邻居发现协议（NDP）报文，以便调试 IPv6 连通性或分析 IPv6 网络行为。

**验收标准:**
- [ ] 实现 IPv6 头部：Version、TrafficClass、FlowLabel、PayloadLength、NextHeader、HopLimit、SrcIP (16B)、DstIP (16B)
- [ ] 支持 IPv6 扩展头部链式解析（Hop-by-Hop、Routing、Fragment、Destination Options），NextHeader 链式跳转
- [ ] 支持 Fragment Header 内的分段信息解析（但不实现重组，仅解析 Header）
- [ ] 实现 ICMPv6：Type、Code、Checksum、Message Body
- [ ] 支持 ICMPv6 常见类型：Echo Request (128)、Echo Reply (129)、Destination Unreachable (1)、Packet Too Big (2)、Time Exceeded (3)、Parameter Problem (4)
- [ ] 实现 NDP 报文：Router Solicitation (133)、Router Advertisement (134)、Neighbor Solicitation (135)、Neighbor Advertisement (136)、Redirect (137)
- [ ] 支持 NDP Options 的 TLV 解析：Source/Target Link-Layer Address (1/2)、Prefix Info (3)、MTU (5)
- [ ] IPv6 伪头部 checksum 计算正确（用于上层协议 TCP/UDP/ICMPv6）
- [ ] 构造输出与 Scapy `IPv6/ICMPv6EchoRequest` 生成的报文逐字节一致
- [ ] 解析结果与 Wireshark 解析结果字段值一致
- [ ] `go test ./pkg/layers/ipv6/...` 通过
- [ ] `go test ./pkg/layers/icmpv6/...` 通过
- [ ] `go test ./pkg/layers/ndp/...` 通过
- [ ] `go vet ./...` 通过

---

### US-004: VLAN (802.1Q) 协议支持

**描述:** 作为数据中心网络工程师，我需要解析和构造带 VLAN Tag 的以太网帧，以便分析跨 VLAN 流量或构造 VLAN 标记的测试包。

**验收标准:**
- [ ] 实现 802.1Q VLAN 头部：TPID (0x8100)、PCP (3 bits)、DEI (1 bit)、VID (12 bits)
- [ ] 支持 VLAN Tag 层可嵌套（QinQ / 802.1ad，TPID=0x88A8）
- [ ] VLAN 层位于 Ethernet 头部和上层协议（IP/ARP 等）之间，解析时自动识别
- [ ] Builder API 支持 `NewDot1Q().VID(100).Over(NewIP().DstIP("10.0.0.1"))` 链式调用
- [ ] 构造输出与 Scapy `Dot1Q(vlan=100)/IP()` 生成的报文逐字节一致
- [ ] 解析结果与 Wireshark 解析结果字段值一致
- [ ] `go test ./pkg/layers/dot1q/...` 通过
- [ ] `go vet ./...` 通过

---

### US-005: VXLAN + GRE 隧道协议支持

**描述:** 作为云计算网络工程师，我需要解析和构造 VXLAN 和 GRE 隧道封装的报文，以便分析 Overlay 网络流量或调试隧道连通性问题。

**验收标准:**
- [ ] 实现 VXLAN 头部：Flags (8 bits)、Reserved (24 bits)、VNI (24 bits，占 3 字节)、Reserved2 (8 bits)
- [ ] VXLAN 封装结构：Outer Ethernet → Outer IP → Outer UDP (dport=4789) → VXLAN → Inner Ethernet → Inner IP → ...
- [ ] 解析时自动识别 VXLAN 封装并递归解析内层报文
- [ ] 实现 GRE 头部：C/ K/ S 标志位、reserved0、Version、ProtocolType (0x0800=IP, 0x6558=Transparent Ethernet)、Checksum、Key、SequenceNumber（条件字段，根据标志位决定是否存在）
- [ ] GRE 封装结构：Outer IP → GRE → Inner IP/Inner Ethernet → ...
- [ ] 实现 GRE 的 Transparent Ethernet Bridging 模式（ProtocolType=0x6558）
- [ ] 构造输出与 Scapy `VXLAN()/Ether()/IP()` 和 `GRE()/IP()` 生成的报文逐字节一致
- [ ] 解析结果与 Wireshark 解析结果字段值一致
- [ ] `go test ./pkg/layers/vxlan/...` 通过
- [ ] `go test ./pkg/layers/gre/...` 通过
- [ ] `go vet ./...` 通过

---

### US-006: TLV/Options 通用解析框架

**描述:** 作为协议实现者，我需要一个通用的 TLV（Type-Length-Value）解析框架，以便快速实现 DHCP Options、NDP Options、DNS EDNS Options 等变长选项字段，避免协议间重复代码。

**验收标准:**
- [ ] 定义 `TLVOption` 接口/结构体：Type、Length、Value ([]byte)
- [ ] 实现 `TLVParser`：从 `[]byte` 中解析 TLV 列表，支持固定长度和变长两种模式
- [ ] 支持 End-of-Options (type=0) 和 Pad (type=0) 的标准终止语义
- [ ] 支持 Nested TLV（选项值本身包含子 TLV）
- [ ] 实现 `TLVBuilder`：从 TLV 列表构造 `[]byte`
- [ ] DHCP Options 和 NDP Options 使用此框架实现，避免重复代码
- [ ] `go test ./pkg/fields/tlv_test.go` 通过
- [ ] `go vet ./...` 通过

---

### US-007: Layer 自动发现与通用隧道递归解析

**描述:** 作为库的开发者，我需要一个可注册的 Layer 发现系统，使 Dissect 能够根据端口号、NextHeader 值、TPID 值等自动识别上层协议；同时支持隧道协议的递归解析（VXLAN → Inner Ethernet → Inner IP → ...）。

**验收标准:**
- [ ] 定义 `DissectorFunc func(data []byte) (proto string, consumed int, err error)` 类型
- [ ] 提供 `RegisterDissector(proto string, fn DissectorFunc)` 注册新的协议识别函数
- [ ] 提供统一的 `Dissect(raw []byte, firstLayer string)` 入口，根据注册的 dissector 链递归解析所有层
- [ ] 现有 Ethernet/IP/TCP/UDP/ICMP/ARP 的 dissection 迁移到注册机制（不破坏现有 API）
- [ ] 支持隧道协议的递归：识别到 VXLAN/GRE 层后，自动继续解析内层报文
- [ ] 支持端口号识别：解析 UDP 层后，当 dport=53 时自动识别为 DNS，dport=67/68 时自动识别为 DHCP，dport=4789 时自动识别为 VXLAN
- [ ] 解析失败时返回清晰错误：哪个层、哪个字段、原始字节的 hex dump
- [ ] `go test ./pkg/packet/...` 通过
- [ ] `go vet ./...` 通过

---

### US-008: Builder API 与快捷函数扩展

**描述:** 作为库的使用者，我需要新协议的 Builder API 和常用组合的快捷函数，保持与 Phase 1A 一致的使用体验。

**验收标准:**
- [ ] 新增 Builder：`DNSBuilder`、`DHCPBuilder`、`IPv6Builder`、`ICMPv6Builder`、`Dot1QBuilder`、`VXLANBuilder`、`GREBuilder`
- [ ] 每个 Builder 遵循 Phase 1A 模式：链式方法（`SrcIP()` → 返回 `*Builder`）、`Over()` → 返回 `*PacketBuilder`
- [ ] 新增快捷函数：`IPv6ICMPv6Echo`、`EtherDot1QIP`、`EtherDot1QIPICMP`、`EtherIPUDPVXLAN`、`EtherIPGRE`、`EtherIPUDPDNS`、`EtherIPUDPDHCP`（覆盖常用组合）
- [ ] 快捷函数默认值合理（如 DHCP 默认 sport=68, dport=67）
- [ ] `go test ./pkg/goscapy/...` 通过
- [ ] `go vet ./...` 通过

---

## 4. 功能需求

- **FR-1:** 系统必须支持 DNS 报文（RFC 1035）的完整解析和构造，包括名称压缩指针解引用
- **FR-2:** 系统必须支持 DHCP 报文（RFC 2131）的完整解析和构造，包括 Options TLV 列表
- **FR-3:** 系统必须支持 IPv6 头部（RFC 8200）及扩展头部链的解析和构造
- **FR-4:** 系统必须支持 ICMPv6（RFC 4443）的 6 种常见消息类型解析和构造
- **FR-5:** 系统必须支持 NDP（RFC 4861）的 5 种报文类型解析和构造，含 Options TLV
- **FR-6:** 系统必须支持 VLAN Tag (802.1Q) 和 QinQ (802.1ad) 的解析和构造
- **FR-7:** 系统必须支持 VXLAN（RFC 7348）隧道封装报文的递归解析和构造
- **FR-8:** 系统必须支持 GRE（RFC 2784）隧道封装报文的解析和构造，含条件字段（Checksum/Key/Seq 按标志位出现）
- **FR-9:** 系统必须提供通用 TLV Options 解析/构造框架，供 DHCP/NDP/DNS EDNS 等协议复用
- **FR-10:** 系统必须提供可注册的协议发现（Dissector Registry）机制，基于端口号、协议号、TPID 等启发式规则自动识别上层协议
- **FR-11:** Dissect 必须支持隧道协议的递归解析（VXLAN → Inner Ethernet → Inner IP → ...），深度不限
- **FR-12:** 新协议必须完全覆盖序列化（Build）和反序列化（Dissect）两个方向
- **FR-13:** 每个新协议的构造输出必须与 Scapy/Wireshark 逐字节对账
- **FR-14:** 所有新增导出 API 必须有完整的 Go doc 注释

## 5. 非目标（Out of Scope）

- **不包含** HTTP/1.1、HTTP/2、TLS/SSL 协议解析（Phase 1C 候选）
- **不包含** DHCPv6（Phase 1C 候选）
- **不包含** DNS-over-HTTPS / DNS-over-TLS
- **不包含** IPv6 分段重组（仅解析 Fragment Header 字段，不实现缓冲区重组逻辑）
- **不包含** IPv6 扩展头部的 Authentication Header (AH) 和 Encapsulating Security Payload (ESP)
- **不包含** VXLAN-GPE (Generic Protocol Extension)
- **不包含** GRE 的 PPTP 变体（Enhanced GRE）
- **不包含** Geneve、NVGRE 等其他隧道协议
- **不包含** Windows 平台支持
- **不包含** DHCP 中继代理（Relay Agent）的特殊处理
- **不包含** DNS zone transfer (AXFR/IXFR) 的完整实现
- **不包含** 交互式 Shell 或图形化界面
- **不包含** `scapy/contrib` 下的社区贡献协议

## 6. 设计考虑

### 协议分层与组织

```
pkg/layers/
├── dns/             # US-001: DNS (新增)
├── dhcp/            # US-002: DHCP (新增)
├── ipv6/            # US-003: IPv6 (新增)
├── icmpv6/          # US-003: ICMPv6 (新增)
├── ndp/             # US-003: NDP (新增)
├── dot1q/           # US-004: 802.1Q VLAN (新增)
├── vxlan/           # US-005: VXLAN (新增)
├── gre/             # US-005: GRE (新增)
├── ethernet.go      #  现有
├── arp.go           #  现有
├── ip.go            #  现有 (IPv4)
├── tcp.go           #  现有
├── udp.go           #  现有
├── icmp.go          #  现有
├── raw.go           #  现有
├── checksum.go      #  现有
└── init.go          #  现有 (扩展注册)
```

### Dissector Registry 设计

```go
// 注册示例
packet.RegisterDissector("DNS", func(data []byte) (string, int, error) {
    // DNS 头部最小 12 字节，检查 QR 位等
})
packet.RegisterHeuristic("udp.dport", 53, "DNS")
packet.RegisterHeuristic("udp.dport", 67, "DHCP")
packet.RegisterHeuristic("ether.type", 0x8100, "Dot1Q")
packet.RegisterHeuristic("ip.proto", 47, "GRE")  // IP proto 47 = GRE
```

### TLV 框架设计

```go
type TLVOption struct {
    Type   uint8
    Length uint8   // 值部分的长度
    Value  []byte
}

type TLVParser struct {
    opts []TLVOption
}

func ParseTLV(data []byte) (*TLVParser, error)
func (t *TLVParser) Get(typ uint8) *TLVOption
func (t *TLVParser) All() []TLVOption
func BuildTLV(opts []TLVOption) []byte
```

### API 兼容性承诺

- Phase 1A 的所有导出符号不变（`goscapy.NewEthernet()`、`goscapy.EtherIPICMP()` 等保持不变）
- 现有 `packet.Dissect(raw, packet.DissectEthernet)` 签名继续支持
- Builder 的 `Over()` 和 `Build()` 方法签名不变
- `LayerBuilder` 接口不变

## 7. 技术考虑

### DNS 名称压缩

DNS 使用指针压缩（前 2 bits 为 `11` 表示指针，后 14 bits 为偏移量），解析时需维护完整的报文缓冲区以解引用指针，且需防止指针循环（追踪已访问偏移量，最大跳转次数限制）。

### IPv6 伪头部 Checksum

IPv6 的上层协议（TCP/UDP/ICMPv6）checksum 计算包含 IPv6 伪头部（SrcIP + DstIP + PayloadLength + NextHeader），与 IPv4 不同。需在 checksum 工具函数中新增 IPv6 伪头部的生成逻辑。

### 隧道协议的递归解析

VXLAN 和 GRE 都封装了内层报文，Dissect 需要在解析到隧道层后递归调用自身解析内层协议栈。最大递归深度应有限制（建议 8 层），防止畸形报文导致栈溢出。

### 零依赖约束

- DNS 名称压缩、TLV 解析、IPv6 扩展头部链均为纯 Go 实现
- Checksum 计算（含 IPv6 伪头）使用 `encoding/binary` 实现 16 位累加
- 无需 `gopacket`、`libpcap` 等外部包

### 测试策略

- 每个协议至少 3 个测试夹具：最小合法报文、典型报文（含多 Options）、边界报文（空 Options、最大名称压缩深度）
- 用 Scapy/Python 脚本生成测试夹具 `.pcap` 文件存入 `testdata/` 目录
- 序列化对账：Go 构造 → `[]byte` → 与 Scapy `bytes(pkt)` 逐字节比对
- 反序列化对账：读取 `.pcap` → Go 解析 → 字段值与 Scapy `pkt.show()` 比对
- 递归解析上限测试：构造 10 层 VXLAN 嵌套，验证解析在第 8 层停止并报错

## 8. 成功指标

- 8 个用户故事全部验收通过
- 8 种新协议（DNS/DHCP/IPv6/ICMPv6/NDP/Dot1Q/VXLAN/GRE）序列化输出与 Scapy/Wireshark 逐字节一致
- 反序列化后字段值与 Wireshark 解析结果一致
- 隧道协议递归解析至少支持 8 层嵌套
- `go test ./...` 和 `go vet ./...` 全绿
- Phase 1A 现有 API 无破坏性变更（`go test ./pkg/...` 在 1A 测试上全绿）
- Go doc 覆盖所有新增导出符号

## 9. 未决问题

- DNS 资源记录类型的覆盖范围：是否只需 8 种常见类型（A/AAAA/NS/CNAME/PTR/MX/SOA/TXT），还是需要支持 SRV、CAA、TLSA 等更多类型？
- DHCP Options 的覆盖范围：是否只需上述 12 种常见 Options，还是需要支持 Vendor Class ID (60)、Client ID (61) 等？
- IPv6 扩展头部：Routing Header Type 0（已被 RFC 5095 废弃）是否需要解析？还是只支持 Routing Type 2（移动 IPv6）？
- VXLAN 是否需要支持 GBP (Group-Based Policy) 扩展？
- VLAN 优先级 (PCP) 的默认值——Builder 中默认 PCP=0 (Best Effort) 是否合理？