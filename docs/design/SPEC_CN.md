# SPEC: goscapy

> 逆向工程规范文档 — 基于 commit `f93567b` 生成于 2026-05-21

## 1. 概述

### 1.1 项目定位

goscapy 是一个纯 Go 语言编写的网络包构造、解析、发送、接收和嗅探库——相当于 Python Scapy 的 Go 语言版本。它提供符合 Go 语言惯例的类型安全 API，包含流式 Builder 和一行式快捷函数。目标用户为网络工程师、安全研究员以及构建网络工具（端口扫描器、包生成器、网络监控、协议测试框架）的 Go 开发者。

### 1.2 核心能力

- **构建** 任意协议栈，通过流式 Builder API 或一行式快捷函数
- **解析** 原始字节为结构化、带类型的包对象，支持自动协议检测
- **发送** L2（完整以太网帧）或 L3（IP 层，OS 处理链路层）数据包，通过 raw socket
- **接收** 来自网络接口的数据包，支持 BPF 过滤
- **嗅探** 实时流量，支持回调和 channel 两种 API，支持 BPF 过滤器
- **读写 pcap/pcapng** 文件，纯 Go 实现（无 libpcap 依赖）
- **重组** IP 分片为完整数据包
- **限速** 通过令牌桶算法控制发包速率
- **零拷贝** 发送支持（Linux MSG_ZEROCOPY）
- **批量** 发送/接收（sendmmsg/recvmmsg）
- **io_uring** raw socket I/O（Linux）
- **AF_PACKET Fanout** 多核并行抓包（Linux）
- **AF_XDP (XSK)** 零拷贝/拷贝模式包 I/O（Linux）
- **Packet MMAP** TPACKET_V3 环形缓冲区（Linux）
- **自动计算** IP/TCP/UDP/ICMP 校验和、长度及层间绑定

### 1.3 架构风格

单模块 Go 库，分层内部架构：**字段类型 → 协议层定义 → 包组装/解析 → Builder/快捷函数 API → 平台相关 I/O**。公开 API 分为 8 个包：`goscapy`（Builder/快捷函数）、`packet`（核心类型）、`layers`（协议定义）、`fields`（字段类型系统）、`sendrecv`（raw socket I/O）、`sniff`（抓包）、`pcap`（文件 I/O）和 `reassembly`（IP 分片重组）。

---

## 2. 技术栈

| 层级 | 技术 | 版本 |
|-------|-----------|---------|
| 语言 | Go | 1.26+ |
| 外部依赖 | golang.org/x/sys | v0.44.0 |
| 构建 | `go build` | — |
| 测试 | `go test`（标准库） | — |
| 代码检查 | golangci-lint | — |
| 格式化 | gofmt + goimports | — |
| 可选工具 | tcpdump（BPF 过滤器编译） | 任意版本 |
| 许可证 | MIT | — |

---

## 3. 项目结构

```
goscapy/
├── pkg/
│   ├── fields/            # 字段类型系统 — 序列化/反序列化原语
│   │   ├── field.go       #   Field 接口、Desc 元数据
│   │   ├── types.go       #   Byte/Short/Int/Long 字段、MAC/IP/IPv6、Str、BitField 等
│   │   ├── tlv.go         #   TLV 选项解析（DHCP、NDP、DNS EDNS）
│   │   └── *_test.go      #   单元测试
│   ├── packet/            # 核心包/协议层抽象
│   │   ├── packet.go      #   Packet（有序协议层栈）、Push/Insert/GetLayer/Build
│   │   ├── layer.go       #   Layer（协议名 + 字段定义 + 值映射）
│   │   ├── build.go       #   BuildHook 系统 — 四阶段序列化及派生字段计算
│   │   ├── dissect.go     #   解析引擎 — 递归协议解析与启发式检测
│   │   ├── binding.go     #   层间字段绑定（自动设置下层协议类型）
│   │   └── *_test.go      #   单元测试
│   ├── layers/            # 协议层定义及构建/解析注册
│   │   ├── init.go        #   集中注册：绑定、构建钩子、解析器、启发式规则
│   │   ├── ethernet.go    #   以太网帧（dst、src、type）
│   │   ├── arp.go         #   ARP 消息（hwtype、ptype、op、hwsrc/psrc、hwdst/pdst）
│   │   ├── ip.go          #   IPv4 头部（verihl、tos、len、id、frag、ttl、proto、chksum、src、dst）
│   │   ├── ipv6.go        #   IPv6 头部 + 扩展头（Hop-by-Hop、Routing、Fragment、DestOpts）
│   │   ├── tcp.go         #   TCP 头部（端口、seq/ack、dataofs、flags、window、chksum、urgptr）
│   │   ├── tcp_options.go #   TCP 选项解析/构建（MSS、WScale、SACK、Timestamp、NOP）
│   │   ├── udp.go         #   UDP 头部（端口、len、chksum）
│   │   ├── icmp.go        #   ICMP 头部（type、code、chksum、id、seq）
│   │   ├── icmpv6.go      #   ICMPv6 基础头部 + Echo 子层
│   │   ├── ndp.go         #   NDP 消息（RS/RA/NS/NA/Redirect）及 TLV 选项
│   │   ├── raw.go         #   Raw 载荷层
│   │   ├── checksum.go    #   IP/TCP/UDP/ICMP/ICMPv6 校验和计算
│   │   ├── helpers.go     #   校验和用 IP 地址解析辅助函数
│   │   ├── dns/           #   DNS 消息层（头部 + 问题/资源记录段）
│   │   ├── dhcp/          #   DHCP/BOOTP 层（含 TLV 选项）
│   │   ├── dot1q/         #   802.1Q VLAN 标签（TPID、PCP、DEI、VID）
│   │   ├── vxlan/         #   VXLAN 封装（flags、VNI）
│   │   ├── gre/           #   GRE 隧道（flags、version、protocol、可选的 key/seq/chksum）
│   │   ├── lldp/          #   LLDP（结构化 LLDPDU，含 Chassis/Port/TTL/System TLV）
│   │   ├── erspan/        #   ERSPAN v3 封装
│   │   ├── ospf/          #   OSPFv2 头部
│   │   ├── bgp/           #   BGP 通用头部
│   │   └── quic/          #   QUIC Long Header
│   ├── goscapy/           # 顶层公开 API — Builder 和快捷函数
│   │   ├── goscapy.go     #   Builder 类型：EthernetBuilder、IPBuilder、TCPBuilder 等
│   │   ├── shortcuts.go   #   一行式函数：EtherIPICMP、EtherARP、IPTCPBGP 等
│   │   └── goscapy_test.go
│   ├── sendrecv/          # Raw socket 包 I/O（平台相关）
│   │   ├── sendrecv.go    #   公开 API：Send、Sendp、Recv、SendRecv、Sr、Sr1、Srp、Srp1
│   │   ├── sendrecv_darwin.go  # macOS：BPF 实现 L2，AF_INET/AF_INET6 实现 L3，IPv6 unicast hops
│   │   ├── sendrecv_linux.go   # Linux：AF_PACKET 实现 L2，AF_INET/AF_INET6+HDRINCL 实现 L3
│   │   ├── rawconn.go     #   RawConn — 直接 raw socket，支持零拷贝和 RecvInto
│   │   ├── batch.go       #   BatchConn — sendmmsg/recvmmsg 批量操作
│   │   ├── ratelimit.go   #   TokenBucketLimiter — 速率控制发送
│   │   ├── fanout_linux.go    # AF_PACKET Fanout (PACKET_FANOUT) 多核抓包
│   │   ├── iface.go       #   网络接口查询辅助函数
│   │   ├── zerocopy_*.go  #   MSG_ZEROCOPY 支持（Linux）
│   │   ├── mmap_*.go      #   TPACKET_V3 环形缓冲区（Linux）
│   │   ├── uring_*.go     #   io_uring raw socket（Linux）
│   │   ├── xdp_*.go       #   AF_XDP XSK（Linux）
│   │   ├── batch_*.go     #   平台相关批量实现
│   │   ├── filter_*.go    #   平台相关 BPF 过滤器附加
│   │   ├── doc.go         #   包文档
│   │   └── *_test.go
│   ├── sniff/             # 带 BPF 过滤的包捕获
│   │   ├── sniff.go       #   Sniff（回调）、SniffChan（channel）、SniffConfig
│   │   ├── filter.go      #   通过 tcpdump -dd 编译过滤器，parseDDOutput
│   │   └── *_test.go
│   ├── pcap/              # 纯 Go pcap/pcapng 文件读写器
│   │   ├── reader.go      #   Reader：自动检测格式，读取 pcap/pcapng，链路类型分发
│   │   ├── writer.go      #   Writer：写入 pcap 全局头 + 每包记录
│   │   └── pcap_test.go
│   └── reassembly/        # IP 分片重组
│       ├── reassembly.go  #   Reassembler：提交分片、尝试重组、GC、DoS 防护
│       └── reassembly_test.go
├── examples/              # 40 个示例程序（01 至 40）
├── docs/                  # 项目网站（HTML/CSS/JS，中英文双语）
├── tasks/                 # 功能规划的 PRD 文档
├── go.mod / go.sum
├── Makefile
├── README.md / README_CN.md
└── LICENSE (MIT)
```

---

## 4. 数据模型

### 4.1 核心实体

#### 4.1.1 Field（`fields.Field` 接口）

最基础的构建块。每个字段代表协议头部的一个字段，知道如何序列化和反序列化自身。

```
Field interface {
    Name() string
    FixedSize() int      // 变长字段返回 0
    DefaultVal() any
    Pack(val any) ([]byte, error)
    Unpack(b []byte) (val any, consumed int, err error)
}
```

**具体字段类型（共 19 种）：**

| 类型 | 线长 | Go 类型 | 说明 |
|------|-----------|---------|-------|
| `ByteField` | 1 | `uint8` | 无符号字节 |
| `XByteField` | 1 | `uint8` | 十六进制显示字节 |
| `ShortField` | 2 | `uint16` | 大端序 |
| `LEShortField` | 2 | `uint16` | 小端序 |
| `ThreeBytesField` | 3 | `uint32` | 大端序，最大 0xFFFFFF |
| `IntField` | 4 | `uint32` | 大端序无符号 |
| `SignedIntField` | 4 | `int32` | 大端序有符号 |
| `LEIntField` | 4 | `uint32` | 小端序无符号 |
| `LongField` | 8 | `uint64` | 大端序 |
| `LELongField` | 8 | `uint64` | 小端序 |
| `BitField` | 0 | `uint8` | 1-8 位；由外层位组打包 |
| `MACField` | 6 | `net.HardwareAddr` / `string` / `[]byte` | MAC 地址 |
| `IPField` | 4 | `net.IP` / `string` | IPv4 地址 |
| `IPv6Field` | 16 | `net.IP` / `string` / `[]byte` | IPv6 地址 |
| `StrField` | 0 | `string` / `[]byte` | 变长，消费剩余全部字节 |
| `StrLenField` | 0 | `string` / `[]byte` | 长度由另一个字段指定 |
| `StrFixedField` | N | `string` / `[]byte` | 固定 N 字节，不足补零 |
| `PacketField` | 0 | `[]byte` | 嵌套子包 |
| `ConditionalField` | 可变 | 包装任意 Field | 根据运行时值决定是否激活 |

#### 4.1.2 Layer（`packet.Layer`）

协议头部实例。包含协议名称、有序字段定义和运行时字段值。

```
Layer {
    proto  string           // 例如 "Ethernet"、"IP"、"TCP"
    fields []fields.Field   // 有序字段定义
    values map[string]any   // 运行时字段名 → 值
}
```

关键操作：
- `Get(name) / Set(name, val)` — 读写字段值
- `SerializeFields()` — 将所有激活字段打包为字节（原始序列化）
- `ParseFields(data)` — 从字节解析为字段值（解析路径）
- `Over(upper)` — 堆叠上层协议，应用绑定规则，返回 Packet

#### 4.1.3 Packet（`packet.Packet`）

形成完整网络包的有序 Layer 栈。

```
Packet {
    layers []*Layer   // [Ethernet, IP, TCP, Raw]
}
```

关键操作：
- `Push(layer)` — 在顶部添加层
- `Insert(layer)` — 在底部添加层
- `InsertAfter(proto, layer)` — 在匹配层之后插入
- `GetLayer(proto) / HasLayer(proto)` — 层查找
- `Sync()` — 重新应用所有绑定规则
- `Build() / BuildFrom(startIdx)` — 四阶段序列化
- `Copy()` — 浅拷贝

#### 4.1.4 TCPOption（`layers.TCPOption`）

以 Kind-Length-Value 格式表示单个 TCP 选项。

```
TCPOption {
    Kind   uint8    // IANA 分配：MSS(2)、WScale(3)、SACKPerm(4)、SACK(5)、Timestamp(8)、NOP(1)、EOL(0)
    Length uint8    // 总长度（含 Kind 和 Length）
    Data   []byte   // 选项特定载荷（Length - 2 字节）
}
```

#### 4.1.5 TLVOption（`fields.TLVOption`）

通用 Type-Length-Value 选项，适用于 DHCP、NDP、DNS EDNS 等协议。

```
TLVOption {
    Type   uint8
    Length uint8
    Value  []byte
}
```

#### 4.1.6 BPFInstruction（`sendrecv.BPFInstruction`）

单条经典 BPF 指令，对应 `struct bpf_insn` / `struct sock_filter`。

```
BPFInstruction {
    Code uint16
    Jt   uint8
    Jf   uint8
    K    uint32
}
```

#### 4.1.7 PacketRecord（`pcap.PacketRecord`）

来自 pcap/pcapng 文件的带元数据的捕获包。

```
PacketRecord {
    Timestamp  time.Time
    CaptureLen uint32
    OrigLen    uint32
    Data       []byte
    LinkType   uint32
}
```

#### 4.1.8 FragGroup / Fragment（`reassembly`）

IP 分片重组的内部结构。以 `(src_ip, dst_ip, id, proto)` 为键。通过覆盖位图跟踪分片，超时后过期分组（默认 30s），限制并发分组数（默认 1024）以防范 DoS 攻击。

### 4.2 状态转换

**Packet Build（四阶段序列化）：**

```
阶段 1：原始序列化所有层（校验和为零，长度为默认值）
阶段 2：计算累积字节大小（自底向上）
阶段 3：自底向上调用 BuildHook 计算派生字段（校验和、长度）
         每个钩子接收上层字节，设置计算字段，重新序列化
阶段 4：返回拼接后的线格式字节
```

**Packet Dissect（递归协议解析）：**

```
1. 从已知协议开始（来自 startFn 或前一层的 key field）
2. 通过注册的工厂创建层，调用 ParseFields
3. 计算实际头部大小（固定大小或通过 HeaderSizeFunc）
4. 调用 PostParseHook 处理变长字段（如 TCP options）
5. 将层压入包中
6. 如果是隧道协议 → 递归解析内层载荷
7. 通过 key field → next-layer 映射解析下一协议
8. 剩余字节作为 Raw 载荷
9. 最大递归深度：8（隧道嵌套保护）
```

---

## 5. API 接口

### 5.1 Builder API（包 `goscapy`）

每种协议有一个 `*Builder` 类型，流式 setter 方法返回 builder 自身以支持链式调用。所有 builder 实现 `LayerBuilder` 接口（暴露 `.Layer()` 方法）。链式调用以 `.Build()` 结束，返回 `([]byte, error)`。

| Builder | 工厂函数 | 关键 Setter | 协议栈位置 |
|---------|---------|-------------|---------------------|
| `EthernetBuilder` | `NewEthernet()` | `DstMAC`、`SrcMAC`、`Type`、`Over` | 基础层 |
| `IPBuilder` | `NewIP()` | `SrcIP`、`DstIP`、`TTL`、`Proto`、`ID`、`Over` | 基础层 |
| `IPv6Builder` | `NewIPv6()` | `SrcIP`、`DstIP`、`NH`、`HLim`、`TC`、`FL`、`Over` | 基础层 |
| `ICMPBuilder` | `NewICMP()` | `Type`、`Code`、`ID`、`Seq` | 上层 |
| `ICMPv6Builder` | `NewICMPv6()` | `Type`、`Code` | 上层 |
| `TCPBuilder` | `NewTCP()` | `SrcPort`、`DstPort`、`Flags`、`Seq`、`Ack`、`Window`、`Over` | 上层 |
| `UDPBuilder` | `NewUDP()` | `SrcPort`、`DstPort`、`Over` | 上层 |
| `ARPBuilder` | `NewARP()` | `Op`、`SrcMAC`、`SrcIP`、`DstMAC`、`DstIP`、`Over` | 上层 |
| `DNSBuilder` | `NewDNS()` | `ID`、`Flags`、`Questions`、`Data` | 上层 |
| `DHCPBuilder` | `NewDHCP()` | `Op`、`XID`、`CIAddr`、`YIAddr`、`MessageType`、`Options` | 上层 |
| `Dot1QBuilder` | `NewDot1Q()` | `VID`、`PCP`、`DEI`、`Type`、`TPID`、`Over` | 中间层 |
| `VXLANBuilder` | `NewVXLAN()` | `VNI`、`Flags`、`Over` | 中间层 |
| `GREBuilder` | `NewGRE()` | `ProtocolType`、`Key`、`Seq`、`SetChecksum`、`Over` | 中间层 |
| `LLDPBuilder` | `NewLLDPLayer()` | `TLVData`、`LLDPDU` | 上层 |
| `ERSPANBuilder` | `NewERSPANLayer()` | `FromERSPAN` | 中间层 |
| `OSPFBuilder` | `NewOSPFLayer()` | `RouterID`、`AreaID`、`Type`、`Over` | 上层 |
| `BGPBuilder` | `NewBGPLayer()` | `Type`、`Over` | 上层 |
| `QUICBuilder` | `NewQUICLayer()` | `Version`、`DCID`、`SCID`、`Over` | 上层 |

Builder 堆叠示例：
```go
pkt, _ := goscapy.NewEthernet().
    SrcMAC("aa:bb:cc:dd:ee:ff").DstMAC("ff:ff:ff:ff:ff:ff").
    Over(goscapy.NewIP().SrcIP("10.0.0.1").DstIP("10.0.0.2")).
    Over(goscapy.NewTCP().SrcPort(1234).DstPort(80).Flags(layers.TCPSyn)).
    Build()
```

### 5.2 快捷函数（包 `goscapy`）

构建并序列化常见协议栈的一行式函数，使用合理默认值。

| 函数 | 协议栈 | 签名 |
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

### 5.3 解析 API（包 `packet`）

| 函数 | 说明 |
|----------|-------------|
| `Dissect(raw []byte, startFn func([]byte) (string, error)) (*Packet, error)` | 从未知起始协议解析 |
| `DissectByProto(raw []byte, firstProto string) (*Packet, error)` | 从已知协议名解析 |

**解析入口点：**
- `packet.DissectEthernet` — 从以太网开始（兼容 `Dissect`）
- `"Ethernet"`、`"IP"`、`"IPv6"`、`"ARP"` 等 — 用于 `DissectByProto`

### 5.4 发送/接收 API（包 `sendrecv`）

#### 核心函数

| 函数 | 层 | 说明 |
|----------|-------|-------------|
| `Send(pkt, iface)` | L3 | IP 层发送（OS 处理 L2） |
| `Sendp(pkt, iface)` | L2 | 发送完整以太网帧 |
| `Recv(iface, timeout)` | — | 打开接收器，读取一个包，关闭 |
| `SendRecv(pkt, iface, timeout)` | L3 | 发送后收集所有响应 |
| `SendRecv1(pkt, iface, timeout)` | L3 | 发送后返回第一个响应 |
| `SendRecvFiltered(pkt, iface, timeout, instructions)` | L3 | 带 BPF 过滤的 SendRecv |
| `SendRecvFiltered1(pkt, iface, timeout, instructions)` | L3 | 带 BPF 过滤的 SendRecv1 |
| `Sr(pkt, iface, timeout, match)` | L3 | 发送 + 匹配响应（对应 Scapy sr()） |
| `Sr1(pkt, iface, timeout, match)` | L3 | 发送 + 首个匹配（对应 Scapy sr1()） |
| `Srp(pkt, iface, timeout, match)` | L2 | Sendp + 匹配响应（对应 Scapy srp()） |
| `Srp1(pkt, iface, timeout, match)` | L2 | Sendp + 首个匹配（对应 Scapy srp1()） |

#### Receiver 接口

```go
type Receiver interface {
    Recv(timeout time.Duration) (*packet.Packet, error)
    RecvInto(buf []byte, timeout time.Duration) (*packet.Packet, int, error)
    Close() error
}
```

#### 高级 I/O

| 类型 | 说明 |
|------|-------------|
| `RawConn` | 直接 raw socket 连接；`Send(data, dst)`、`Recv(timeout)`、`RecvInto(buf, timeout)` |
| `BatchConn` | 通过 sendmmsg/recvmmsg 批量发送/接收 |
| `TokenBucketLimiter` | 速率控制：`Wait(ctx)`，配合 `SendWithLimiter`/`SendpWithLimiter` 使用 |
| `SendRaw(proto, data, dst)` | 一次性 raw socket 发送 |
| `RecvRaw(proto, timeout)` | 一次性 raw socket 接收 |

#### 匹配 API

```go
type MatchFunc func(sent, received *packet.Packet) bool

// DefaultMatch 返回包含协议特定启发式匹配规则的 MatchFunc：
//   ICMP：Echo Reply 且 id 匹配，或来自目标 IP 的错误类型
//   TCP：端口互换，SYN→SYN-ACK 且 ack==seq+1
//   UDP：端口互换
//   DNS：事务 ID 匹配
//   ARP：is-at 回复且 IP 互换
//   DHCP：xid 匹配，BOOTREPLY
func DefaultMatch(sent *packet.Packet) MatchFunc
```

### 5.5 嗅探 API（包 `sniff`）

```go
type SniffConfig struct {
    Iface        string
    Filter       string                    // BPF 表达式（如 "tcp port 80"）
    Instructions []sendrecv.BPFInstruction // 预编译 BPF
    Count        int                       // 最大包数（0=无限）
    Timeout      time.Duration             // 总时长（0=无超时）
}

type SniffHandler func(pkt *packet.Packet) bool

func Sniff(cfg SniffConfig, handler SniffHandler) error
func SniffChan(cfg SniffConfig) (<-chan *packet.Packet, func())
func CompileFilter(filter string) ([]sendrecv.BPFInstruction, error)
func CompileFilterOnIface(filter, iface string) ([]sendrecv.BPFInstruction, error)
```

### 5.6 Pcap API（包 `pcap`）

```go
// 读取
func NewReader(r io.Reader) (*Reader, error)
func (rd *Reader) ReadPacket() (*PacketRecord, error)
func (rd *Reader) Packets(errp *error) <-chan *PacketRecord
func (rd *Reader) LinkType() uint32
func (r *PacketRecord) Packet() (*packet.Packet, error)

// 写入
func NewWriter(w io.Writer, linkType uint32, snapLen uint32) (*Writer, error)
func (wr *Writer) WritePacket(data []byte, ts time.Time) error
func (wr *Writer) WriteRecord(rec *PacketRecord) error
func (wr *Writer) WritePkt(pkt *packet.Packet) error
```

链路类型：`LinkTypeNull`（0）、`LinkTypeEthernet`（1）、`LinkTypeRaw`（101）、`LinkTypeIPv4`（228）、`LinkTypeIPv6`（229）。

同时支持 pcap（基于魔数检测字节序 + 纳秒/微秒精度）和 pcapng（SHB/IDB/EPB/SPB 块、多接口、自动检测）。

### 5.7 重组 API（包 `reassembly`）

```go
type Reassembler struct { ... }

func New(opts ...Option) *Reassembler
func WithTimeout(d time.Duration) Option
func WithMaxGroups(n int) Option
func (r *Reassembler) Submit(pkt *packet.Packet) *packet.Packet
func (r *Reassembler) Stats() int
func (r *Reassembler) Close()
```

`Submit` 等待更多分片时返回 nil，分片组完整时返回重组后的包。非分片包原样透传。

### 5.8 协议层定义（包 `layers`）

所有协议层构造函数返回 `*packet.Layer`：

| 构造函数 | 协议 | 字段 |
|-------------|----------|--------|
| `NewEthernet()` | Ethernet | dst(MAC)、src(MAC)、type(uint16) |
| `NewARP()` | ARP | hwtype、ptype、hwlen、plen、op、hwsrc、psrc、hwdst、pdst |
| `NewIP()` | IPv4 | verihl、tos、len、id、frag、ttl、proto、chksum、src、dst |
| `NewIPv6()` | IPv6 | ver_tc_fl、plen、nh、hlim、src、dst |
| `NewICMP()` | ICMP | type、code、chksum、id、seq |
| `NewTCP()` | TCP | sport、dport、seq、ack、dataofs、flags、window、chksum、urgptr、options |
| `NewUDP()` | UDP | sport、dport、len、chksum |
| `NewICMPv6()` | ICMPv6 | type、code、chksum、body |
| `NewRaw()` | Raw | load |

加上扩展头（`NewIPv6HopByHop`、`NewIPv6Routing`、`NewIPv6Fragment`、`NewIPv6DestOpts`）、NDP 消息（5 种类型）以及子协议（DNS、DHCP、Dot1Q、VXLAN、GRE、LLDP、ERSPAN、OSPF、BGP、QUIC）——各自位于 `layers/` 下的子包中。

### 5.9 字段构造函数（包 `fields`）

19 种字段构造函数：`NewByteField`、`NewXByteField`、`NewShortField`、`NewLEShortField`、`NewThreeBytesField`、`NewIntField`、`NewSignedIntField`、`NewLEIntField`、`NewLongField`、`NewLELongField`、`NewBitField`、`NewMACField`、`NewIPField`、`NewIPv6Field`、`NewStrField`、`NewStrLenField`、`NewStrFixedField`、`NewPacketField`、`NewConditionalField`。

### 5.10 TLV 工具（包 `fields`）

```go
func ParseTLV(data []byte) ([]TLVOption, error)
func BuildTLV(opts []TLVOption) []byte
func (o *TLVOption) Nested() ([]TLVOption, error)
func GetTLV(opts []TLVOption, typ uint8) *TLVOption
func GetAllTLV(opts []TLVOption, typ uint8) []TLVOption
```

---

## 6. 支持的协议

| 层 | 协议 | 构建 | 解析 |
|-------|-----------|:-----:|:-------:|
| 链路层 | Ethernet | Y | Y |
| 链路层 | 802.1Q VLAN (Dot1Q) | Y | Y |
| 链路层 | ARP | Y | Y |
| 链路层 | LLDP | Y | Y |
| 网络层 | IPv4 | Y | Y |
| 网络层 | IPv6 | Y | Y |
| 网络层 | IPv6 Hop-by-Hop Options | Y | Y |
| 网络层 | IPv6 Routing Header | Y | Y |
| 网络层 | IPv6 Fragment Header | Y | Y |
| 网络层 | IPv6 Destination Options | Y | Y |
| 网络层 | ICMP | Y | Y |
| 网络层 | ICMPv6 | Y | Y |
| 网络层 | ICMPv6 Echo | Y | Y |
| 网络层 | NDP（RS/RA/NS/NA/Redirect） | Y | Y |
| 网络层 | GRE | Y | Y |
| 网络层 | VXLAN | Y | Y |
| 网络层 | ERSPAN v3 | Y | Y |
| 网络层 | OSPFv2 | Y | Y |
| 传输层 | TCP（含选项） | Y | Y |
| 传输层 | UDP | Y | Y |
| 传输层 | QUIC Long Header | Y | Y |
| 应用层 | DNS | Y | Y |
| 应用层 | DHCP/BOOTP | Y | Y |
| 应用层 | BGP | Y | Y |
| 载荷 | Raw | Y | Y |

---

## 7. 配置

goscapy 采用极简配置——没有配置文件或环境变量。所有配置均为编程式：

| 参数 | 类型 | 默认值 | 配置位置 |
|-----------|------|---------|-------|
| `SniffConfig.Iface` | `string` | **（必填）** | `sniff.Sniff()` |
| `SniffConfig.Filter` | `string` | `""`（无过滤） | `sniff.Sniff()` |
| `SniffConfig.Instructions` | `[]BPFInstruction` | `nil` | `sniff.Sniff()` |
| `SniffConfig.Count` | `int` | `0`（无限） | `sniff.Sniff()` |
| `SniffConfig.Timeout` | `time.Duration` | `0`（无超时） | `sniff.Sniff()` |
| `Reassembler.timeout` | `time.Duration` | `30s` | `reassembly.WithTimeout()` |
| `Reassembler.maxGroups` | `int` | `1024` | `reassembly.WithMaxGroups()` |
| `TokenBucketLimiter.pps` | `int` | **（必填）** | `NewTokenBucketLimiter()` |
| `TokenBucketLimiter.burst` | `int` | `max(1, min(pps/10, 100))` | `NewTokenBucketLimiter()` |
| `pcap.Writer.snapLen` | `uint32` | `65535`（为 0 时） | `pcap.NewWriter()` |
| BPF 缓冲区大小 (Darwin) | `uint32` | `32768` (32 KB) | `openBPFDevice()` 硬编码 |
| 最大隧道深度 | `int` | `8` | `dissect()` 硬编码 |
| 最大重组大小 | `int` | `65535` | `reassembly` 硬编码 |

### 外部依赖

| 服务/工具 | 用途 | 缺失影响 |
|-------------|---------|----------------|
| `tcpdump` | BPF 过滤器字符串编译（`sniff.CompileFilter`） | 可选；可直接传入预编译 BPF 指令 |
| `golang.org/x/sys` | Unix 系统调用封装（`unix.Poll`、`unix.IPV6_HDRINCL`） | Linux 平台必需 |
| Root/管理员权限 | Raw socket 操作 | 所有发送/接收/嗅探操作必需 |
| `/dev/bpf*` (macOS) | L2 包捕获/发送的 BPF 设备 | macOS L2 操作必需 |
| 网络接口 | 发送/接收目标 | 所有 I/O 操作必需 |

---

## 8. 平台支持

| 特性 | macOS (Darwin) | Linux |
|---------|:---:|:---:|
| L3 发送 (IPv4) | AF_INET + IP_HDRINCL | AF_INET + IP_HDRINCL |
| L3 发送 (IPv6) | AF_INET6 + IPV6_UNICAST_HOPS（无 HDRINCL） | AF_INET6 + IPV6_HDRINCL |
| L2 发送 | BPF 写入 /dev/bpf* | AF_PACKET sendto |
| 接收 | BPF 读取 /dev/bpf*（select，即时模式） | AF_PACKET recvfrom（poll） |
| BPF 过滤 | BIOCSETF ioctl | SO_ATTACH_FILTER setsockopt |
| 混杂模式 | BIOCPROMISC ioctl | 未显式设置 |
| 回环接口名 | `lo0` | `lo` |
| MSG_ZEROCOPY | 不支持 | 支持 |
| 批量 sendmmsg/recvmmsg | 不支持 | 支持 |
| io_uring | 不支持 | 支持 |
| TPACKET_V3 MMAP | 不支持 | 支持 |
| AF_PACKET Fanout | 不支持 | 支持 |
| AF_XDP XSK | 不支持 | 支持 |

---

## 9. 注册/扩展系统

库通过注册模式实现可扩展性。所有注册在 `init()` 函数中完成。

### 9.1 构建钩子注册

```go
packet.RegisterBuildHook(proto string, hook BuildHook)
```

构建钩子在 `Packet.Build()` 期间计算派生字段（校验和、长度）。当前已注册：`IP`、`IPv6`、`ICMPv6`、`ICMP`、`TCP`、`UDP`。

### 9.2 协议层注册（用于解析）

```go
packet.RegisterLayer(proto string, factory LayerFactory)           // 工厂函数创建空层
packet.RegisterKeyField(proto, fieldName string)                   // 哪个字段标识上层协议
packet.RegisterNextLayer(proto string, keyValue uint64, nextProto) // 字段值 → 下一协议
packet.RegisterHeuristic(lowerProto, field string, value any, nextProto) // 便捷组合
packet.RegisterHeaderSizeFunc(proto string, fn HeaderSizeFunc)     // 变长头部（IP、TCP、扩展头）
packet.RegisterPostParseHook(proto string, hook PostParseHook)     // 解析额外头部字节（TCP options）
packet.RegisterDissector(proto string, fn DissectorFunc)           // 从原始字节识别协议
packet.RegisterTunnelPayload(proto, innerProto string)             // 隧道 → 递归解析
```

### 9.3 绑定注册

```go
packet.RegisterBinding(upper, lower, field string, value any)
```

当 `upper` 堆叠在 `lower` 之上时，`lower.field` 自动设置为 `value`。例如：`RegisterBinding("IP", "Ethernet", "type", 0x0800)`。

---

## 10. 构建/解析协议链

### 10.1 已注册的下一层映射

**Ethernet.type → 上层：**
- `0x0800` → IP
- `0x0806` → ARP
- `0x8035` → RARP
- `0x86DD` → IPv6
- `0x8100` → Dot1Q
- `0x88A8` → Dot1Q（QinQ）
- `0x88CC` → LLDP

**IP.proto → 上层：**
- `1` → ICMP
- `6` → TCP
- `17` → UDP
- `47` → GRE
- `89` → OSPF

**IPv6.nh → 上层：**
- `0` → IPv6 Hop-by-Hop
- `6` → TCP
- `17` → UDP
- `43` → IPv6 Routing
- `44` → IPv6 Fragment
- `58` → ICMPv6
- `60` → IPv6 DestOpts

**ICMPv6.type → 子层：**
- `128` → ICMPv6 Echo
- `129` → ICMPv6 Echo Reply
- `133` → NDP Router Solicitation
- `134` → NDP Router Advertisement
- `135` → NDP Neighbor Solicitation
- `136` → NDP Neighbor Advertisement
- `137` → NDP Redirect

**基于端口的启发式规则：**
- UDP:53 → DNS
- UDP:67/68 → DHCP
- UDP:443 → QUIC
- UDP:4789 → VXLAN
- TCP:179 → BGP

**隧道载荷：**
- VXLAN → Ethernet（递归解析内层）

---

## 11. 业务规则与约束

1. **校验和自动计算。** 在 `Build()` 期间显式设置校验和字段会被覆盖——构建钩子将其归零，对头部+载荷计算校验和，再重新序列化。对于 UDP，计算为零的校验和会被替换为 0xFFFF（RFC 768）。

2. **协议层绑定自动应用。** 在 Ethernet 上堆叠 IP 时自动设置 EtherType=0x0800。`Sync()` 重新应用所有绑定。用户可在堆叠后通过 `Set()` 覆盖。

3. **IPv4 总长度、UDP 长度、IPv6 载荷长度** 在 Build 期间根据上层字节自动计算。

4. **TCP dataofs** 在 Build 期间根据序列化后的选项长度自动计算。

5. **Darwin IPv4 raw socket** 要求 `ip_len` 和 `ip_off` 为主机字节序（小端序需字节交换）。Darwin 发送实现自动处理。

6. **Darwin IPv6 raw socket** 不支持 IPV6_HDRINCL。内核填充 IPv6 头部，仅发送载荷。跳数限制通过 IPV6_UNICAST_HOPS 设置。

7. **Linux IPv6 raw socket** 支持 IPV6_HDRINCL——完整发送 IPv6 头部 + 载荷。

8. **macOS BPF** 使用 `/dev/bpf*` 设备（尝试 0-255）。设置 BIOCIMMEDIATE 使读取立即返回。BPF 返回 `[bpf_hdr + data]` 批次；接收器解析批次中所有包并将额外的包排队。

9. **分片重组** 使用覆盖位图检测间隙。分组在可配置超时（默认 30s）后过期。最大并发分组数可配置（默认 1024）。超过 65535 总字节的分组将被丢弃以防范 DoS。

10. **解析将剩余字节包装为 Raw 层。** 如果无法解析下一层协议，剩余字节自动成为 Raw 载荷层。

11. **隧道解析为递归解析**，最大深度 8 层以防止畸形包导致栈溢出。

12. **ConditionalField** 仅在其条件函数基于当前字段值返回 true 时才序列化/反序列化。用于 GRE 可选字段（key、seq、checksum）。

13. **TCP 选项** 在 PostParseHook 中解析（固定字段 + 头部大小之后）。构建时选项由自定义字段类型序列化。

14. **速率限制器** 对 500μs 以下的等待使用自旋循环（为精度消耗 CPU），对更长的等待使用定时器。

---

## 12. 非功能性特征

### 12.1 性能

- **零分配接收路径：** `RecvInto` 允许调用者提供缓冲区，避免 BPF 批次中首个包的内存分配。
- **批量解析：** Darwin BPF 接收器在单次 `read()` 中解析所有包并入队，分摊系统调用成本。
- **覆盖位图** 用于分片重组，使用 `[]bool` 实现 O(1) 逐字节间隙检测。
- **速率限制器自旋循环**（500μs 以下）避免高频发送时的定时器系统调用开销。
- **MSG_ZEROCOPY**（Linux）避免发送时内核→用户空间拷贝。
- **sendmmsg/recvmmsg**（Linux）每次系统调用批量处理多条消息。
- **TPACKET_V3**（Linux）使用 mmap 环形缓冲区实现零拷贝接收。
- **AF_XDP**（Linux）通过 XSK 提供零拷贝或拷贝模式包 I/O。
- 峰值重组大小限制为 65535 字节。Pcap 捕获长度限制为 0x100000（1MB）。

### 12.2 安全性

- **需要 root 权限** 进行所有 raw socket 操作——已在 README 中声明。
- **重组 DoS 防护：** 最多 1024 个并发分片组，每组最多 65535 字节。超出限制时静默丢弃分片。
- **最大隧道深度 8** 防止恶意嵌套隧道头部导致栈溢出。
- **输入验证** 所有字段类型——类型断言带有明确的错误类型错误消息。
- **可疑 pcap 捕获长度** 检查：大于 0x100000 的值将被拒绝。
- 无密钥管理——库不处理凭证或认证。

### 12.3 错误处理

- 所有公开函数返回 `error`。错误使用 `fmt.Errorf` 配合 `%w` 包装以支持 `errors.Is`。
- `ErrTimeout` 哨兵值允许调用者通过 `errors.Is(err, sendrecv.ErrTimeout)` 区分超时和致命错误。
- BPF 批量解析静默跳过畸形包（不记录日志）并继续处理下一个。
- 解析错误在错误消息链中包含协议层名称和字段名称。
- 构建钩子错误包装协议名称。钩子返回的字节数不匹配会被捕获并报告。

### 12.4 线程安全

- `Reassembler` 对所有分组操作使用 `sync.Mutex`。后台 GC goroutine 定期运行，通过关闭 channel 停止。
- `TokenBucketLimiter` 对令牌状态使用 `sync.Mutex`。
- `SniffChan` 使用 `sync.OnceFunc` 实现幂等停止。
- `RawConn` 零拷贝状态由 `sync.Mutex` 保护。

---

## 13. 测试策略

| 类型 | 框架 | 覆盖模式 |
|------|-----------|-----------------|
| 单元测试 | `go test`（标准） | 每个包有 `*_test.go` 文件。40 个测试文件，约 12K 行测试代码，总计约 75K 行（约 16% 测试比例）。 |
| 集成测试 | `go test` | sendrecv（Darwin/Linux）、sniff（回环测试）、batch、zerocopy、mmap、uring 均有平台相关测试。子包（DNS、DHCP、Dot1Q、VXLAN、GRE、LLDP、ERSPAN、OSPF、BGP、QUIC）各自有测试。 |
| 竞态检测 | `make test-race` | Makefile 显式目标，使用 `-race` 标志。 |
| 覆盖率 | `make test-cover` | 生成 `coverage.out` 和可选的 HTML 报告。 |
| 基准测试 | `make bench` | 所有包执行 `-bench=. -benchmem`。 |
| 代码检查 | `make lint` | golangci-lint。 |
| 仅构建 | `make vet` | `go vet ./...`。 |

---

## 14. 示例程序概览

40 个示例程序展示每项功能：

| # | 示例 | 展示内容 |
|---|---------|---------------------|
| 01 | ethernet-ip | 构建 Eth+IP 包 |
| 02 | tcp-udp | TCP/UDP 包构建 |
| 03 | icmp-ping | ICMP Echo Request 构建 |
| 04 | arp | ARP 请求/回复构建 |
| 05 | ipv6 | IPv6 包构建 |
| 06 | dns | DNS 查询构建 |
| 07 | dhcp | DHCP discover/request 构建 |
| 08 | vlan | 802.1Q VLAN 标签 |
| 09 | gre-vxlan | GRE 和 VXLAN 隧道 |
| 10 | dissect | 从原始字节解析包 |
| 11 | send | 通过 raw socket L3 发送 |
| 12 | sendrecv | 发送并接收响应 |
| 13 | tcp-syn-scan | TCP SYN 端口扫描器 |
| 14 | sniff | 实时包捕获 |
| 15 | bpf-filter | BPF 过滤器编译和使用 |
| 16 | shortcuts | 所有一行式快捷函数 |
| 17 | ping | 使用 Sr1 匹配的 ICMP ping |
| 18 | traceroute | UDP traceroute 实现 |
| 19 | raw-socket | RawConn 发送/接收 |
| 20 | batch-raw-socket | BatchConn 批量操作 |
| 21 | zerocopy | MSG_ZEROCOPY 发送 |
| 22 | uring-raw-socket | io_uring raw socket I/O |
| 23 | packet-mmap | TPACKET_V3 环形缓冲区 |
| 24 | dns-client | 使用 sendrecv 的 DNS 客户端 |
| 25 | ntp-client | 使用 sendrecv 的 NTP 客户端 |
| 26 | dhcp-client | 使用 sendrecv 的 DHCP 客户端 |
| 27 | arp-scanner | ARP 网络扫描器 |
| 31 | port-scanner | TCP 端口扫描器 |
| 32 | fishfinder | 网络设备发现 |
| 33 | ipv6-ping | IPv6 ping |
| 34 | fanout | AF_PACKET Fanout 多核 |
| 35 | xdp | AF_XDP 零拷贝 I/O |
| 36 | ratelimit | 令牌桶速率限制 |
| 37 | tcp-options | TCP 选项构建/解析 |
| 38 | pcap-rw | Pcap 文件读写 |
| 39 | reassembly | IP 分片重组 |
| 40 | recvinto | 零分配接收 |

---

## 15. 构建与开发

### 15.1 本地环境配置

```bash
git clone https://github.com/smallnest/goscapy
cd goscapy
go mod download
make build    # go build ./...
make test     # go test ./...
make check    # fmt + vet + lint + test
```

### 15.2 主要 Make 目标

| 目标 | 命令 |
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

## 16. 已知差距与假设

- **无 IPv6 分片重组。** 重组包仅处理 IPv4 分片。
- **无 TCP 流重组。** 仅实现了 IP 层分片重组。
- **无扩展头的 ICMPv6 校验和。** ICMPv6 校验和仅针对消息体计算；未实现扩展头伪头部逻辑。
- **NDP 选项解析有限。** NDP 消息暴露原始 TLV 选项而非完全类型化的选项结构体。
- **无运行时配置文件。** 所有行为均为编程式控制；无 YAML/JSON/TOML 配置。
- **无结构化日志。** 库仅使用 `fmt.Errorf`——无日志级别，无结构化输出。
- **Darwin BPF 是唯一的 macOS 接收器。** macOS 没有 AF_PACKET 等价实现；所有 L2 接收通过 BPF。
- **tcpdump 可选但推荐** 用于 BPF 过滤器编译。预编译指令无需 tcpdump。
- **无 HTTP/gRPC 服务器。** 纯库——无需部署网络服务。
- **测试覆盖不均衡。** 核心 packet/layers/fields 包有充分的单元测试。部分高级功能（zerocopy、uring、xdp）因硬件/内核要求而测试覆盖较少。
- **无模糊测试基础设施。**
- **docs/ 目录包含静态网站**（HTML/CSS/JS，中英文版本），而非 API 文档。API 文档托管在 pkg.go.dev。
- **tasks/ 目录包含功能规划用的 PRD 文档**，而非实现产物。

---

## 17. 附录

### A. 内部依赖图

```
goscapy（Builder、快捷函数）
  ├── packet（Packet、Layer、Build、Dissect、Binding）
  │     └── fields（Field 接口、类型、TLV）
  ├── layers（协议定义、校验和、辅助函数）
  │     ├── packet、fields
  │     └── 子包：dns、dhcp、dot1q、vxlan、gre、lldp、erspan、ospf、bgp、quic
  ├── sendrecv（raw socket I/O）
  │     ├── packet
  │     └── golang.org/x/sys（仅 Linux）
  ├── sniff（抓包）
  │     ├── sendrecv
  │     └── packet
  ├── pcap（文件 I/O）
  │     └── packet
  └── reassembly（分片重组）
        ├── packet
        └── layers
```

### B. Git 历史摘要

- 首次提交：约在 2025 年（tail 中不可见）
- 活跃开发中，约 30 个可见提交
- 近期功能添加（从新到旧）：AF_XDP、AF_PACKET Fanout、IP 分片重组、IPv6 发送、pcap 读写器、令牌桶速率限制器、TCP 选项、RecvInto
- 单人贡献者：`chaoyuepan`
- 仓库地址：`github.com/smallnest/goscapy`

### C. 协议号常量

**EtherType：** `EtherTypeIPv4`（0x0800）、`EtherTypeARP`（0x0806）、`EtherTypeRARP`（0x8035）、`EtherTypeIPv6`（0x86DD）

**IP 协议号：** `IPProtoICMP`（1）、`IPProtoTCP`（6）、`IPProtoUDP`（17）

**ARP 操作：** `ARPWhoHas`（1）、`ARPIsAt`（2）、`RARPWhoIs`（3）、`RARPIsAt`（4）

**TCP 标志位：** `TCPSyn`（0x02）、`TCPAck`（0x10）、`TCPFin`（0x01）、`TCPRst`（0x04）、`TCPPsh`（0x08）、`TCPUrg`（0x20）、`TCPEce`（0x40）、`TCPCwr`（0x80）

**ICMP 类型：** `ICMPEchoReply`（0）、`ICMPDestUnreach`（3）、`ICMPEchoRequest`（8）、`ICMPTimeExceed`（11）

**IPv6 Next Header：** 扩展头：0（Hop-by-Hop）、43（Routing）、44（Fragment）、60（DestOpts）；上层协议：6（TCP）、17（UDP）、58（ICMPv6）、59（No Next Header）

**ICMPv6 类型：** 128（Echo Request）、129（Echo Reply）、133-137（NDP）

### D. 代码量 / 代码指标

- 所有包约 75,000 行 Go 源代码
- 约 12,000 行测试代码，40 个测试文件（约 16% 测试比例）
- 8 个公开包
- 40 个示例程序
- 25+ 个支持的协议/子协议
- 19 种字段类型
- 19 个快捷函数
- 18 种 Builder 类型