# goscapy

[![Go Reference](https://pkg.go.dev/badge/github.com/smallnest/goscapy.svg)](https://pkg.go.dev/github.com/smallnest/goscapy)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.26-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-green)](LICENSE)

纯 Go 实现的网络数据包构造、解析、发送、接收和嗅探库。goscapy 提供符合 Go 语言习惯的 API，包括类型安全的构建器模式和一行式快捷函数。

## 特性

- **构建器 API** — 流畅的方法链式调用，类型安全、语义明确的数据包构造
- **快捷函数** — 常用协议栈的一行式调用，内置合理默认值
- **数据包解析** — 从原始字节自动识别协议层，还原结构化数据包
- **发送与接收** — 通过原始套接字收发数据包（支持 L2 和 L3 层）
- **数据包嗅探** — 支持回调式和通道式两种 API，支持 BPF 过滤器
- **自动校验和** — IP、TCP、UDP、ICMP 校验和在序列化时自动计算
- **层间绑定** — 相邻协议层字段自动推断（如 IP 层叠在 Ethernet 上时自动设置 EtherType=0x0800）
- **跨平台** — 支持 Darwin (macOS) 和 Linux，各自使用平台特定的原始套接字实现

## 支持的协议

| 层级 | 协议 |
|------|------|
| 链路层 | Ethernet、ARP |
| 网络层 | IPv4 |
| 传输层 | TCP、UDP、ICMP |
| 载荷层 | Raw |

## 安装

```bash
go get github.com/smallnest/goscapy
```

## 快速开始

### 构建数据包（构建器 API）

```go
// Ethernet + IP + ICMP Echo 请求
pkt, err := goscapy.NewEthernet().
    SrcMAC("aa:bb:cc:dd:ee:ff").
    DstMAC("ff:ff:ff:ff:ff:ff").
    Over(goscapy.NewIP().SrcIP("192.168.1.1").DstIP("8.8.8.8")).
    Over(goscapy.NewICMP().Type(8).Code(0)).
    Build()
```

### 构建数据包（快捷函数）

```go
// 同上，一行完成
pkt, err := goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
```

### 解析数据包

```go
raw := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, ...} // 原始字节
pkt, err := packet.Dissect(raw, packet.DissectEthernet)
fmt.Println(pkt.String()) // "Ethernet / IP / ICMP"
```

### 发送数据包

```go
pkt, _ := goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
sendrecv.Send(pkt, "eth0")  // L3 层发送（IP 层）
sendrecv.Sendp(pkt, "eth0") // L2 层发送（以太网帧）
```

### 嗅探数据包

```go
// 回调式
sniff.Sniff(sniff.SniffConfig{
    Iface:   "eth0",
    Filter:  "icmp",
    Timeout: 10 * time.Second,
}, func(pkt *packet.Packet) bool {
    fmt.Println(pkt)
    return true // 继续嗅探
})

// 通道式
ch, stop := sniff.SniffChan(sniff.SniffConfig{Iface: "eth0", Count: 5})
defer stop()
for pkt := range ch {
    fmt.Println(pkt)
}
```

## 文档

完整文档请访问 [pkg.go.dev/github.com/smallnest/goscapy](https://pkg.go.dev/github.com/smallnest/goscapy)。

### 包结构

| 包 | 说明 |
|----|------|
| `pkg/goscapy` | 构建器 API 和快捷函数 |
| `pkg/packet` | 核心数据包/协议层类型，构建、解析、字段绑定 |
| `pkg/layers` | 各协议层定义（Ethernet、ARP、IP、TCP、UDP、ICMP、Raw） |
| `pkg/sendrecv` | 原始套接字收发（Send、Sendp、Recv、SendRecv） |
| `pkg/sniff` | 数据包嗅探，支持 BPF 过滤器 |
| `pkg/fields` | 字段类型系统（序列化、反序列化） |

### 快捷函数

| 函数 | 协议栈 |
|------|--------|
| `EtherIP` | Ethernet + IPv4 + Payload |
| `EtherIPICMP` | Ethernet + IPv4 + ICMP |
| `EtherIPTCP` | Ethernet + IPv4 + TCP |
| `EtherIPUDP` | Ethernet + IPv4 + UDP |
| `EtherARP` | Ethernet + ARP |
| `IPICMP` | IPv4 + ICMP（不含 Ethernet） |
| `IPTCP` | IPv4 + TCP（不含 Ethernet） |
| `IPUDP` | IPv4 + UDP（不含 Ethernet） |

### 构建器

| 构建器 | 主要方法 |
|--------|----------|
| `EthernetBuilder` | `SrcMAC`、`DstMAC`、`Type` |
| `IPBuilder` | `SrcIP`、`DstIP`、`TTL`、`Proto`、`ID` |
| `ICMPBuilder` | `Type`、`Code`、`ID`、`Seq` |
| `TCPBuilder` | `SrcPort`、`DstPort`、`Flags`、`Seq`、`Ack`、`Window` |
| `UDPBuilder` | `SrcPort`、`DstPort` |
| `ARPBuilder` | `Op`、`SrcMAC`、`SrcIP`、`DstMAC`、`DstIP` |

## 平台支持

| 平台 | L2 收发 | L3 收发 | BPF 过滤 | 回环接口 |
|------|:-------:|:-------:|:--------:|:--------:|
| macOS (Darwin) | BPF | AF_INET | 内核 BPF | lo0 |
| Linux | AF_PACKET | AF_INET | SO_ATTACH_FILTER | lo |

## 环境要求

- Go 1.26+
- macOS 或 Linux
- 原始套接字操作需要 root/管理员权限
- `tcpdump`（可选，用于通过 `sniff.CompileFilter` 编译 BPF 过滤字符串）

## Makefile

```bash
make build         # 编译所有包
make test          # 运行所有测试
make test-race     # 竞态检测测试
make test-cover    # 生成覆盖率报告
make bench         # 运行基准测试
make lint          # 运行 golangci-lint
make fmt           # 格式化代码
make vet           # 运行 go vet
make check         # 一键运行 fmt + vet + lint + test
```

## 许可证

BSD 3-Clause License。详见 [LICENSE](LICENSE)。