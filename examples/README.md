# goscapy 示例集

本文件夹包含 goscapy 库所有核心特性的可运行示例，按学习难度递增排列。

## 快速开始

```bash
# 克隆项目
git clone https://github.com/smallnest/goscapy.git
cd goscapy

# 运行第一个示例
cd examples/01-ethernet-ip
go run main.go
```

## 示例列表

### 📦 基础包构建（无需 root 权限）

| # | 示例 | 说明 | 运行 |
|---|------|------|------|
| 01 | [Ethernet + IPv4](01-ethernet-ip/) | Builder API 构建基础数据包 | `go run main.go` |
| 02 | [TCP/UDP](02-tcp-udp/) | 传输层协议构建，Shortcut vs Builder | `go run main.go` |
| 03 | [ICMP Ping](03-icmp-ping/) | ICMP Echo Request/Reply 构建 | `go run main.go` |
| 04 | [ARP](04-arp/) | ARP 请求和应答包构建 | `go run main.go` |
| 05 | [IPv6](05-ipv6/) | IPv6 及扩展头构建 | `go run main.go` |
| 06 | [DNS](06-dns/) | DNS 查询包构建 | `go run main.go` |
| 07 | [DHCP](07-dhcp/) | DHCP DORA 四步交互包构建 | `go run main.go` |
| 08 | [VLAN](08-vlan/) | 802.1Q VLAN 标签包构建 | `go run main.go` |
| 09 | [GRE/VXLAN](09-gre-vxlan/) | 隧道封装包构建 | `go run main.go` |
| 10 | [包解析](10-dissect/) | 将原始字节解析为结构化包 | `go run main.go` |
| 16 | [Shortcut 函数](16-shortcuts/) | 所有快捷函数综合示例 | `go run main.go` |

### 📡 网络操作（需要 root 权限）

| # | 示例 | 说明 | 运行 |
|---|------|------|------|
| 11 | [发送数据包](11-send/) | Send (L3) 和 Sendp (L2) | `sudo go run main.go en0` |
| 12 | [发送并接收](12-sendrecv/) | SendRecv1 / SendRecv 请求响应 | `sudo go run main.go en0` |
| 13 | [TCP SYN 扫描](13-tcp-syn-scan/) | 半开放端口扫描 | `sudo go run main.go en0 127.0.0.1` |
| 14 | [包嗅探](14-sniff/) | 实时流量捕获 | `sudo go run main.go en0` |
| 15 | [BPF 过滤器](15-bpf-filter/) | BPF 过滤器编译和使用 | `go run main.go` |

## 学习路径

```
新手推荐路径:
  01 → 02 → 03 → 10 → 16 → 11 → 12 → 14

网络工程师路径:
  01 → 04 → 05 → 08 → 09 → 10 → 11 → 14

安全研究路径:
  01 → 02 → 03 → 10 → 11 → 12 → 13 → 14 → 15
```

## 权限说明

- **不需要 root**: 示例 01-10, 15, 16（仅构建/解析数据包）
- **需要 root**: 示例 11-14（发送/嗅探原始套接字）
  - macOS: 使用 `sudo go run main.go`
  - Linux: 使用 `sudo go run main.go` 或设置 `CAP_NET_RAW` 能力

## 项目结构

每个示例都是独立的 Go module，通过 `replace` 指令引用父项目：

```
examples/
├── README.md                   # 本文件
├── 01-ethernet-ip/
│   ├── go.mod                  # 独立 module，replace 到 ../..
│   └── main.go
├── 02-tcp-udp/
│   ├── go.mod
│   └── main.go
└── ...
```
