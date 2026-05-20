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

### 🛠️ 真实网络工具（goscapy 实现，需 root）

| # | 工具 | 说明 | 运行 |
|---|------|------|------|
| 17 | [Ping](17-ping/) | 真实 ICMP Ping，RTT 测量与统计 | `sudo go run main.go <目标>` |
| 18 | [Traceroute](18-traceroute/) | 变 TTL 逐跳路由追踪 | `sudo go run main.go <目标>` |
| 24 | [DNS 客户端](24-dns-client/) | 发送 DNS 查询，解析 A/AAAA/MX 等记录 | `sudo go run main.go <域名>` |
| 25 | [NTP 客户端](25-ntp-client/) | NTP 时间同步，测量时钟偏移 | `sudo go run main.go` |
| 26 | [DHCP 客户端](26-dhcp-client/) | DHCP DORA 流程获取 IP | `sudo go run main.go` |
| 27 | [ARP 扫描器](27-arp-scanner/) | ARP 局域网主机发现 | `sudo go run main.go -cidr 192.168.1.0/24` |
| 32 | [Fishfinder 探测器](32-fishfinder/) | 并发高能 IP/时延扫描器 (ICMP/TCP) | `sudo go run main.go -cidr 192.168.1.0/24` |

### 🌐 真实网络工具（Go 标准库实现，无需 root）

| # | 工具 | 说明 | 运行 |
|---|------|------|------|
| 28 | [WoL 发送器](28-wol-sender/) | Wake-on-LAN 魔术包广播 | `go run main.go <MAC>` |
| 29 | [TFTP 客户端](29-tftp-client/) | TFTP 文件下载 (RRQ) | `go run main.go <服务器> <文件>` |
| 30 | [WHOIS 客户端](30-whois-client/) | WHOIS 域名信息查询 | `go run main.go <域名>` |
| 31 | [端口扫描器](31-port-scanner/) | TCP Connect 并发端口扫描 | `go run main.go -p 80,443 <目标>` |

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

真实工具路径:
  17 (Ping) → 18 (Traceroute) → 24 (DNS) → 27 (ARP Scanner) → 32 (Fishfinder) → 31 (Port Scanner)
```

## 权限说明

- **不需要 root**: 示例 01-10, 15-16, 28-31（构建/解析/标准网络库）
- **需要 root**: 示例 11-14, 17, 18-27, 32（原始套接字/嗅探/收发/高级特性）
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
