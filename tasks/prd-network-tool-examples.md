# PRD: 真实网络工具示例集

## 1. Introduction

在 `examples/` 目录中新增 15 个真实可用的网络工具示例（编号 17-31），覆盖 ICMP、TCP、UDP、DNS、NTP、DHCP、ARP、HTTP、TFTP、WHOIS、WoL、端口扫描等常见网络场景。

与现有示例（01-16 以**数据包构建/解析**为主）不同，本次示例重点在于**实际网络 I/O**——工具真正发包、收包、解析响应并输出结果，用户可以直接在命令行中使用。

## 2. Goals

- 每个工具是独立可运行的 Go module（遵循现有 `examples/NN-name/` 目录结构）
- 优先使用 goscapy 原始套接字（raw socket）实现，仅在不可行时回退到 Go `net` 标准库
- 所有工具包含清晰的命令行参数说明和错误提示
- 输出格式直观易读，适合学习和排障场景
- 需要 root 权限的工具在代码和注释中明确标注

## 3. User Stories

### goscapy-first 工具（原始套接字，需 root）

#### US-001: Ping 工具
**Description:** 作为网络工程师，我希望有一个真正能测 RTT 的 ping 工具，它发送 ICMP Echo Request 并解析 Echo Reply，输出往返时间和统计信息。

**Acceptance Criteria:**
- [ ] 发送 ICMP Echo Request 到指定目标 IP/域名
- [ ] 等待并解析 ICMP Echo Reply，计算 RTT（毫秒）
- [ ] 支持 `-c` 参数指定发包次数（默认 4）
- [ ] 支持 `-i` 参数指定发包间隔（默认 1s）
- [ ] 输出每条 reply 的 seq、ttl、rtt
- [ ] 结束后输出统计：发送/接收/丢包率/min/avg/max/mdev
- [ ] 支持 Ctrl+C 中断并输出统计
- [ ] Typecheck/lint 通过
- [ ] 使用 `sudo go run main.go <target>` 可独立运行

#### US-002: Traceroute 工具
**Description:** 作为网络工程师，我希望追踪数据包到达目标经过的每一跳路由，查看每跳的 IP 和延迟。

**Acceptance Criteria:**
- [ ] 从 TTL=1 开始逐跳递增发送探测包
- [ ] 收到 ICMP Time Exceeded 时记录该跳 IP 和 RTT
- [ ] 到达目标（收到 ICMP Echo Reply）或超过最大跳数（默认 30）时停止
- [ ] 每跳发送 3 个探测包，输出各次 RTT
- [ ] 超时显示 `*`
- [ ] 支持 `-m` 参数设置最大跳数
- [ ] 支持 `-q` 参数设置每跳探测次数
- [ ] Typecheck/lint 通过
- [ ] 使用 `sudo go run main.go <target>` 可独立运行

#### US-003: DNS 客户端
**Description:** 作为开发者，我希望向指定 DNS 服务器发送真实的 DNS 查询，解析并展示返回的 A/AAAA/CNAME/MX 等记录。

**Acceptance Criteria:**
- [ ] 发送 DNS 查询包到指定 DNS 服务器（默认 8.8.8.8）
- [ ] 解析 DNS 响应，提取 Answer 区的资源记录
- [ ] 支持 `-type` 参数指定查询类型：A, AAAA, MX, NS, TXT, CNAME
- [ ] 支持 `-server` 参数指定 DNS 服务器
- [ ] 输出格式：域名 → 记录类型 → 记录值
- [ ] 显示查询响应时间
- [ ] Typecheck/lint 通过
- [ ] 使用 `sudo go run main.go <domain>` 可独立运行

#### US-004: NTP 客户端
**Description:** 作为系统管理员，我希望查询 NTP 服务器获取精确时间，显示当前时间和与服务器的时钟偏移。

**Acceptance Criteria:**
- [ ] 构造 NTP 客户端请求包（48 字节，goscapy Raw payload over UDP）
- [ ] 发送到 NTP 服务器（默认 pool.ntp.org），等待响应
- [ ] 解析 NTP 响应：参考时间戳、往返延迟、时钟偏移
- [ ] 输出本地时间、服务器参考时间、RTT、Offset
- [ ] 支持 `-server` 参数指定 NTP 服务器
- [ ] Typecheck/lint 通过
- [ ] 使用 `sudo go run main.go` 可独立运行

#### US-005: DHCP 客户端
**Description:** 作为网络工程师，我希望执行真实的 DHCP DORA 交互流程，从 DHCP 服务器获取 IP 地址。

**Acceptance Criteria:**
- [ ] 发送 DHCP Discover（广播）
- [ ] 等待并解析 DHCP Offer
- [ ] 发送 DHCP Request
- [ ] 等待并解析 DHCP ACK
- [ ] 输出获取到的 IP、子网掩码、网关、DNS 服务器、租约时间
- [ ] 支持 `-iface` 参数指定网络接口
- [ ] Typecheck/lint 通过
- [ ] 使用 `sudo go run main.go` 可独立运行

#### US-006: ARP 扫描器
**Description:** 作为网络管理员，我希望扫描局域网内活跃的主机，通过发送 ARP 请求发现存活设备。

**Acceptance Criteria:**
- [ ] 对指定 IP 范围（CIDR 格式，如 192.168.1.0/24）逐个发送 ARP 请求
- [ ] 收到 ARP Reply 则记录 IP/MAC 对应关系
- [ ] 支持并发扫描（可配置并发数，默认 50）
- [ ] 超时时间内未收到回复则跳过
- [ ] 输出格式：IP 地址 → MAC 地址，按 IP 排序
- [ ] 扫描完成后输出统计：扫描总数/存活数/耗时
- [ ] 支持 `-cidr` 和 `-workers` 参数
- [ ] Typecheck/lint 通过
- [ ] 使用 `sudo go run main.go -cidr 192.168.1.0/24` 可独立运行

#### US-007: Wake-on-LAN 发送器
**Description:** 作为管理员，我希望发送 Wake-on-LAN 魔术包唤醒局域网内的计算机。

**Acceptance Criteria:**
- [ ] 构造 WoL 魔术包（6 字节 0xFF + 目标 MAC 重复 16 次）
- [ ] 通过 UDP 广播发送到端口 9（或指定端口 7）
- [ ] 支持 MAC 地址输入（支持 `:` `-` 分隔符）
- [ ] 支持 `-broadcast` 指定广播地址（默认 255.255.255.255）
- [ ] 输出发包确认信息
- [ ] Typecheck/lint 通过
- [ ] 使用 `sudo go run main.go <MAC>` 可独立运行

### Go net 回退工具（无需 root 或 root 可选）

#### US-008: TCP Echo Server
**Description:** 作为开发者，我希望有一个简单的 TCP Echo 服务器用于调试，收到什么就原样返回。

**Acceptance Criteria:**
- [ ] 监听指定端口（默认 7777）
- [ ] 每个客户端连接收到数据后原样返回
- [ ] 支持多客户端并发连接
- [ ] 打印客户端连接/断开日志和时间戳
- [ ] 支持 `-port` 参数
- [ ] 收到 SIGINT/Ctrl+C 时优雅关闭
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go` 可独立运行（无需 root）

#### US-009: TCP Echo Client
**Description:** 作为开发者，我希望连接 TCP Echo Server，发送消息并接收回显。

**Acceptance Criteria:**
- [ ] 连接到指定 IP:端口（默认 127.0.0.1:7777）
- [ ] 发送用户输入的消息，接收并打印回显
- [ ] 计算并输出 RTT
- [ ] 支持交互模式（持续读 stdin 发送）和单次模式（`-msg` 参数）
- [ ] 连接失败时输出明确的错误信息
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go` 可独立运行（无需 root）

#### US-010: UDP Echo Server
**Description:** 作为开发者，我希望有一个无连接的 UDP Echo 服务器，方便调试 UDP 通信。

**Acceptance Criteria:**
- [ ] 监听指定 UDP 端口（默认 7778）
- [ ] 收到数据报后原样返回给发送方
- [ ] 打印每个数据报的来源 IP:端口、大小、时间戳
- [ ] 支持 `-port` 参数
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go` 可独立运行（无需 root）

#### US-011: UDP Echo Client
**Description:** 作为开发者，我希望向 UDP Echo Server 发送数据报并接收回显。

**Acceptance Criteria:**
- [ ] 向目标 IP:端口发送 UDP 数据报
- [ ] 设置接收超时（默认 3 秒）
- [ ] 收到回显后打印内容和 RTT
- [ ] 支持单次模式（`-msg`）和交互模式（stdin）
- [ ] 超时时输出提示
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go` 可独立运行（无需 root）

#### US-012: HTTP GET 客户端
**Description:** 作为开发者，我希望有一个轻量 HTTP 客户端，手动构造 HTTP 请求并显示响应（用于理解 HTTP 协议）。

**Acceptance Criteria:**
- [ ] 手动构造 HTTP/1.1 GET 请求（通过 TCP 连接发送）
- [ ] 解析 HTTP 响应头和 body
- [ ] 输出状态行、响应头、响应体（截断显示）
- [ ] 显示连接时间、首字节时间
- [ ] 支持 `-host` 指定 Host 头（用于测试）
- [ ] 支持自动跟随重定向（可选 `-L`）
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go <URL>` 可独立运行（无需 root）

#### US-013: TFTP 客户端
**Description:** 作为网络工程师，我希望从 TFTP 服务器下载文件（RRQ），用于嵌入式设备固件更新等场景。

**Acceptance Criteria:**
- [ ] 发送 TFTP Read Request (RRQ) 到服务器
- [ ] 接收数据包（DATA），发送 ACK，组装文件
- [ ] 支持 `octet` 模式传输
- [ ] 显示传输进度（已接收字节数）
- [ ] 传输完成输出文件大小、耗时、平均速率
- [ ] 支持超时重传（默认重试 3 次）
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go <server> <filename>` 可独立运行（无需 root）

#### US-014: WHOIS 客户端
**Description:** 作为运维人员，我希望查询域名的 WHOIS 信息（注册商、到期时间等）。

**Acceptance Criteria:**
- [ ] 连接到 WHOIS 服务器（默认 whois.iana.org，自动适配）
- [ ] 发送域名查询请求（CRLF 结尾）
- [ ] 接收并显示 WHOIS 原始响应
- [ ] 支持 `-server` 指定 WHOIS 服务器
- [ ] 提取关键信息：注册商、创建时间、到期时间、DNS 服务器
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go <domain>` 可独立运行（无需 root）

#### US-015: TCP 端口扫描器
**Description:** 作为安全研究员，我希望扫描目标主机的开放 TCP 端口（全连接扫描），了解服务暴露情况。

**Acceptance Criteria:**
- [ ] 对指定 IP 和端口范围进行 TCP Connect 扫描
- [ ] 支持 `-p` 参数：单个端口（80）、端口范围（20-100）、混合（22,80,443）
- [ ] 支持常用端口预设（`--top-ports 100` 扫描前 100 常用端口）
- [ ] 识别常见端口对应的服务名称（80→HTTP, 443→HTTPS 等）
- [ ] 并发扫描，可配置并发数（默认 100）
- [ ] 输出格式：PORT | STATE | SERVICE
- [ ] 扫描完成输出统计：总数/开放数/耗时
- [ ] Typecheck/lint 通过
- [ ] 使用 `go run main.go <target>` 可独立运行（无需 root）

## 4. Functional Requirements

- **FR-1:** 每个工具必须是独立的 Go module，目录名为 `examples/NN-tool-name/main.go`，带独立 `go.mod`
- **FR-2:** 编号 17-31，延续现有示例的编号体系
- **FR-3:** 每个工具必须可独立运行，不依赖其他示例
- **FR-4:** goscapy-first 工具（US-001 ~ US-007）使用 goscapy 的 Builder API 构造数据包 + sendrecv 收发
- **FR-5:** Go net 回退工具（US-008 ~ US-015）使用 Go 标准库 `net` 包实现
- **FR-6:** 需要 root 权限的工具在文件头部和 README 中明确标注
- **FR-7:** 所有工具至少包含基础命令行参数支持（`flag` 包或 `os.Args`）
- **FR-8:** 每个工具的 `go.mod` 通过 `replace` 指令引用父项目 `../../`
- **FR-9:** 所有工具的错误信息使用英文，代码注释使用中文（与现有示例风格一致）
- **FR-10:** 更新 `examples/README.md`，添加新工具的说明和运行方式

## 5. Non-Goals (Out of Scope)

- 不实现图形界面或 Web 界面
- 不实现 IPv6 版本的工具（可在后续 PRD 中扩展）
- 不实现 TLS/SSL 支持（https 客户端在后续考虑）
- 不实现多平台安装脚本（每个工具 `go run` 即可）
- 不实现性能基准测试或压测工具
- DNS 客户端不实现 DNS-over-HTTPS (DoH) 或 DNS-over-TLS (DoT)

## 6. Design Considerations

### 目录结构
```
examples/
├── README.md                    # 更新，添加 17-31 的说明
├── 17-ping/
│   ├── go.mod
│   └── main.go
├── 18-traceroute/
│   ├── go.mod
│   └── main.go
├── 19-tcp-echo-server/
│   ├── go.mod
│   └── main.go
├── 20-tcp-echo-client/
│   ├── go.mod
│   └── main.go
├── 21-udp-echo-server/
│   ├── go.mod
│   └── main.go
├── 22-udp-echo-client/
│   ├── go.mod
│   └── main.go
├── 23-dns-client/
│   ├── go.mod
│   └── main.go
├── 24-ntp-client/
│   ├── go.mod
│   └── main.go
├── 25-http-get/
│   ├── go.mod
│   └── main.go
├── 26-dhcp-client/
│   ├── go.mod
│   └── main.go
├── 27-arp-scanner/
│   ├── go.mod
│   └── main.go
├── 28-wol-sender/
│   ├── go.mod
│   └── main.go
├── 29-tftp-client/
│   ├── go.mod
│   └── main.go
├── 30-whois-client/
│   ├── go.mod
│   └── main.go
└── 31-port-scanner/
    ├── go.mod
    └── main.go
```

### 编码规范
- 每个 `main.go` 包含：文件头注释（工具说明、运行方式）、协议简介、分步代码、参考信息
- 风格与现有 01-16 示例保持一致
- 需要 root 的使用 `sudo go run main.go`；不需要的直接 `go run main.go`

## 7. Technical Considerations

| 工具 | 关键依赖 | 权限 | 技术要点 |
|------|---------|------|---------|
| ping | goscapy + sendrecv | root | SendRecv1, ICMP Echo, RTT 计算 |
| traceroute | goscapy + sendrecv | root | 变 TTL, ICMP Time Exceeded 解析 |
| dns-client | goscapy + sendrecv | root | DNS Builder, UDP/53, 响应解析 |
| ntp-client | goscapy + sendrecv | root | NewRawWith, NTP 48 字节二进制协议 |
| dhcp-client | goscapy + sendrecv | root | DHCP Builder, 广播, DORA 状态机 |
| arp-scanner | goscapy + sendrecv | root | ARP Builder, 并发, CIDR 遍历 |
| wol-sender | goscapy 或 net | root(可选) | Magic Packet, UDP 广播 |
| tcp-echo-server | net | 无 | ListenTCP, goroutine per conn |
| tcp-echo-client | net | 无 | DialTCP, stdin 交互 |
| udp-echo-server | net | 无 | ListenUDP, 无连接回显 |
| udp-echo-client | net | 无 | DialUDP, 超时处理 |
| http-get | net | 无 | 手动构造 HTTP/1.1 请求, TCP 连接 |
| tftp-client | net | 无 | UDP, RRQ, DATA/ACK 状态机, 超时重传 |
| whois-client | net | 无 | TCP/43, 纯文本协议 |
| port-scanner | net | 无 | DialTCP 并发, 服务识别 |

### NTP 协议说明
NTP 客户端需要手动构造 48 字节的 NTP 请求包。goscapy 没有内置 NTP layer builder，将通过 `layers.NewRawWith(data)` 将构造好的 48 字节 NTP 数据作为 UDP payload。NTP 包格式（RFC 5905）：
- LI (2 bits) + VN (3 bits) + Mode (3 bits) = 1 byte
- Stratum, Poll, Precision 等字段
- 发送时填入 Transmit Timestamp，收到后计算 offset 和 delay

## 8. Success Metrics

- 所有 15 个工具可独立编译运行（`go build` 无报错）
- goscapy-first 工具在 `sudo` 下正常收发网络包
- 每个工具的错误处理和用户提示完善且友好
- `examples/README.md` 更新完整，新用户可以按指引运行

## 9. Open Questions

- 是否需要在体积较大的工具（如 arp-scanner, port-scanner）中添加进度条？[Assumption: 先不加，输出文本进度即可]
- HTTP GET 客户端是否应支持 POST/PUT？[Assumption: 仅 GET，保持简单]
- 是否需要在项目根目录的 `README.md` 中也说明新工具？[Assumption: 由用户在 PRD review 时决定]