// 示例 32: Fishfinder (探鱼仪) IP/时延扫描器
//
// 本示例演示如何使用 goscapy 实现一个并发的高性能 IP 和时延扫描器。
// 支持以下模式:
//   1. ICMP 模式 (-mode icmp): 发送 ICMP Echo Request，接收 Echo Reply。
//   2. TCP 模式 (-mode tcp): 发送 TCP SYN 包到指定端口（如 80），根据接收到的 SYN-ACK 判断存活。
//
// 特性:
//   - 支持并发发送 worker 控制（-workers）
//   - 使用 sync.Map 记录发送时间并精确测量每个存活主机的 RTT (往返时延)
//   - 使用 sendrecv.Send 进行 L3 发送，自动处理 IP_HDRINCL 和平台差异
//   - 接收端使用 sendrecv.OpenFilteredReceiver 进行带 BPF 过滤的嗅探，提升性能
//
// 运行方式: sudo go run main.go -cidr <CIDR> [选项]
// 示例:     sudo go run main.go -cidr 192.168.1.0/24 -mode icmp
//           sudo go run main.go -cidr 192.168.1.0/24 -mode tcp -port 80 -workers 200
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
	"github.com/smallnest/goscapy/pkg/sniff"
)

func main() {
	cidr := flag.String("cidr", "", "扫描的 IP 范围 (CIDR 格式, 如 192.168.1.0/24)")
	mode := flag.String("mode", "icmp", "扫描模式 (icmp 或 tcp)")
	workers := flag.Int("workers", 100, "并发发送协程数")
	port := flag.Int("port", 80, "TCP 模式下的目标端口")
	timeout := flag.Duration("timeout", 2*time.Second, "响应超时时间")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	flag.Parse()

	if *cidr == "" {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go -cidr <CIDR> [选项]\n")
		fmt.Fprintf(os.Stderr, "选项:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	modeVal := *mode
	if modeVal != "icmp" && modeVal != "tcp" {
		fmt.Fprintf(os.Stderr, "错误: 不支持的模式 %q, 必须为 icmp 或 tcp\n", modeVal)
		os.Exit(1)
	}

	// 1. 自动选择或验证网络接口
	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	srcIP := getSrcIP(ifaceVal)
	if srcIP == "0.0.0.0" {
		fmt.Fprintf(os.Stderr, "错误: 无法在接口 %s 上获取有效的源 IP\n", ifaceVal)
		os.Exit(1)
	}

	ips := cidrToIPs(*cidr)
	if len(ips) == 0 {
		fmt.Fprintf(os.Stderr, "错误: 未找到可扫描的 IP 地址\n")
		os.Exit(1)
	}

	fmt.Printf("⚡️ Fishfinder 启动扫描: %s (模式: %s)\n", *cidr, modeVal)
	fmt.Printf("接口: %s, 源 IP: %s\n", ifaceVal, srcIP)
	fmt.Printf("目标数: %d, 发送并发: %d, 超时: %v\n", len(ips), *workers, *timeout)
	if modeVal == "tcp" {
		fmt.Printf("TCP 探测目标端口: %d\n", *port)
	}
	fmt.Println()

	// 2. 准备嗅探 — 编译 BPF 过滤器
	scannerID := uint16(os.Getpid() & 0xffff)
	sport := uint16(30000 + time.Now().UnixNano()%20000)

	var filterExpr string
	if modeVal == "icmp" {
		filterExpr = fmt.Sprintf("icmp and dst host %s", srcIP)
	} else {
		filterExpr = fmt.Sprintf("tcp and dst host %s and dst port %d", srcIP, sport)
	}

	// 指定接口编译 BPF 过滤器，避免 macOS PKTAP 数据链路类型问题
	instructions, err := sniff.CompileFilterOnIface(filterExpr, ifaceVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: BPF 过滤器编译失败 (%v)，将使用无过滤器模式\n", err)
		instructions = nil
	}

	// 打开带过滤器的接收器（显式处理错误，避免静默失败）
	rx, err := sendrecv.OpenFilteredReceiver(ifaceVal, instructions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法打开接收器: %v\n", err)
		os.Exit(1)
	}
	defer rx.Close()

	// 3. 开启接收协程处理响应并测量时延
	var aliveCount int32
	var sentTrack sync.Map // key: targetIP (string), value: time.Time
	recvDone := make(chan struct{})

	go func() {
		defer close(recvDone)
		deadline := time.Now().Add(*timeout + 500*time.Millisecond)
		for time.Now().Before(deadline) {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			pkt, err := rx.Recv(remaining)
			if err != nil {
				// 超时、无有效包（无过滤器模式下常见）等都是正常情况，继续等待
				// 直到 deadline 到期后自动退出循环
				continue
			}

			ipLayer := pkt.GetLayer("IP")
			if ipLayer == nil {
				continue
			}

			srcVal, _ := ipLayer.Get("src")
			srcIPNet, ok := srcVal.(net.IP)
			if !ok {
				continue
			}
			targetIP := srcIPNet.String()

			// 检查是否在我们发送的记录中
			sentTimeVal, ok := sentTrack.Load(targetIP)
			if !ok {
				continue
			}
			sentTime := sentTimeVal.(time.Time)

			// 根据协议类型进行更严密的校验
			matched := false
			if modeVal == "icmp" {
				icmpLayer := pkt.GetLayer("ICMP")
				if icmpLayer != nil {
					itypeVal, _ := icmpLayer.Get("type")
					idVal, _ := icmpLayer.Get("id")
					if itypeVal.(uint8) == layers.ICMPEchoReply && idVal.(uint16) == scannerID {
						matched = true
					}
				}
			} else {
				tcpLayer := pkt.GetLayer("TCP")
				if tcpLayer != nil {
					flagsVal, _ := tcpLayer.Get("flags")
					sportVal, _ := tcpLayer.Get("sport")
					// SYN-ACK = 0x12
					if flagsVal.(uint8) == (layers.TCPSyn|layers.TCPAck) && sportVal.(uint16) == uint16(*port) {
						matched = true
					}
				}
			}

			if matched {
				rtt := time.Since(sentTime)
				// 防止重复计数
				sentTrack.Delete(targetIP)
				atomic.AddInt32(&aliveCount, 1)
				fmt.Printf("[+] %-16s (RTT: %.2f ms)\n", targetIP, float64(rtt.Microseconds())/1000.0)
			}
		}
	}()

	// 4. 并发发送探测包
	var sendErrCount int32
	start := time.Now()
	sem := make(chan struct{}, *workers)
	var sendWG sync.WaitGroup

	for _, ip := range ips {
		sendWG.Add(1)
		go func(targetIP string) {
			defer sendWG.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 记录发送时刻 (在发送之前记录，避免 RTT 偏大)
			sentTrack.Store(targetIP, time.Now())

			// 构造报文
			var pkt *packet.Packet
			if modeVal == "icmp" {
				pkt = goscapy.NewIP().
					SrcIP(srcIP).
					DstIP(targetIP).
					Over(goscapy.NewICMP().
						Type(layers.ICMPEchoRequest).
						ID(scannerID).
						Seq(1)).
					Packet()
			} else {
				pkt = goscapy.NewIP().
					SrcIP(srcIP).
					DstIP(targetIP).
					Over(goscapy.NewTCP().
						SrcPort(sport).
						DstPort(uint16(*port)).
						Flags(layers.TCPSyn).
						Seq(1000)).
					Packet()
			}

			// 使用 sendrecv.Send 发送 L3 报文 (自动处理 IP_HDRINCL 和平台差异)
			if err := sendrecv.Send(pkt, ifaceVal); err != nil {
				sentTrack.Delete(targetIP)
				atomic.AddInt32(&sendErrCount, 1)
			}
		}(ip)
	}

	// 等待发送完毕
	sendWG.Wait()

	// 等待接收协程处理完所有响应
	<-recvDone

	elapsed := time.Since(start)
	fmt.Println("\n------------------------------------------------")
	fmt.Printf("扫描完成: 总数 %d, 存活 %d, 发送失败 %d, 耗时 %.2f s\n",
		len(ips), atomic.LoadInt32(&aliveCount), atomic.LoadInt32(&sendErrCount), elapsed.Seconds())
}

func cidrToIPs(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无效的 CIDR: %s\n", cidr)
		os.Exit(1)
	}

	var ips []string
	ip := ipnet.IP.To4()
	if ip == nil {
		fmt.Fprintf(os.Stderr, "只支持 IPv4 CIDR\n")
		os.Exit(1)
	}

	startIP := make(net.IP, len(ip))
	copy(startIP, ip.Mask(ipnet.Mask))

	for ip := startIP; ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func getSrcIP(iface string) string {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return "0.0.0.0"
	}
	addrs, err := i.Addrs()
	if err != nil || len(addrs) == 0 {
		return "0.0.0.0"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "0.0.0.0"
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "en0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			return iface.Name
		}
	}
	return "en0"
}
