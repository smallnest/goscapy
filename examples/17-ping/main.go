// 示例 17: Ping 工具
//
// 本示例演示如何使用 goscapy 实现真实的 Ping 工具。
// 你将学到:
//   - ICMP Echo Request/Reply 的发送与接收
//   - sendrecv.Sr1() + DefaultMatch 的自动回包匹配
//   - RTT (往返时间) 的精确测量
//   - 域名解析到 IP 地址
//   - 丢包率和延迟统计
//   - Ctrl+C 信号处理与优雅退出
//
// 运行方式: sudo go run main.go [选项] <目标>
// 示例:     sudo go run main.go 8.8.8.8
//           sudo go run main.go -c 10 -i 500ms google.com
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	count := flag.Int("c", 4, "发包次数")
	interval := flag.Duration("i", time.Second, "发包间隔")
	iface := flag.String("I", "", "网络接口 (默认自动检测)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go [选项] <目标>\n")
		fmt.Fprintf(os.Stderr, "示例: sudo go run main.go 8.8.8.8\n")
		fmt.Fprintf(os.Stderr, "      sudo go run main.go -c 10 google.com\n")
		os.Exit(1)
	}

	target := flag.Arg(0)

	ip, err := resolveHost(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 %s 失败: %v\n", target, err)
		os.Exit(1)
	}

	dstIP := net.ParseIP(ip).To4()
	if dstIP == nil {
		fmt.Fprintf(os.Stderr, "无效的 IPv4 地址: %s\n", ip)
		os.Exit(1)
	}

	fmt.Printf("PING %s (%s): 56 data bytes\n", target, ip)
	if ip != target {
		fmt.Printf("  解析到: %s\n", ip)
	}

	// 确定网络接口。
	nic := *iface
	if nic == "" {
		nic = detectInterface(dstIP)
	}

	// 获取本地 IP（IPPROTO_RAW + IP_HDRINCL 需要完整 IP 头）。
	srcIP := getLocalIP(nic)
	if srcIP == nil {
		fmt.Fprintf(os.Stderr, "无法获取接口 %s 的本地 IPv4 地址\n", nic)
		os.Exit(1)
	}
	fmt.Printf("  使用接口: %s (本地 IP: %s)\n", nic, srcIP)

	pid := uint16(os.Getpid() & 0xFFFF)

	var rtts []float64
	sent := 0
	received := 0

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		<-sigCh
		close(done)
	}()

	// 接收超时 = 发包间隔。
	recvTimeout := *interval

loop:
	for seq := 1; seq <= *count; seq++ {
		select {
		case <-done:
			break loop
		default:
		}

		start := time.Now()

		// 用 goscapy 构建 IP + ICMP Echo Request 报文。
		ipLayer := layers.NewIP()
		ipLayer.Set("src", srcIP)
			ipLayer.Set("dst", dstIP)
		ipLayer.Set("ttl", uint8(64))
		icmpLayer := layers.NewICMPEcho(pid, uint16(seq))
		pkt := ipLayer.Over(icmpLayer)

		// Sr1: 发送并等待第一个匹配的回包。
		// match=nil 表示使用 DefaultMatch 自动匹配:
		//   received.IP.src == sent.IP.dst &&
		//   received.ICMP.type == EchoReply &&
		//   received.ICMP.id == sent.ICMP.id
		_, resp, recvErr := sendrecv.Sr1(pkt, nic, recvTimeout, nil)

		sent++

		if recvErr != nil {
			if errors.Is(recvErr, sendrecv.ErrTimeout) {
				fmt.Printf("请求超时 (seq=%d)\n", seq)
			} else {
				fmt.Printf("发送失败 (seq=%d): %v\n", seq, recvErr)
			}
		} else if resp == nil {
			fmt.Printf("请求超时 (seq=%d)\n", seq)
		} else {
			rtt := time.Since(start).Seconds() * 1000

			ttl := getTTL(resp)
			icmpType, icmpCode := getICMPInfo(resp)

			switch icmpType {
			case 0: // Echo Reply
				received++
				rtts = append(rtts, rtt)
				fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
					84, ip, seq, ttl, rtt)
			case 3:
				fmt.Printf("来自 %s 的目标不可达 (type=%d, code=%d)\n", ip, icmpType, icmpCode)
			case 11:
				fmt.Printf("来自 %s 的 TTL 超时 (type=%d, code=%d)\n", ip, icmpType, icmpCode)
			default:
				fmt.Printf("来自 %s 的响应: type=%d, code=%d, seq=%d\n", ip, icmpType, icmpCode, seq)
			}
		}

		elapsed := time.Since(start)
		if seq < *count && elapsed < *interval {
			select {
			case <-done:
				break loop
			case <-time.After(*interval - elapsed):
			}
		}
	}

	signal.Stop(sigCh)

	fmt.Println()
	fmt.Printf("--- %s ping statistics ---\n", target)
	loss := 0.0
	if sent > 0 {
		loss = float64(sent-received) / float64(sent) * 100
	}
	fmt.Printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
		sent, received, loss)

	if len(rtts) > 0 {
		sort.Float64s(rtts)
		minRTT := rtts[0]
		maxRTT := rtts[len(rtts)-1]
		avgRTT := average(rtts)
		mdev := stdDev(rtts, avgRTT)

		fmt.Printf("round-trip min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
			minRTT, avgRTT, maxRTT, mdev)
	}
}

// detectInterface 自动检测到达目标 IP 的网络接口。
func detectInterface(dstIP net.IP) string {
	// macOS: 通过 route get 获取默认路由接口。
	if out, err := exec.Command("route", "-n", "get", dstIP.String()).Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "interface:") {
				name := strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
				if name != "" {
					return name
				}
			}
		}
	}

	// 回退: 枚举所有接口，取第一个非 loopback 的 IPv4 接口。
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					return iface.Name
				}
			}
		}
	}

	// macOS 默认。
	return "en0"
}

func resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}


// getLocalIP 返回指定接口的第一个 IPv4 地址。
func getLocalIP(ifaceName string) net.IP {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4
			}
		}
	}
	return nil
}

func getTTL(pkt *packet.Packet) uint8 {
	if ipLayer := pkt.GetLayer("IP"); ipLayer != nil {
		if ttl, err := ipLayer.Get("ttl"); err == nil && ttl != nil {
			return ttl.(uint8)
		}
	}
	return 0
}

func getICMPInfo(pkt *packet.Packet) (uint8, uint8) {
	if icmpLayer := pkt.GetLayer("ICMP"); icmpLayer != nil {
		t, _ := icmpLayer.Get("type")
		c, _ := icmpLayer.Get("code")
		var typ, cod uint8
		if t != nil {
			typ = t.(uint8)
		}
		if c != nil {
			cod = c.(uint8)
		}
		return typ, cod
	}
	return 255, 255
}

func average(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stdDev(vals []float64, mean float64) float64 {
	if len(vals) <= 1 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		d := v - mean
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(vals)))
}