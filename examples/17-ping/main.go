// 示例 17: Ping 工具
//
// 本示例演示如何使用 goscapy 实现真实的 Ping 工具。
// 你将学到:
//   - ICMP Echo Request/Reply 的发送与接收
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
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	count := flag.Int("c", 4, "发包次数")
	interval := flag.Duration("i", time.Second, "发包间隔")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go [选项] <目标>\n")
		fmt.Fprintf(os.Stderr, "示例: sudo go run main.go 8.8.8.8\n")
		fmt.Fprintf(os.Stderr, "      sudo go run main.go -c 10 google.com\n")
		os.Exit(1)
	}

	target := flag.Arg(0)
	if *iface == "" {
		*iface = defaultIface()
	}

	ip, err := resolveHost(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 %s 失败: %v\n", target, err)
		os.Exit(1)
	}

	fmt.Printf("PING %s (%s): %d data bytes\n", target, ip, 56)
	if ip != target {
		fmt.Printf("  解析到: %s\n", ip)
	}

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

loop:
	for seq := 1; seq <= *count; seq++ {
		select {
		case <-done:
			break loop
		default:
		}

		start := time.Now()

		pkt := buildPingPacket(ip, pid, uint16(seq))
		sent++

		_, reply, err := sendrecv.SendRecv1(pkt, *iface, *interval)
		rtt := time.Since(start).Seconds() * 1000

		if err != nil {
			fmt.Fprintf(os.Stderr, "发送失败: %v\n", err)
			os.Exit(1)
		}

		if reply == nil {
			fmt.Printf("请求超时 (seq=%d)\n", seq)
		} else {
			ttl := getTTL(reply)
			icmpType, icmpCode := getICMPInfo(reply)

			if icmpType == 0 { // Echo Reply
				received++
				rtts = append(rtts, rtt)
				fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
					84, ip, seq, ttl, rtt)
			} else if icmpType == 3 {
				fmt.Printf("来自 %s 的目标不可达 (type=%d, code=%d)\n", ip, icmpType, icmpCode)
			} else {
				fmt.Printf("来自 %s 的响应: type=%d, code=%d, seq=%d\n", ip, icmpType, icmpCode, seq)
			}
		}

		elapsed := time.Since(start)
		if seq < *count && sent < *count && elapsed < *interval {
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

func buildPingPacket(dstIP string, id, seq uint16) *packet.Packet {
	return goscapy.NewEthernet().
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP(dstIP).
			TTL(64).
			Proto(layers.IPProtoICMP)).
		Over(goscapy.NewICMP().
			Type(layers.ICMPEchoRequest).
			Code(0).
			ID(id).
			Seq(seq)).
		Packet()
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