// 示例 18: Traceroute 工具
//
// 本示例演示如何使用 goscapy 实现 Traceroute（路由追踪）工具。
// 你将学到:
//   - TTL (Time To Live) 递增技术追踪路由路径
//   - ICMP Time Exceeded 消息的解析
//   - 每跳多探测包实现延迟测量
//   - 并发（每跳多个探测包）提高追踪速度
//
// 运行方式: sudo go run main.go [选项] <目标>
// 示例:     sudo go run main.go 8.8.8.8
//           sudo go run main.go -m 15 -q 3 google.com
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	maxHops := flag.Int("m", 30, "最大跳数")
	nqueries := flag.Int("q", 3, "每跳探测包数量")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go [选项] <目标>\n")
		fmt.Fprintf(os.Stderr, "示例: sudo go run main.go 8.8.8.8\n")
		fmt.Fprintf(os.Stderr, "      sudo go run main.go -m 15 google.com\n")
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

	fmt.Printf("traceroute to %s (%s), %d hops max, %d probes per hop\n\n",
		target, ip, *maxHops, *nqueries)

	pid := uint16(os.Getpid() & 0xFFFF)

	for ttl := 1; ttl <= *maxHops; ttl++ {
		fmt.Printf("%2d  ", ttl)

		var routerIP string
		var rtts []string
		reachedTarget := false

		for probe := 0; probe < *nqueries; probe++ {
			start := time.Now()
			pkt := buildProbe(ip, pid, uint16(ttl), uint16(probe))
			_, reply, err := sendrecv.SendRecv1(pkt, *iface, 2*time.Second)
			rtt := time.Since(start)

			if err != nil {
				fmt.Fprintf(os.Stderr, "发送失败: %v\n", err)
				os.Exit(1)
			}

			if reply == nil {
				rtts = append(rtts, "*")
			} else {
				srcIP := getSrcIP(reply)
				icmpType, _ := getICMPInfo(reply)

				if srcIP != "" {
					routerIP = srcIP
				}

				if icmpType == 0 { // Echo Reply - reached target
					reachedTarget = true
				}

				rtts = append(rtts, fmt.Sprintf("%.2f ms", rtt.Seconds()*1000))
			}
		}

		if routerIP == "" {
			fmt.Println(strings.Join(rtts, "  "))
		} else {
			fmt.Printf("%s (%s)  %s\n", routerIP, routerIP, strings.Join(rtts, "  "))
		}

		if reachedTarget {
			fmt.Println("\n已到达目标。")
			break
		}
	}
}

func buildProbe(dstIP string, id, ttl, seq uint16) *packet.Packet {
	return goscapy.NewEthernet().
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP(dstIP).
			TTL(uint8(ttl)).
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

func getSrcIP(pkt *packet.Packet) string {
	if ipLayer := pkt.GetLayer("IP"); ipLayer != nil {
		if src, err := ipLayer.Get("src"); err == nil && src != nil {
			return src.(string)
		}
	}
	return ""
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