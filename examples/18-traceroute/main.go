// 示例 18: Traceroute 工具
//
// 本示例演示如何使用 goscapy 实现 Traceroute（路由追踪）工具。
// 你将学到:
//   - TTL (Time To Live) 递增技术追踪路由路径
//   - ICMP Time Exceeded 消息的解析
//   - 每跳多探测包实现延迟测量
//   - 使用 sendrecv 进行数据包发送与接收匹配
//
// 运行方式: sudo go run main.go [选项] <目标>
// 示例:     sudo go run main.go 8.8.8.8
//           sudo go run main.go -m 15 -q 3 google.com
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	maxHops := flag.Int("m", 30, "最大跳数")
	nqueries := flag.Int("q", 3, "每跳探测包数量")
	timeout := flag.Duration("w", 2*time.Second, "每跳探测超时")
	iface := flag.String("I", "", "网络接口 (默认自动检测)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go [选项] <目标>\n")
		fmt.Fprintf(os.Stderr, "示例: sudo go run main.go 8.8.8.8\n")
		fmt.Fprintf(os.Stderr, "      sudo go run main.go -m 15 google.com\n")
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

	fmt.Printf("traceroute to %s (%s), %d hops max, %d probes per hop\n", target, ip, *maxHops, *nqueries)
	fmt.Printf("  使用接口: %s (本地 IP: %s)\n\n", nic, srcIP)

	pid := uint16(os.Getpid() & 0xFFFF)

	// 自定义 MatchFunc 用以匹配返回的 ICMP Echo Reply 或 ICMP Time Exceeded / Dest Unreachable。
	match := func(sent, received *packet.Packet) bool {
		// 获取接收报文的 IP 和 ICMP 层。
		recvIP := received.GetLayer("IP")
		recvICMP := received.GetLayer("ICMP")
		if recvIP == nil || recvICMP == nil {
			return false
		}

		recvTypeVal, err := recvICMP.Get("type")
		if err != nil || recvTypeVal == nil {
			return false
		}
		recvType, ok := recvTypeVal.(uint8)
		if !ok {
			return false
		}

		sentIP := sent.GetLayer("IP")
		sentICMP := sent.GetLayer("ICMP")
		if sentIP == nil || sentICMP == nil {
			return false
		}

		var sentDstIP net.IP
		if dstVal, err := sentIP.Get("dst"); err == nil && dstVal != nil {
			sentDstIP, _ = dstVal.(net.IP)
		}
		if sentDstIP == nil {
			return false
		}

		var sentID uint16
		if idVal, err := sentICMP.Get("id"); err == nil && idVal != nil {
			sentID, _ = idVal.(uint16)
		}
		var sentSeq uint16
		if seqVal, err := sentICMP.Get("seq"); err == nil && seqVal != nil {
			sentSeq, _ = seqVal.(uint16)
		}

		switch recvType {
		case 0: // Echo Reply
			// 响应源 IP 必须是目标 IP。
			var recvSrcIP net.IP
			if srcVal, err := recvIP.Get("src"); err == nil && srcVal != nil {
				recvSrcIP, _ = srcVal.(net.IP)
			}
			if recvSrcIP == nil || !recvSrcIP.Equal(sentDstIP) {
				return false
			}

			// ICMP 标识符和序列号必须匹配。
			var recvID uint16
			if idVal, err := recvICMP.Get("id"); err == nil && idVal != nil {
				recvID, _ = idVal.(uint16)
			}
			var recvSeq uint16
			if seqVal, err := recvICMP.Get("seq"); err == nil && seqVal != nil {
				recvSeq, _ = seqVal.(uint16)
			}

			return recvID == sentID && recvSeq == sentSeq

		case 3, 11: // Destination Unreachable 或 Time Exceeded
			// 导致错误的原始数据包被嵌入在 ICMP 负荷 (Raw layer) 中。
			rawLayer := received.GetLayer("Raw")
			if rawLayer == nil {
				return false
			}
			loadVal, err := rawLayer.Get("load")
			if err != nil || loadVal == nil {
				return false
			}
			loadBytes, ok := loadVal.([]byte)
			if !ok {
				return false
			}

			// 解包原始报文（从 IP 层开始解析）。
			innerPkt, err := packet.DissectByProto(loadBytes, "IP")
			if err != nil {
				return false
			}

			innerIP := innerPkt.GetLayer("IP")
			innerICMP := innerPkt.GetLayer("ICMP")
			if innerIP == nil || innerICMP == nil {
				return false
			}

			// 内部包的目的 IP 必须匹配我们的目标 IP，且 ICMP 标识符及序列号匹配。
			var innerDstIP net.IP
			if dstVal, err := innerIP.Get("dst"); err == nil && dstVal != nil {
				innerDstIP, _ = dstVal.(net.IP)
			}
			if innerDstIP == nil || !innerDstIP.Equal(sentDstIP) {
				return false
			}

			var innerID uint16
			if idVal, err := innerICMP.Get("id"); err == nil && idVal != nil {
				innerID, _ = idVal.(uint16)
			}
			var innerSeq uint16
			if seqVal, err := innerICMP.Get("seq"); err == nil && seqVal != nil {
				innerSeq, _ = seqVal.(uint16)
			}

			return innerID == sentID && innerSeq == sentSeq
		}

		return false
	}

	for ttl := 1; ttl <= *maxHops; ttl++ {
		fmt.Printf("%2d  ", ttl)

		var routerIP string
		var rtts []string
		reachedTarget := false

		for probe := 0; probe < *nqueries; probe++ {
			// 构建 IP + ICMP Echo Request 报文
			ipLayer := layers.NewIP()
			ipLayer.Set("src", srcIP)
			ipLayer.Set("dst", dstIP)
			ipLayer.Set("ttl", uint8(ttl))
			icmpLayer := layers.NewICMPEcho(pid, uint16(ttl*1000+probe))
			pkt := ipLayer.Over(icmpLayer)

			start := time.Now()
			// Sr1: 发送并接收匹配的响应包
			_, resp, recvErr := sendrecv.Sr1(pkt, nic, *timeout, match)
			rtt := time.Since(start)

			if recvErr != nil {
				if errors.Is(recvErr, sendrecv.ErrTimeout) || resp == nil {
					rtts = append(rtts, "*")
				} else {
					rtts = append(rtts, "?")
				}
			} else if resp == nil {
				rtts = append(rtts, "*")
			} else {
				respIPLayer := resp.GetLayer("IP")
				if respIPLayer != nil {
					if srcVal, err := respIPLayer.Get("src"); err == nil && srcVal != nil {
						routerIP = srcVal.(net.IP).String()
					}
				}

				respICMPLayer := resp.GetLayer("ICMP")
				if respICMPLayer != nil {
					if typeVal, err := respICMPLayer.Get("type"); err == nil && typeVal != nil {
						if typeVal.(uint8) == 0 { // Echo Reply (说明到达了最终目标)
							reachedTarget = true
						}
					}
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