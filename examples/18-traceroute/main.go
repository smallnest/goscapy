// 示例 18: Traceroute 工具
//
// 本示例演示如何使用 goscapy 实现 Traceroute（路由追踪）工具。
// 你将学到:
//   - TTL (Time To Live) 递增技术追踪路由路径
//   - ICMP Time Exceeded 消息的解析
//   - 每跳多探测包实现延迟测量
//   - 原始 ICMP socket 的使用 (与 ping 示例相同的方式)
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
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	maxHops := flag.Int("m", 30, "最大跳数")
	nqueries := flag.Int("q", 3, "每跳探测包数量")
	timeout := flag.Duration("w", 2*time.Second, "每跳探测超时")
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

	fmt.Printf("traceroute to %s (%s), %d hops max, %d probes per hop\n\n",
		target, ip, *maxHops, *nqueries)

	// 打开 raw ICMP socket。使用 IPPROTO_ICMP 而非 IPPROTO_RAW，
	// 内核会处理 IP 头部并正确投递 ICMP 回复到我们的 socket。
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法创建 ICMP socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	pid := uint16(os.Getpid() & 0xFFFF)

	dstIP := net.ParseIP(ip).To4()
	if dstIP == nil {
		fmt.Fprintf(os.Stderr, "无效的 IPv4 地址: %s\n", ip)
		os.Exit(1)
	}
	var addr [4]byte
	copy(addr[:], dstIP)
	sockAddr := &syscall.SockaddrInet4{Addr: addr}

	for ttl := 1; ttl <= *maxHops; ttl++ {
		fmt.Printf("%2d  ", ttl)

		// 设置 TTL
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
			fmt.Fprintf(os.Stderr, "设置 TTL 失败: %v\n", err)
			os.Exit(1)
		}

		var routerIP string
		var rtts []string
		reachedTarget := false

		for probe := 0; probe < *nqueries; probe++ {
			start := time.Now()

			// 用 goscapy 构建 ICMP Echo Request 报文
			icmpBytes, err := buildICMPEchoRequest(pid, uint16(probe))
			if err != nil {
				fmt.Fprintf(os.Stderr, "构建 ICMP 报文失败: %v\n", err)
				os.Exit(1)
			}

			// 发送 ICMP Echo Request
			if err := syscall.Sendto(fd, icmpBytes, 0, sockAddr); err != nil {
				fmt.Fprintf(os.Stderr, "发送失败: %v\n", err)
				os.Exit(1)
			}

			// 设置读取超时
			tv := syscall.NsecToTimeval(timeout.Nanoseconds())
			syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

			// 接收 ICMP 回复 (recvfrom 返回 IP 头 + ICMP 头)
			buf := make([]byte, 1500)
			n, _, recvErr := syscall.Recvfrom(fd, buf, 0)

			rtt := time.Since(start)

			if recvErr != nil {
				rtts = append(rtts, "*")
			} else {
				// 用 goscapy 从 IP 层解析收到的回复
				replyPkt, err := packet.DissectByProto(buf[:n], "IP")
				if err != nil {
					rtts = append(rtts, "*")
				} else {
					srcIP := getSrcIP(replyPkt)
					icmpType, _ := getICMPInfo(replyPkt)

					if srcIP != "" {
						routerIP = srcIP
					}

					if icmpType == 0 { // Echo Reply - reached target
						reachedTarget = true
					}

					rtts = append(rtts, fmt.Sprintf("%.2f ms", rtt.Seconds()*1000))
				}
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

// buildICMPEchoRequest 用 goscapy 构建 ICMP Echo Request 报文（ICMP 头 + 56 字节 payload）。
func buildICMPEchoRequest(id, seq uint16) ([]byte, error) {
	icmpLayer := layers.NewICMPEcho(id, seq)
	hdrBytes, err := icmpLayer.SerializeFields()
	if err != nil {
		return nil, err
	}

	// 附加 56 字节 payload (标准 ping 数据大小)
	payload := make([]byte, 56)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}

	pkt := make([]byte, 0, len(hdrBytes)+len(payload))
	pkt = append(pkt, hdrBytes...)
	pkt = append(pkt, payload...)

	// 计算 ICMP 校验和
	csum := layers.ICMPChecksum(pkt)
	// 写回校验和字段 (offset 2, 2 bytes)
	pkt[2] = byte(csum >> 8)
	pkt[3] = byte(csum)

	return pkt, nil
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

func getSrcIP(pkt *packet.Packet) string {
	if ipLayer := pkt.GetLayer("IP"); ipLayer != nil {
		if src, err := ipLayer.Get("src"); err == nil && src != nil {
			return src.(net.IP).String()
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