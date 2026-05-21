// 示例 33: IPv6 Ping (ICMPv6 Echo Request / Reply)
//
// 本示例演示如何使用 goscapy 发送 ICMPv6 Echo Request 并接收 Echo Reply。
// 使用 sendrecv.Send (L3) 自动选择 AF_INET6 路径发送 IPv6 报文。
//
// 运行方式: sudo go run main.go -dst <IPv6地址> [-I <接口>] [-c <次数>]
// 示例:     sudo go run main.go -dst ::1
//           sudo go run main.go -dst fe80::1%en0 -I en0 -c 5
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	dst := flag.String("dst", "::1", "目标 IPv6 地址")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	count := flag.Int("c", 4, "发送 Echo Request 次数")
	timeout := flag.Duration("W", 2*time.Second, "每次等待响应的超时时间")
	flag.Parse()

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIPv6Iface()
	}

	srcIP := getIPv6SrcIP(ifaceVal, *dst)
	if srcIP == "" {
		fmt.Fprintf(os.Stderr, "错误: 无法在接口 %s 上获取有效的 IPv6 源地址\n", ifaceVal)
		os.Exit(1)
	}

	fmt.Printf("PING6 %s from %s via %s\n", *dst, srcIP, ifaceVal)

	id := uint16(os.Getpid() & 0xffff)
	var sent, received int
	var totalRTT time.Duration

	for seq := uint16(1); seq <= uint16(*count); seq++ {
		// 构造 IPv6 / ICMPv6 Echo Request 报文
		ipv6 := layers.NewIPv6()
		ipv6.Set("src", srcIP)
		ipv6.Set("dst", *dst)
		ipv6.Set("nh", layers.IPv6NextHdrICMP)
		ipv6.Set("hlim", uint8(64))

		icmpHdr := layers.NewICMPv6()
		icmpHdr.Set("type", layers.ICMPv6EchoRequest)

		icmpBody := layers.NewICMPv6Echo(id, seq)

		pkt := packet.NewFrom(ipv6, icmpHdr, icmpBody)

		// 打开接收器
		rx, err := sendrecv.OpenReceiver(ifaceVal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 无法打开接收器: %v\n", err)
			os.Exit(1)
		}

		sendTime := time.Now()
		if err := sendrecv.Send(pkt, ifaceVal); err != nil {
			rx.Close()
			fmt.Fprintf(os.Stderr, "发送失败: %v\n", err)
			continue
		}
		sent++

		// 等待匹配的 Echo Reply
		deadline := time.Now().Add(*timeout)
		matched := false

		for time.Now().Before(deadline) {
			remaining := time.Until(deadline)
			resp, err := rx.Recv(remaining)
			if err != nil {
				if errors.Is(err, sendrecv.ErrTimeout) {
					break
				}
				break
			}

			// 检查是否是 ICMPv6 Echo Reply
			icmpLayer := resp.GetLayer("ICMPv6")
			if icmpLayer == nil {
				continue
			}
			typeVal, _ := icmpLayer.Get("type")
			if typeVal != layers.ICMPv6EchoReply {
				continue
			}

			echoLayer := resp.GetLayer("ICMPv6 Echo Reply")
			if echoLayer == nil {
				echoLayer = resp.GetLayer("ICMPv6 Echo")
			}
			if echoLayer == nil {
				continue
			}
			idVal, _ := echoLayer.Get("id")
			seqVal, _ := echoLayer.Get("seq")
			if idVal != id || seqVal != seq {
				continue
			}

			rtt := time.Since(sendTime)
			totalRTT += rtt
			received++
			matched = true

			// 获取源 IP
			ipLayer := resp.GetLayer("IPv6")
			respSrc := *dst
			if ipLayer != nil {
				if s, err := ipLayer.Get("src"); err == nil {
					if ip, ok := s.(net.IP); ok {
						respSrc = ip.String()
					}
				}
			}

			fmt.Printf("%d bytes from %s: icmp_seq=%d time=%.3f ms\n",
				64, respSrc, seq, float64(rtt.Microseconds())/1000.0)
			break
		}

		rx.Close()

		if !matched {
			fmt.Printf("Request timeout for icmp_seq %d\n", seq)
		}

		if seq < uint16(*count) {
			time.Sleep(1 * time.Second)
		}
	}

	fmt.Printf("\n--- %s ping6 statistics ---\n", *dst)
	loss := float64(sent-received) / float64(sent) * 100
	fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n", sent, received, loss)
	if received > 0 {
		avgRTT := totalRTT / time.Duration(received)
		fmt.Printf("rtt avg = %.3f ms\n", float64(avgRTT.Microseconds())/1000.0)
	}
}

func getIPv6SrcIP(iface, dst string) string {
	// For link-local destinations, use the interface's link-local address.
	dstIP := net.ParseIP(dst)

	i, err := net.InterfaceByName(iface)
	if err != nil {
		return ""
	}
	addrs, err := i.Addrs()
	if err != nil || len(addrs) == 0 {
		return ""
	}

	var linkLocal, global string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() != nil {
			continue
		}
		ip6 := ipnet.IP.To16()
		if ip6 == nil {
			continue
		}
		if ip6.IsLinkLocalUnicast() {
			linkLocal = ip6.String()
		} else if ip6.IsGlobalUnicast() {
			global = ip6.String()
		} else if ip6.IsLoopback() {
			if dstIP != nil && dstIP.IsLoopback() {
				return ip6.String()
			}
		}
	}

	if dstIP != nil && dstIP.IsLinkLocalUnicast() && linkLocal != "" {
		return linkLocal
	}
	if global != "" {
		return global
	}
	return linkLocal
}

func defaultIPv6Iface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "lo0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() == nil && ipnet.IP.To16() != nil {
				return iface.Name
			}
		}
	}
	return sendrecv.LoopbackName()
}
