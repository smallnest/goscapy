// 示例 36: Token Bucket 限速发包
//
// 本示例演示如何使用 TokenBucketLimiter 控制发包速率。
// 适用于扫描、探测等需要控制发包速率避免触发防火墙限制的场景。
//
// 运行方式: sudo go run main.go [-I <接口>] [-dst <目标IP>] [-pps <每秒包数>] [-n <总包数>]
// 示例:     sudo go run main.go -dst 192.168.1.1 -pps 100 -n 500
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW。

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	dst := flag.String("dst", "192.168.1.1", "目标 IP 地址")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	pps := flag.Int("pps", 100, "每秒包数 (packets per second)")
	burst := flag.Int("burst", 0, "突发容量 (默认 pps/10)")
	n := flag.Int("n", 200, "总发包数 (0=无限)")
	flag.Parse()

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	fmt.Printf("限速发包: dst=%s, iface=%s, pps=%d, burst=%d, count=%d\n",
		*dst, ifaceVal, *pps, *burst, *n)

	// 获取本机 IP 作为源地址
	srcIP := getLocalIP(ifaceVal)
	if srcIP == nil {
		fmt.Fprintf(os.Stderr, "无法获取接口 %s 的本地 IP\n", ifaceVal)
		os.Exit(1)
	}
	fmt.Printf("源地址: %s\n\n", srcIP)

	// 创建限速器
	limiter := sendrecv.NewTokenBucketLimiter(*pps, *burst)

	// 构建 ICMP Echo Request 包
	ip := layers.NewIP()
	ip.Set("src", srcIP.String())
	ip.Set("dst", *dst)
	ip.Set("proto", layers.IPProtoICMP)

	icmp := layers.NewICMPEcho(0x1234, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n收到中断信号，停止发送...")
		cancel()
	}()

	start := time.Now()
	sent := 0

	for i := 0; *n == 0 || i < *n; i++ {
		// 更新序列号
		icmp.Set("seq", uint16(i&0xffff))

		pkt := packet.NewFrom(ip, icmp)

		if err := sendrecv.SendWithLimiter(ctx, pkt, ifaceVal, limiter); err != nil {
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintf(os.Stderr, "发送失败 [%d]: %v\n", i, err)
			continue
		}
		sent++

		if sent%(*pps) == 0 {
			elapsed := time.Since(start).Seconds()
			actualPPS := float64(sent) / elapsed
			fmt.Printf("  已发送 %d 包, 耗时 %.2fs, 实际速率 %.1f pps\n",
				sent, elapsed, actualPPS)
		}
	}

	elapsed := time.Since(start)
	actualPPS := float64(sent) / elapsed.Seconds()
	fmt.Printf("\n--- 统计 ---\n")
	fmt.Printf("发送: %d 包, 耗时: %.2fs, 实际速率: %.1f pps (目标: %d pps)\n",
		sent, elapsed.Seconds(), actualPPS, *pps)
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
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
	return "eth0"
}

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
