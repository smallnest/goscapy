// 示例 64: 循环探测 — SrLoop / SrFlood（需 root）
//
// 本示例演示 goscapy 借鉴 Scapy srloop()/srflood() 的主动探测原语:
//   - sendrecv.SrLoop  — 循环发送并匹配响应，适合延迟探测/存活监控
//   - sendrecv.SrFlood — 高速洪泛（可限速），用于授权压测
//
// ⚠️ 仅对你有授权测试的主机使用洪泛功能；高 PPS 可能打满链路或触发 IDS。
//
// 运行方式: sudo go run main.go <目标IP> [iface]

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: sudo go run main.go <目标IP> [iface]")
		fmt.Println("示例: sudo go run main.go 8.8.8.8 eth0")
		os.Exit(1)
	}
	dst := os.Args[1]
	iface := "eth0"
	if len(os.Args) >= 3 {
		iface = os.Args[2]
	}

	// 构造 ICMP Echo 探测包。
	ip := layers.NewIP()
	_ = ip.Set("dst", dst)
	_ = ip.Set("proto", layers.IPProtoICMP)
	icmp := layers.NewICMPEcho(0x1234, 1)
	pkt := packet.NewFrom(ip, icmp)

	fmt.Printf("=== SrLoop: 向 %s 发送 5 次 ICMP Echo，间隔 1s ===\n", dst)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := sendrecv.SrLoop(ctx, pkt, iface, sendrecv.SrLoopOptions{
		Count:    5,
		Interval: time.Second,
		Timeout:  time.Second,
	}, func(r sendrecv.LoopResult) {
		if r.Response != nil {
			fmt.Printf("  回复 RTT=%v\n", r.RTT.Round(time.Microsecond))
		} else {
			fmt.Println("  超时（无回复）")
		}
	})
	if err != nil && err != context.DeadlineExceeded {
		fmt.Printf("SrLoop 错误: %v\n", err)
	}

	got := 0
	for _, r := range results {
		if r.Response != nil {
			got++
		}
	}
	fmt.Printf("发送 %d 个，收到 %d 个回复\n", len(results), got)
}
