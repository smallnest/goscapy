// 示例 67: 应答机实例 — ICMP / ARP / DNS 响应器（需 root）
//
// 本示例演示 pkg/answer/responders 提供的开箱即用应答机实例:
//   - responders.ICMPEchoResponder — 响应 ping
//   - responders.ARPResponder      — 响应指定 IP 的 ARP who-has
//   - responders.DNSResponder      — 用静态 zone 回答 A 查询
//
// 三者都基于 pkg/answer 的 AnsweringMachine 框架，适合做测试桩或蜜罐。
//
// ⚠️ ARP/DNS 响应会影响同网段其他主机，仅在授权测试网络中使用。
//
// 运行方式:
//   sudo go run main.go icmp <iface>
//   sudo go run main.go arp  <iface> <本机IP> <本机MAC>
//   sudo go run main.go dns  <iface>

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/smallnest/goscapy/pkg/answer"
	"github.com/smallnest/goscapy/pkg/answer/responders"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}
	mode, iface := os.Args[1], os.Args[2]

	var am *answer.AnsweringMachine
	switch mode {
	case "icmp":
		am = responders.ICMPEchoResponder(iface)
		fmt.Printf("ICMP Echo 响应器启动于 %s（Ctrl-C 停止）\n", iface)

	case "arp":
		if len(os.Args) < 5 {
			usage()
			os.Exit(1)
		}
		am = responders.ARPResponder(iface, os.Args[3], os.Args[4])
		fmt.Printf("ARP 响应器: 对 %s 的 who-has 回复 %s\n", os.Args[3], os.Args[4])

	case "dns":
		// 静态 zone：把几个域名解析到固定 IP。
		zone := map[string]string{
			"example.com":  "93.184.216.34",
			"test.local":   "10.0.0.10",
			"goscapy.test": "192.0.2.1",
		}
		am = responders.DNSResponder(iface, responders.StaticDNSResolver(zone, 300))
		fmt.Printf("DNS 响应器启动于 %s，已加载 %d 条 A 记录\n", iface, len(zone))

	default:
		usage()
		os.Exit(1)
	}

	// 加上日志回调，观察每次应答。
	am.SetOnReply(func(_, reply *packet.Packet) {
		fmt.Printf("已应答: %s\n", reply.Summary())
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	n, err := am.Run(ctx)
	fmt.Printf("\n共发送 %d 个应答\n", n)
	if err != nil && err != context.Canceled {
		fmt.Printf("错误: %v\n", err)
	}
}

func usage() {
	fmt.Println("用法:")
	fmt.Println("  sudo go run main.go icmp <iface>")
	fmt.Println("  sudo go run main.go arp  <iface> <本机IP> <本机MAC>")
	fmt.Println("  sudo go run main.go dns  <iface>")
}
