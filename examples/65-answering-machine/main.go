// 示例 65: 应答机框架 — AnsweringMachine（ARP 响应器，需 root）
//
// 本示例演示 goscapy 借鉴 Scapy AnsweringMachine 的服务仿真框架。
// 它实现一个简单的 ARP 响应器：监听 who-has 请求，对指定 IP 回复 is-at。
//
// 框架负责 嗅探 → 判定 → 构造回复 → 发送 的循环；调用方只需提供:
//   - IsRequest(pkt) — 是否是需要应答的请求
//   - MakeReply(pkt) — 构造回复包
//
// ⚠️ ARP 响应器会影响同网段主机的 ARP 缓存，仅在授权测试网络中使用。
//
// 运行方式: sudo go run main.go <监听iface> <本机IP> <本机MAC>

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/smallnest/goscapy/pkg/answer"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("用法: sudo go run main.go <iface> <本机IP> <本机MAC>")
		fmt.Println("示例: sudo go run main.go eth0 192.168.1.50 aa:bb:cc:dd:ee:ff")
		os.Exit(1)
	}
	iface, myIP, myMAC := os.Args[1], os.Args[2], os.Args[3]

	am := answer.New(answer.Config{
		Iface:  iface,
		SendL2: true, // ARP 在链路层应答
	}, answer.Funcs{
		// 判定: 是 who-has 且询问的是本机 IP。
		IsRequest: func(pkt *packet.Packet) bool {
			arp := pkt.GetLayer("ARP")
			if arp == nil {
				return false
			}
			op, _ := arp.Get("op")
			if op.(uint16) != layers.ARPWhoHas {
				return false
			}
			pdst, _ := arp.Get("pdst")
			return fmt.Sprintf("%v", pdst) == myIP
		},
		// 构造回复: is-at，把发送方/目标地址对调。
		MakeReply: func(pkt *packet.Packet) (*packet.Packet, bool) {
			req := pkt.GetLayer("ARP")
			reqHwsrc, _ := req.Get("hwsrc")
			reqPsrc, _ := req.Get("psrc")

			eth := layers.NewEthernetWith(fmt.Sprintf("%v", reqHwsrc), myMAC, layers.EtherTypeARP)
			arp := layers.NewARP()
			_ = arp.Set("op", layers.ARPIsAt)
			_ = arp.Set("hwsrc", myMAC)
			_ = arp.Set("psrc", myIP)
			_ = arp.Set("hwdst", fmt.Sprintf("%v", reqHwsrc))
			_ = arp.Set("pdst", fmt.Sprintf("%v", reqPsrc))
			return packet.NewFrom(eth, arp), true
		},
		OnReply: func(_, reply *packet.Packet) {
			fmt.Printf("已回复: %s\n", reply.Summary())
		},
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("ARP 响应器启动: 对 %s 的 who-has 回复 %s（Ctrl-C 停止）\n", myIP, myMAC)
	n, err := am.Run(ctx)
	fmt.Printf("\n共发送 %d 个回复\n", n)
	if err != nil && err != context.Canceled {
		fmt.Printf("错误: %v\n", err)
	}
}
