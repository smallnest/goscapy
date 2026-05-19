// 示例 12: 发送并接收示例（SendRecv/SendRecv1）
//
// ⚠️  需要 root 权限: sudo go run main.go
//
// 本示例演示如何发送数据包并等待响应（类似 Ping 的请求/响应模式）。
// 你将学到:
//   - SendRecv1() 发送一个包并等待一个响应
//   - SendRecv() 发送一个包并收集多个响应
//   - 如何解析收到的响应包并提取字段
//   - 超时设置的重要性
//   - BPF 过滤在响应匹配中的作用
//
// 运行方式: sudo go run main.go [接口名]
// 示例:     sudo go run main.go en0       (macOS)
//           sudo go run main.go eth0      (Linux)
//
// 注意: 发送/接收原始数据包需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	fmt.Println("=== goscapy 示例 12: 发送并接收 ===")
	fmt.Println()

	iface := "en0"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	fmt.Printf("使用网络接口: %s\n", iface)
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第一部分: SendRecv1 - 发送一个包，等待一个响应
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: SendRecv1 (Ping) ---")
	fmt.Println()
	fmt.Println("SendRecv1() 发送一个包并等待第一个响应，类似于 Ping。")
	fmt.Println("它会在发送前打开接收器，避免错过快速响应。")
	fmt.Println()

	// 构建 ICMP Echo Request
	pingPkt := goscapy.NewEthernet().
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP("127.0.0.1").                // 回环地址
			TTL(64).
			Proto(layers.IPProtoICMP)).
		Over(goscapy.NewICMP().
			Type(layers.ICMPEchoRequest).
			Code(0).
			ID(0xABCD).
			Seq(1)).
		Packet()

	fmt.Println("发送 ICMP Echo Request 到 127.0.0.1...")
	timeout := 3 * time.Second

	sent, received, err := sendrecv.SendRecv1(pingPkt, iface, timeout)
	if err != nil {
		fmt.Printf("  SendRecv1 失败 (需要 root 权限): %v\n", err)
		fmt.Println("  请使用: sudo go run main.go")
	} else {
		fmt.Println("  发送成功!")
		if received != nil {
			fmt.Printf("  收到响应!\n")

			// 解析响应包
			for _, layer := range received.Layers() {
				fmt.Printf("    Layer: %s\n", layer.Proto())
			}

			// 检查是否是 ICMP Echo Reply
			icmpLayer := received.GetLayer("ICMP")
			if icmpLayer != nil {
				icmpType, _ := icmpLayer.Get("type")
				icmpCode, _ := icmpLayer.Get("code")
				fmt.Printf("    ICMP 类型: %v (0=Echo Reply)\n", icmpType)
				fmt.Printf("    ICMP 代码: %v\n", icmpCode)
			}
		} else {
			fmt.Printf("  未收到响应 (超时 %v)\n", timeout)
		}

		// 检查发送包
		if sent != nil {
			_ = sent // 发送的包，可用于验证
		}
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第二部分: SendRecv - 发送一个包，收集多个响应
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: SendRecv (多响应收集) ---")
	fmt.Println()
	fmt.Println("SendRecv() 发送一个包，然后在超时时间内收集所有收到的包。")
	fmt.Println("适用于广播包（可能收到多个响应）的场景。")
	fmt.Println()

	broadcastPkt := goscapy.NewEthernet().
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP("127.0.0.1").
			TTL(64).
			Proto(layers.IPProtoICMP)).
		Over(goscapy.NewICMP().
			Type(layers.ICMPEchoRequest).
			Code(0).
			ID(0xDCBA).
			Seq(1)).
		Packet()

	fmt.Println("发送 ICMP Echo Request (收集模式)...")
	_, responses, err := sendrecv.SendRecv(broadcastPkt, iface, 2*time.Second)
	if err != nil {
		fmt.Printf("  SendRecv 失败 (需要 root 权限): %v\n", err)
	} else {
		fmt.Printf("  收到 %d 个响应\n", len(responses))
		for i, resp := range responses {
			fmt.Printf("  响应 %d:\n", i+1)
			for _, layer := range resp.Layers() {
				fmt.Printf("    - %s\n", layer.Proto())
			}
		}
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: 使用 Receiver 接口手动收包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: OpenReceiver 手动收包 ---")
	fmt.Println()
	fmt.Println("如果需要更精细的控制，可以使用 OpenReceiver 手动管理接收流程。")
	fmt.Println()

	rx, err := sendrecv.OpenReceiver(iface)
	if err != nil {
		fmt.Printf("  打开接收器失败 (需要 root 权限): %v\n", err)
		fmt.Println("  请使用: sudo go run main.go")
	} else {
		defer rx.Close()

		fmt.Println("  等待数据包 (超时 2 秒)...")
		pkt, err := rx.Recv(2 * time.Second)
		if err != nil {
			fmt.Printf("  接收超时或错误: %v\n", err)
		} else {
			fmt.Printf("  收到包! 协议层:\n")
			for _, layer := range pkt.Layers() {
				fmt.Printf("    - %s\n", layer.Proto())
			}
		}
	}

	// 避免未使用的 import 错误
	_ = log.Println

	// -----------------------------------------------------------------------
	// API 参考
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- API 参考 ---")
	fmt.Println()
	fmt.Println("  sendrecv.SendRecv1(pkt, iface, timeout)")
	fmt.Println("    → 发送一个包，返回第一个响应")
	fmt.Println("    → 返回: (sent, received, error)")
	fmt.Println()
	fmt.Println("  sendrecv.SendRecv(pkt, iface, timeout)")
	fmt.Println("    → 发送一个包，收集所有响应直到超时")
	fmt.Println("    → 返回: (sent, []*response, error)")
	fmt.Println()
	fmt.Println("  sendrecv.OpenReceiver(iface)")
	fmt.Println("    → 打开接收器，手动调用 Recv()")
	fmt.Println("    → 记得调用 Close() 释放资源")
	fmt.Println()
	fmt.Println("  sendrecv.OpenFilteredReceiver(iface, bpfInstructions)")
	fmt.Println("    → 打开带 BPF 过滤的接收器")
	fmt.Println()
	fmt.Println("下一步: 运行 13-tcp-syn-scan 示例，学习 TCP 端口扫描")
}
