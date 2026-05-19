// 示例 03: ICMP Echo Request 构建示例
//
// 本示例演示如何构建 ICMP Echo Request（Ping 请求）数据包。
// 你将学到:
//   - ICMP 协议在 Ping 中的作用
//   - 如何使用 ICMP Builder 设置类型、代码、ID、序列号
//   - 如何使用 Shortcut 函数快速构建 ICMP 包
//   - Builder API 和 Shortcut 函数的对比
//
// 运行方式: go run main.go
// 注意: 本示例仅构建数据包，不需要 root 权限。

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

func main() {
	fmt.Println("=== goscapy 示例 03: ICMP Echo Request (Ping) ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// ICMP 协议简介
	// -----------------------------------------------------------------------
	// ICMP (Internet Control Message Protocol) 是 IP 层的辅助协议。
	// Ping 命令使用 ICMP Echo Request (type=8) 和 Echo Reply (type=0) 来测试
	// 目标主机是否可达。
	//
	// ICMP Echo 消息包含:
	//   - Type: 8 (Echo Request) 或 0 (Echo Reply)
	//   - Code: 0
	//   - ID: 标识符，用于匹配请求和回复
	//   - Seq: 序列号，每发一个 Ping 递增 1
	//   - Data: 可选的数据载荷

	// -----------------------------------------------------------------------
	// 第一部分: Builder API 构建 ICMP Echo Request
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: Builder API 构建 ICMP Echo Request ---")
	fmt.Println()

	// 从底层到顶层逐层叠加: Ethernet → IPv4 → ICMP
	icmpPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").      // 目标 MAC (网关或目标主机)
		SrcMAC("00:11:22:33:44:55").       // 源 MAC
		Type(layers.EtherTypeIPv4).        // 上层协议: IPv4
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").         // 源 IP
			DstIP("8.8.8.8").               // 目标 IP (Google DNS)
			TTL(64).                         // 生存时间
			Proto(layers.IPProtoICMP)).      // 上层协议: ICMP (1)
		Over(goscapy.NewICMP().
			Type(layers.ICMPEchoRequest).    // ICMP 类型: Echo Request (8)
			Code(0).                          // ICMP 代码: 0
			ID(0x1234).                       // 标识符: 0x1234
			Seq(1))                           // 序列号: 1

	icmpBytes, err := icmpPkt.Build()
	if err != nil {
		log.Fatalf("构建 ICMP 包失败: %v", err)
	}

	fmt.Printf("ICMP Echo Request 构建成功!\n")
	fmt.Printf("  总长度: %d 字节\n", len(icmpBytes))
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(icmpBytes))

	// -----------------------------------------------------------------------
	// 第二部分: Shortcut 函数快速构建
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: Shortcut 函数一行构建 ---")
	fmt.Println()

	// EtherIPICMP 是最快捷的方式，一行代码即可构建完整的 ICMP 包
	shortcutBytes, err := goscapy.EtherIPICMP(
		"00:aa:bb:cc:dd:ee",    // 目标 MAC
		"8.8.8.8",               // 目标 IP
		8,                        // ICMP Type: Echo Request
		0,                        // ICMP Code: 0
	)
	if err != nil {
		log.Fatalf("Shortcut 构建 ICMP 包失败: %v", err)
	}

	fmt.Printf("Shortcut ICMP 包: %d 字节\n", len(shortcutBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: 构建 ICMP Echo Reply
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: ICMP Echo Reply ---")
	fmt.Println()

	// Echo Reply (type=0) 是对 Echo Request 的回应
	echoReplyPkt := goscapy.NewEthernet().
		DstMAC("00:11:22:33:44:55").
		SrcMAC("00:aa:bb:cc:dd:ee").
		Over(goscapy.NewIP().
			SrcIP("8.8.8.8").
			DstIP("192.168.1.100").
			TTL(64).
			Proto(layers.IPProtoICMP)).
		Over(goscapy.NewICMP().
			Type(layers.ICMPEchoReply).     // ICMP 类型: Echo Reply (0)
			Code(0).
			ID(0x1234).                       // 同一个标识符
			Seq(1))                           // 同一个序列号

	replyBytes, err := echoReplyPkt.Build()
	if err != nil {
		log.Fatalf("构建 ICMP Echo Reply 失败: %v", err)
	}

	fmt.Printf("ICMP Echo Reply 构建成功! %d 字节\n", len(replyBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第四部分: L3 层 ICMP 包（无 Ethernet 头）
	// -----------------------------------------------------------------------
	fmt.Println("--- 第四部分: L3 层 ICMP (无 Ethernet 头) ---")
	fmt.Println()

	// 有些场景下不需要 Ethernet 头（比如通过 raw socket 发送 L3 包）
	l3ICMPBytes, err := goscapy.IPICMP(
		"192.168.1.100",  // 源 IP
		"8.8.8.8",         // 目标 IP
		8,                  // ICMP Type: Echo Request
		0,                  // ICMP Code: 0
	)
	if err != nil {
		log.Fatalf("L3 ICMP 构建失败: %v", err)
	}

	fmt.Printf("L3 ICMP 包 (无 Ethernet 头): %d 字节\n", len(l3ICMPBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// ICMP 类型参考
	// -----------------------------------------------------------------------
	fmt.Println("--- ICMP 类型参考 ---")
	fmt.Println()
	fmt.Println("  layers.ICMPEchoRequest  (8)  = Echo 请求 (Ping)")
	fmt.Println("  layers.ICMPEchoReply    (0)  = Echo 回复 (Pong)")
	fmt.Println("  layers.ICMPDestUnreach  (3)  = 目标不可达")
	fmt.Println("  layers.ICMPTimeExceed  (11)  = TTL 超时 (Traceroute)")
	fmt.Println()
	fmt.Println("下一步: 运行 04-arp 示例，学习 ARP 协议")
}
