// 示例 04: ARP 包构建示例
//
// 本示例演示如何构建 ARP 请求和 ARP 应答数据包。
// 你将学到:
//   - ARP 协议在局域网中的作用（IP 地址到 MAC 地址的映射）
//   - 如何构建 ARP 请求（Who has 192.168.1.1?）
//   - 如何构建 ARP 应答（192.168.1.1 is at aa:bb:cc:dd:ee:ff）
//   - ARP 操作码（1=请求, 2=应答）的含义
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
	fmt.Println("=== goscapy 示例 04: ARP 包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// ARP 协议简介
	// -----------------------------------------------------------------------
	// ARP (Address Resolution Protocol) 用于在局域网中将 IP 地址解析为 MAC 地址。
	//
	// 工作流程:
	//   1. 主机 A 想和主机 B (192.168.1.2) 通信，但不知道 B 的 MAC 地址
	//   2. 主机 A 广播 ARP 请求: "Who has 192.168.1.2? Tell 192.168.1.1"
	//   3. 主机 B 收到请求后，单播 ARP 应答: "192.168.1.2 is at aa:bb:cc:dd:ee:ff"
	//
	// ARP 包的关键字段:
	//   - Op: 操作码 (1=请求/Who-has, 2=应答/Is-at)
	//   - SrcMAC / SrcIP: 发送方的 MAC 和 IP
	//   - DstMAC / DstIP: 目标的 MAC 和 IP

	// -----------------------------------------------------------------------
	// 第一部分: 构建 ARP 请求 (Who has ...)
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: ARP 请求 (Who has 192.168.1.1?) ---")
	fmt.Println()

	// ARP 请求需要发送到广播地址 ff:ff:ff:ff:ff:ff
	// 这样局域网中的所有主机都能收到
	arpRequest := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").      // 广播地址: 发送给所有人
		SrcMAC("00:11:22:33:44:55").       // 发送方 MAC
		Type(layers.EtherTypeARP).         // EtherType: ARP (0x0806)
		Over(goscapy.NewARP().
			Op(layers.ARPWhoHas).            // 操作码: 1 (请求/Who-has)
			SrcMAC("00:11:22:33:44:55").     // 发送方 MAC
			SrcIP("192.168.1.100").          // 发送方 IP
			DstMAC("00:00:00:00:00:00").     // 目标 MAC: 未知（全 0）
			DstIP("192.168.1.1"))            // 目标 IP: 我想知道谁的 MAC

	arpReqBytes, err := arpRequest.Build()
	if err != nil {
		log.Fatalf("构建 ARP 请求失败: %v", err)
	}

	fmt.Printf("ARP 请求构建成功!\n")
	fmt.Printf("  含义: \"Who has 192.168.1.1? Tell 192.168.1.100\"\n")
	fmt.Printf("  总长度: %d 字节\n", len(arpReqBytes))
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(arpReqBytes))

	// -----------------------------------------------------------------------
	// 第二部分: 构建 ARP 应答 (Is at ...)
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: ARP 应答 (192.168.1.1 is at aa:bb:cc:dd:ee:ff) ---")
	fmt.Println()

	// ARP 应答是单播的，直接回复给请求方
	arpReply := goscapy.NewEthernet().
		DstMAC("00:11:22:33:44:55").       // 发送给请求方
		SrcMAC("aa:bb:cc:dd:ee:ff").        // 回复方 MAC
		Type(layers.EtherTypeARP).
		Over(goscapy.NewARP().
			Op(layers.ARPIsAt).               // 操作码: 2 (应答/Is-at)
			SrcMAC("aa:bb:cc:dd:ee:ff").      // 回复方 MAC
			SrcIP("192.168.1.1").             // 回复方 IP
			DstMAC("00:11:22:33:44:55").      // 请求方 MAC
			DstIP("192.168.1.100"))           // 请求方 IP

	arpReplyBytes, err := arpReply.Build()
	if err != nil {
		log.Fatalf("构建 ARP 应答失败: %v", err)
	}

	fmt.Printf("ARP 应答构建成功!\n")
	fmt.Printf("  含义: \"192.168.1.1 is at aa:bb:cc:dd:ee:ff\"\n")
	fmt.Printf("  总长度: %d 字节\n", len(arpReplyBytes))
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(arpReplyBytes))

	// -----------------------------------------------------------------------
	// 第三部分: 使用 Shortcut 函数
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: Shortcut 函数 ---")
	fmt.Println()

	// EtherARP 一行构建完整的 ARP 包
	shortcutBytes, err := goscapy.EtherARP(
		"00:11:22:33:44:55",    // 源 MAC / 发送方 MAC
		"ff:ff:ff:ff:ff:ff",    // 目标 MAC / 广播
		"192.168.1.100",         // 发送方 IP (psrc)
		"192.168.1.1",           // 目标 IP (pdst)
		layers.ARPWhoHas,        // 操作码: 请求
	)
	if err != nil {
		log.Fatalf("Shortcut ARP 构建失败: %v", err)
	}

	fmt.Printf("Shortcut ARP 请求: %d 字节\n", len(shortcutBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// ARP 操作码参考
	// -----------------------------------------------------------------------
	fmt.Println("--- ARP 操作码参考 ---")
	fmt.Println()
	fmt.Println("  layers.ARPWhoHas (1) = ARP 请求 (Who has ...?)")
	fmt.Println("  layers.ARPIsAt   (2) = ARP 应答 (... is at ...)")
	fmt.Println()
	fmt.Println("提示: ARP 请求发广播 (ff:ff:ff:ff:ff:ff)，ARP 应答发单播")
	fmt.Println()
	fmt.Println("下一步: 运行 05-ipv6 示例，学习 IPv6 和扩展头")
}
