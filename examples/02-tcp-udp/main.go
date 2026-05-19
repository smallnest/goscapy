// 示例 02: TCP/UDP 传输层包构建
//
// 本示例演示如何在 IP 层上叠加 TCP 和 UDP 传输层协议。
// 你将学到:
//   - 如何使用 TCP Builder 构建带有标志位的 TCP 头
//   - 如何使用 UDP Builder 构建 UDP 数据报
//   - TCP 标志位（SYN、ACK、FIN 等）的含义
//   - Builder API 和 Shortcut 函数两种写法的对比
//   - goscapy 的自动校验和机制
//
// 运行方式: go run main.go
// 注意: 本示例仅构建数据包，不需要 root 权限。

package main

import (
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

func main() {
	fmt.Println("=== goscapy 示例 02: TCP/UDP 传输层包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第一部分: 使用 Builder API 构建 TCP SYN 包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: TCP SYN 包 ---")
	fmt.Println()
	fmt.Println("TCP SYN 是 TCP 三次握手的第一步，客户端发送 SYN 请求建立连接。")
	fmt.Println()

	// Builder API: 逐层叠加，完全控制每个字段
	tcpSynPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").       // 目标 MAC
		SrcMAC("00:11:22:33:44:55").        // 源 MAC
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").          // 源 IP
			DstIP("10.0.0.1").               // 目标 IP
			TTL(64).                          // TTL
			Proto(layers.IPProtoTCP)).        // 协议: TCP (6)
		Over(goscapy.NewTCP().
			SrcPort(54321).                   // 源端口: 随机高端口
			DstPort(80).                      // 目标端口: HTTP
			Seq(1000).                        // 序列号
			Flags(layers.TCPSyn).             // 标志: SYN
			Window(65535))                    // 窗口大小

	tcpSynBytes, err := tcpSynPkt.Build()
	if err != nil {
		log.Fatalf("构建 TCP SYN 包失败: %v", err)
	}
	fmt.Printf("TCP SYN 包构建成功! 总长度: %d 字节\n", len(tcpSynBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第二部分: 使用 Builder API 构建 TCP SYN+ACK 包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: TCP SYN+ACK 包 ---")
	fmt.Println()

	tcpSynAckPkt := goscapy.NewEthernet().
		DstMAC("00:11:22:33:44:55").
		SrcMAC("00:aa:bb:cc:dd:ee").
		Over(goscapy.NewIP().
			SrcIP("10.0.0.1").
			DstIP("192.168.1.100").
			TTL(64).
			Proto(layers.IPProtoTCP)).
		Over(goscapy.NewTCP().
			SrcPort(80).
			DstPort(54321).
			Seq(2000).                         // 服务器的初始序列号
			Ack(1001).                         // 确认号 = 客户端 seq + 1
			Flags(layers.TCPSyn|layers.TCPAck). // 标志: SYN + ACK
			Window(65535))

	tcpSynAckBytes, err := tcpSynAckPkt.Build()
	if err != nil {
		log.Fatalf("构建 TCP SYN+ACK 包失败: %v", err)
	}
	fmt.Printf("TCP SYN+ACK 包构建成功! 总长度: %d 字节\n", len(tcpSynAckBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: 使用 Builder API 构建 UDP 包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: UDP 数据报 ---")
	fmt.Println()
	fmt.Println("UDP 比 TCP 简单得多，没有连接、序列号、确认等机制。")
	fmt.Println("只需要设置源端口和目标端口即可。")
	fmt.Println()

	udpPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").
			DstIP("8.8.8.8").
			TTL(64).
			Proto(layers.IPProtoUDP)).
		Over(goscapy.NewUDP().
			SrcPort(12345).                     // 源端口
			DstPort(53))                        // 目标端口: DNS

	udpBytes, err := udpPkt.Build()
	if err != nil {
		log.Fatalf("构建 UDP 包失败: %v", err)
	}
	fmt.Printf("UDP 包构建成功! 总长度: %d 字节\n", len(udpBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第四部分: 使用 Shortcut 函数（一行代码构建）
	// -----------------------------------------------------------------------
	fmt.Println("--- 第四部分: Shortcut 函数 vs Builder API ---")
	fmt.Println()
	fmt.Println("同样的 TCP SYN 包，用 Shortcut 函数只需一行:")
	fmt.Println()

	// Shortcut 函数: EtherIPTCP 一行搞定 Ethernet + IP + TCP
	shortcutBytes, err := goscapy.EtherIPTCP(
		"00:11:22:33:44:55",  // 源 MAC
		"00:aa:bb:cc:dd:ee",  // 目标 MAC
		"192.168.1.100",       // 源 IP
		"10.0.0.1",            // 目标 IP
		54321,                 // 源端口
		80,                    // 目标端口
		layers.TCPSyn,         // TCP 标志
	)
	if err != nil {
		log.Fatalf("Shortcut 构建 TCP 包失败: %v", err)
	}
	fmt.Printf("Shortcut TCP SYN 包: %d 字节\n", len(shortcutBytes))

	// Shortcut 函数: IPUDP（不带 Ethernet 头）
	shortcutUDP, err := goscapy.IPUDP(
		"192.168.1.100", // 源 IP
		"8.8.8.8",        // 目标 IP
		12345,             // 源端口
		53,                // 目标端口
	)
	if err != nil {
		log.Fatalf("Shortcut 构建 UDP 包失败: %v", err)
	}
	fmt.Printf("Shortcut UDP 包 (无 Ethernet 头): %d 字节\n", len(shortcutUDP))

	fmt.Println()

	// -----------------------------------------------------------------------
	// TCP 标志位参考
	// -----------------------------------------------------------------------
	fmt.Println("--- TCP 标志位参考 ---")
	fmt.Println()
	fmt.Println("  layers.TCPSyn (0x02) = 同步，用于建立连接")
	fmt.Println("  layers.TCPAck (0x10) = 确认，确认已收到的数据")
	fmt.Println("  layers.TCPFin (0x01) = 完成，用于关闭连接")
	fmt.Println("  layers.TCPRst (0x04) = 重置，异常关闭连接")
	fmt.Println("  layers.TCPPsh (0x08) = 推送，要求立即交付数据")
	fmt.Println("  layers.TCPUrg (0x20) = 紧急，紧急数据")
	fmt.Println()
	fmt.Println("  可以用位或组合多个标志: layers.TCPSyn | layers.TCPAck")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 自动校验和说明
	// -----------------------------------------------------------------------
	fmt.Println("--- 自动校验和机制 ---")
	fmt.Println()
	fmt.Println("goscapy 会自动计算以下校验和:")
	fmt.Println("  - IP 头校验和 (Header Checksum)")
	fmt.Println("  - TCP 校验和 (包含伪首部)")
	fmt.Println("  - UDP 校验和 (包含伪首部)")
	fmt.Println()
	fmt.Println("你不需要手动计算校验和，Build() 时会自动填充。")
	fmt.Println()
	fmt.Println("下一步: 运行 03-icmp-ping 示例，学习 ICMP Echo Request (Ping)")
}
