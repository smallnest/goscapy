// 示例 05: IPv6 包构建示例
//
// 本示例演示如何构建 IPv6 数据包及其扩展头。
// 你将学到:
//   - IPv6 与 IPv4 的关键区别
//   - 如何构建基本 IPv6 包
//   - 如何添加 IPv6 扩展头（Hop-by-Hop、Routing 等）
//   - 如何构建 IPv6 + ICMPv6 Echo Request
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
	fmt.Println("=== goscapy 示例 05: IPv6 包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// IPv6 vs IPv4 关键区别
	// -----------------------------------------------------------------------
	// 1. 地址长度: IPv4 = 32 位, IPv6 = 128 位
	// 2. 头部大小: IPv4 = 20-60 字节 (可变), IPv6 = 40 字节 (固定)
	// 3. 分片: IPv4 在路由器中分片, IPv6 只在源端分片
	// 4. 扩展头: IPv6 用扩展头代替 IPv4 的选项字段
	// 5. 校验和: IPv6 头没有校验和（由上层协议负责）
	// 6. 配置: IPv6 支持自动配置 (SLAAC)

	// -----------------------------------------------------------------------
	// 第一部分: 基本IPv6 包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: 基本 IPv6 包 ---")
	fmt.Println()

	ipv6Pkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Type(layers.EtherTypeIPv6).         // EtherType: IPv6 (0x86DD)
		Over(goscapy.NewIPv6().
			SrcIP("fe80::1").                // 源 IPv6: 链路本地地址
			DstIP("fe80::2").                // 目标 IPv6: 链路本地地址
			NH(layers.IPv6NextHdrTCP).       // Next Header: TCP (6)
			HLim(64))                        // Hop Limit: 64

	ipv6Bytes, err := ipv6Pkt.Build()
	if err != nil {
		log.Fatalf("构建 IPv6 包失败: %v", err)
	}

	fmt.Printf("基本 IPv6 包构建成功! %d 字节\n", len(ipv6Bytes))
	fmt.Printf("  Ethernet 头: 14 字节\n")
	fmt.Printf("  IPv6 头:     40 字节 (固定)\n")
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(ipv6Bytes))

	// -----------------------------------------------------------------------
	// 第二部分: IPv6 + ICMPv6 Echo Request (Ping6)
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: IPv6 + ICMPv6 Echo Request ---")
	fmt.Println()

	// ICMPv6 是 IPv6 的 ICMP 等价物，协议号 58
	ipv6ICMPBytes, err := goscapy.IPv6ICMPv6Echo(
		"fe80::1",   // 源 IPv6
		"fe80::2",   // 目标 IPv6
		0x1234,      // ICMPv6 ID
		1,           // ICMPv6 Seq
	)
	if err != nil {
		log.Fatalf("构建 IPv6 ICMPv6 包失败: %v", err)
	}

	fmt.Printf("IPv6 ICMPv6 Echo Request: %d 字节\n", len(ipv6ICMPBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: IPv6 扩展头
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: IPv6 扩展头 ---")
	fmt.Println()
	fmt.Println("IPv6 扩展头位于 IPv6 基本头和上层协议之间，提供可选功能。")
	fmt.Println("常见扩展头:")
	fmt.Println("  - Hop-by-Hop Options (0):   每个路由器都要处理")
	fmt.Println("  - Routing (43):             指定数据包经过的路由")
	fmt.Println("  - Fragment (44):            分片信息")
	fmt.Println("  - Destination Options (60): 只有目标主机处理")
	fmt.Println()

	// 构建 IPv6 + Hop-by-Hop + TCP 的包
	// Hop-by-Hop 扩展头的 nh 字段指向下一个头（TCP）
	hopByHop := layers.NewIPv6HopByHop()
	hopByHop.Set("nh", layers.IPv6NextHdrTCP) // 下一个头: TCP
	hopByHop.Set("len", uint8(0))              // 长度: (0+1)*8 = 8 字节

	// IPv6 基本头的 NH 指向 Hop-by-Hop 扩展头
	extPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Type(layers.EtherTypeIPv6).
		Over(goscapy.NewIPv6().
			SrcIP("2001:db8::1").
			DstIP("2001:db8::2").
			NH(layers.IPv6ExtHdrHopByHop).  // NH 指向 Hop-by-Hop
			HLim(64)).
		Over(goscapy.NewTCP().
			SrcPort(12345).
			DstPort(80).
			Flags(layers.TCPSyn))

	// 将 Hop-by-Hop 扩展头插入到 IPv6 和 TCP 之间
	extPkt.Packet().InsertAfter("IPv6", hopByHop)

	extBytes, err := extPkt.Build()
	if err != nil {
		log.Fatalf("构建 IPv6 扩展头包失败: %v", err)
	}

	fmt.Printf("IPv6 + Hop-by-Hop + TCP 包: %d 字节\n", len(extBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// IPv6 Next Header 值参考
	// -----------------------------------------------------------------------
	fmt.Println("--- IPv6 Next Header 值参考 ---")
	fmt.Println()
	fmt.Println("  layers.IPv6NextHdrTCP    (6)  = TCP")
	fmt.Println("  layers.IPv6NextHdrUDP    (17) = UDP")
	fmt.Println("  layers.IPv6NextHdrICMP   (58) = ICMPv6")
	fmt.Println("  layers.IPv6NextHdrNoHdr  (59) = No Next Header")
	fmt.Println()
	fmt.Println("扩展头编号:")
	fmt.Println("  layers.IPv6ExtHdrHopByHop (0)  = Hop-by-Hop Options")
	fmt.Println("  layers.IPv6ExtHdrRouting  (43) = Routing")
	fmt.Println("  layers.IPv6ExtHdrFragment (44) = Fragment")
	fmt.Println("  layers.IPv6ExtHdrDestOpts (60) = Destination Options")
	fmt.Println()
	fmt.Println("下一步: 运行 06-dns 示例，学习 DNS 查询包构建")
}
