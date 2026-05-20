// 示例 10: 数据包解析（Dissect）示例
//
// 本示例演示如何使用 goscapy 将原始字节解析为结构化的数据包。
// 你将学到:
//   - 如何使用 DissectByProto() 解析原始字节
//   - 如何访问各层字段（MAC、IP、端口等）
//   - 自动协议检测如何工作
//   - 解析引擎的自动协议推断机制
//
// 运行方式: go run main.go
// 注意: 本示例不需要 root 权限。

package main

import (
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 10: 数据包解析（Dissect） ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 解析简介
	// -----------------------------------------------------------------------
	// goscapy 可以将网络上的原始字节解析为结构化的 Packet 对象。
	// 解析引擎会自动识别协议类型，逐层解析。
	//
	// 例如，一个 Ethernet + IPv4 + TCP 包的原始字节会被解析为:
	//   Layer 0: Ethernet (包含 src/dst MAC)
	//   Layer 1: IPv4     (包含 src/dst IP, TTL, 协议号)
	//   Layer 2: TCP      (包含 src/dst 端口, 标志位)

	// -----------------------------------------------------------------------
	// 第一部分: 构建一个包，然后解析它
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: 构建 → 解析 TCP 包 ---")
	fmt.Println()

	// 先构建一个 Ethernet + IP + TCP 包
	tcpPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").
			DstIP("10.0.0.1").
			TTL(64).
			Proto(layers.IPProtoTCP)).
		Over(goscapy.NewTCP().
			SrcPort(54321).
			DstPort(80).
			Seq(1000).
			Ack(0).
			Flags(layers.TCPSyn).
			Window(65535))

	pkt := tcpPkt.Packet()
	rawBytes, err := pkt.Build()
	if err != nil {
		log.Fatalf("构建包失败: %v", err)
	}

	fmt.Printf("原始字节 (%d 字节) 已生成\n", len(rawBytes))

	// 现在用 DissectByProto 解析这些字节
	// "Ethernet" 指定第一个协议层是 Ethernet
	dissectedPkt, err := packet.DissectByProto(rawBytes, "Ethernet")
	if err != nil {
		log.Fatalf("解析包失败: %v", err)
	}

	// -----------------------------------------------------------------------
	// 第二部分: 逐层访问解析结果
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第二部分: 逐层查看解析结果 ---")
	fmt.Println()

	for i, layer := range dissectedPkt.Layers() {
		fmt.Printf("Layer %d: %s\n", i, layer.Proto())
	}

	fmt.Println()

	// 访问 Ethernet 层
	ethLayer := dissectedPkt.GetLayer("Ethernet")
	if ethLayer != nil {
		dstMAC, _ := ethLayer.Get("dst")
		srcMAC, _ := ethLayer.Get("src")
		etherType, _ := ethLayer.Get("type")
		fmt.Printf("  Ethernet:\n")
		fmt.Printf("    目标 MAC: %v\n", dstMAC)
		fmt.Printf("    源 MAC:   %v\n", srcMAC)
		fmt.Printf("    类型:     0x%04x\n", etherType)
	}

	// 访问 IP 层 (IPv4)
	ipLayer := dissectedPkt.GetLayer("IP")
	if ipLayer != nil {
		srcIP, _ := ipLayer.Get("src")
		dstIP, _ := ipLayer.Get("dst")
		ttl, _ := ipLayer.Get("ttl")
		proto, _ := ipLayer.Get("proto")
		fmt.Printf("  IP (IPv4):\n")
		fmt.Printf("    源 IP:  %v\n", srcIP)
		fmt.Printf("    目标 IP: %v\n", dstIP)
		fmt.Printf("    TTL:    %v\n", ttl)
		fmt.Printf("    协议:   %v\n", proto)
	}

	// 访问 TCP 层
	tcpLayer := dissectedPkt.GetLayer("TCP")
	if tcpLayer != nil {
		srcPort, _ := tcpLayer.Get("sport")
		dstPort, _ := tcpLayer.Get("dport")
		flags, _ := tcpLayer.Get("flags")
		seq, _ := tcpLayer.Get("seq")
		fmt.Printf("  TCP:\n")
		fmt.Printf("    源端口:  %v\n", srcPort)
		fmt.Printf("    目标端口: %v\n", dstPort)
		fmt.Printf("    标志:    0x%02x\n", flags)
		fmt.Printf("    序列号:  %v\n", seq)
	}

	// -----------------------------------------------------------------------
	// 第三部分: 解析 ICMP 包
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第三部分: 解析 ICMP Echo Request ---")
	fmt.Println()

	icmpBytes, err := goscapy.EtherIPICMP(
		"00:aa:bb:cc:dd:ee",
		"8.8.8.8",
		8, 0,
	)
	if err != nil {
		log.Fatalf("构建 ICMP 包失败: %v", err)
	}

	icmpPkt, err := packet.DissectByProto(icmpBytes, "Ethernet")
	if err != nil {
		log.Fatalf("解析 ICMP 包失败: %v", err)
	}

	fmt.Println("解析 ICMP 包的协议层:")
	for i, layer := range icmpPkt.Layers() {
		fmt.Printf("  Layer %d: %s\n", i, layer.Proto())
	}

	icmpLayer := icmpPkt.GetLayer("ICMP")
	if icmpLayer != nil {
		icmpType, _ := icmpLayer.Get("type")
		icmpCode, _ := icmpLayer.Get("code")
		fmt.Printf("  ICMP:\n")
		fmt.Printf("    类型: %v (8=Echo Request)\n", icmpType)
		fmt.Printf("    代码: %v\n", icmpCode)
	}

	// -----------------------------------------------------------------------
	// 第四部分: 检查协议层是否存在
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第四部分: 检查协议层 ---")
	fmt.Println()

	fmt.Printf("  包含 Ethernet 层? %v\n", dissectedPkt.HasLayer("Ethernet"))
	fmt.Printf("  包含 IP 层?       %v\n", dissectedPkt.HasLayer("IP"))
	fmt.Printf("  包含 TCP 层?      %v\n", dissectedPkt.HasLayer("TCP"))
	fmt.Printf("  包含 UDP 层?      %v\n", dissectedPkt.HasLayer("UDP"))
	fmt.Printf("  总层数:           %d\n", dissectedPkt.Len())

	// -----------------------------------------------------------------------
	// 解析 API 参考
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 解析 API 参考 ---")
	fmt.Println()
	fmt.Println("  packet.DissectByProto(raw, \"Ethernet\")  - 从 Ethernet 开始解析")
	fmt.Println("  packet.DissectByProto(raw, \"IP\")        - 从 IP (IPv4) 开始解析 (无 Ethernet)")
	fmt.Println("  packet.DissectByProto(raw, \"IPv6\")      - 从 IPv6 开始解析")
	fmt.Println()
	fmt.Println("  pkt.GetLayer(\"TCP\")   - 获取指定协议层")
	fmt.Println("  pkt.HasLayer(\"UDP\")   - 检查协议层是否存在")
	fmt.Println("  pkt.Layers()           - 获取所有层")
	fmt.Println("  layer.Get(\"sport\")     - 获取层的字段值")
	fmt.Println()
	fmt.Println("下一步: 运行 11-send 示例，学习如何发送数据包")
}
