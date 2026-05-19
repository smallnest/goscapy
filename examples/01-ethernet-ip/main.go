// 示例 01: Ethernet + IPv4 基础包构建
//
// 本示例演示如何使用 goscapy 的 Builder API 构建最基础的网络数据包。
// 你将学到:
//   - 如何创建 Ethernet 帧（设置源/目 MAC 地址）
//   - 如何创建 IPv4 头（设置源/目 IP 地址、TTL、协议号）
//   - Builder API 的链式调用风格
//   - Over() 方法如何将协议层"叠加"在一起
//   - 如何将构建好的包序列化为原始字节
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
	fmt.Println("=== goscapy 示例 01: Ethernet + IPv4 基础包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 1. 使用 Builder API 构建 Ethernet 帧
	// -----------------------------------------------------------------------
	// NewEthernet() 创建一个 Ethernet 帧构建器，包含默认值。
	// DstMAC() 设置目标 MAC 地址（这里用广播地址 ff:ff:ff:ff:ff:ff）。
	// SrcMAC() 设置源 MAC 地址。
	// Type() 设置 EtherType 字段，0x0800 表示上层是 IPv4。
	ethernet := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").    // 目标 MAC: 广播地址
		SrcMAC("00:11:22:33:44:55").    // 源 MAC: 我们的网卡地址
		Type(layers.EtherTypeIPv4)      // EtherType = IPv4 (0x0800)

	// -----------------------------------------------------------------------
	// 2. 使用 Builder API 构建 IPv4 头
	// -----------------------------------------------------------------------
	// NewIP() 创建 IPv4 头构建器，默认 TTL=64。
	// SrcIP() 设置源 IP 地址。
	// DstIP() 设置目标 IP 地址。
	// TTL() 设置生存时间（每经过一个路由器减 1）。
	// Proto() 设置上层协议号（6=TCP, 17=UDP, 1=ICMP）。
	// ID() 设置标识字段（用于分片重组）。
	ip := goscapy.NewIP().
		SrcIP("192.168.1.100").        // 源 IP: 我们的 IP
		DstIP("192.168.1.1").           // 目标 IP: 网关
		TTL(64).                         // 生存时间: 64 跳
		Proto(layers.IPProtoTCP).        // 上层协议: TCP
		ID(0x1234)                       // 标识: 0x1234

	// -----------------------------------------------------------------------
	// 3. 使用 Over() 方法将协议层叠加
	// -----------------------------------------------------------------------
	// Over() 是 goscapy 的核心概念——它将一个协议层"叠加"在另一个之上。
	// 调用链从最底层（Ethernet）开始，逐层向上叠加（IP → 上层协议）。
	// 这和实际网络协议栈的顺序一致：Ethernet 在最外层，IP 在里面。
	//
	// 这里我们只叠加了两层（Ethernet + IP），不包含传输层协议，
	// 所以 Build() 后得到的是一个没有载荷的 IP 数据报。
	pkt := ethernet.Over(ip)

	// -----------------------------------------------------------------------
	// 4. 序列化为原始字节
	// -----------------------------------------------------------------------
	// Build() 将所有层序列化为网络字节序（大端）的原始字节数组。
	rawBytes, err := pkt.Build()
	if err != nil {
		log.Fatalf("构建数据包失败: %v", err)
	}

	fmt.Println("构建成功! Ethernet + IPv4 数据包:")
	fmt.Printf("  总长度: %d 字节\n", len(rawBytes))
	fmt.Printf("  Hex dump:\n%s\n", formatHexDump(rawBytes))

	// -----------------------------------------------------------------------
	// 5. 解读输出
	// -----------------------------------------------------------------------
	// 输出的字节结构如下:
	//   [0-5]   目标 MAC: ff:ff:ff:ff:ff:ff (6 字节)
	//   [6-11]  源 MAC:   00:11:22:33:44:55 (6 字节)
	//   [12-13] EtherType: 08 00 (IPv4)
	//   [14]    Version + IHL: 45 (IPv4, 20 字节头)
	//   [15]    TOS: 00
	//   [16-17] Total Length: 00 14 (20 字节)
	//   [18-19] Identification: 12 34
	//   ... 后面是 IP 头的其他字段

	fmt.Println("提示: Ethernet 头 14 字节 + IPv4 头 20 字节 = 34 字节")
	fmt.Println("下一步: 运行 02-tcp-udp 示例，学习如何在 IP 上叠加传输层协议")
}

// formatHexDump 将字节格式化为易读的 hex dump 格式
func formatHexDump(data []byte) string {
	var result string
	for i := 0; i < len(data); i += 16 {
		// 偏移量
		result += fmt.Sprintf("  %04x  ", i)

		// Hex 部分
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result += fmt.Sprintf("%02x ", data[i+j])
			} else {
				result += "   "
			}
			if j == 7 {
				result += " "
			}
		}

		// ASCII 部分
		result += " |"
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				result += string(b)
			} else {
				result += "."
			}
		}
		result += "|\n"
	}
	return result
}

