// 示例 09: GRE/VXLAN 隧道包构建示例
//
// 本示例演示如何构建 GRE 和 VXLAN 隧道封装包。
// 你将学到:
//   - 隧道技术在网络叠加中的用途
//   - 如何构建 GRE 隧道包
//   - 如何构建 VXLAN 隧道包
//   - 隧道的内层和外层结构
//
// 运行方式: go run main.go
// 注意: 本示例仅构建数据包，不需要 root 权限。

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers/gre"
)

func main() {
	fmt.Println("=== goscapy 示例 09: GRE/VXLAN 隧道包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 隧道技术简介
	// -----------------------------------------------------------------------
	// 网络隧道将一个协议包封装在另一个协议包中进行传输。
	// 常见用途:
	//   - VPN (虚拟专用网络)
	//   - 数据中心网络叠加 (Overlay)
	//   - 跨网络传输不兼容的协议
	//
	// 外层包: [Ethernet → IP → GRE/VXLAN]
	// 内层包: [被封装的原始数据包]

	// -----------------------------------------------------------------------
	// 第一部分: GRE 隧道
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: GRE 隧道 ---")
	fmt.Println()
	fmt.Println("GRE (Generic Routing Encapsulation) 是一种通用隧道协议。")
	fmt.Println("常用于站点间 VPN 连接。")
	fmt.Println()

	// 构建 GRE 隧道包，内层载荷是 IP 数据
	grePkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("10.0.0.1").                  // 隧道源端 IP
			DstIP("10.0.0.2").                  // 隧道目标 IP
			Proto(47)).                          // 协议号: GRE
		Over(goscapy.NewGRE().
			ProtocolType(gre.ProtoIP).           // 内层协议: IPv4
			Key(0x12345678).                     // GRE Key: 用于识别隧道
			Seq(1))                              // 序列号: 用于排序

	greBytes, err := grePkt.Build()
	if err != nil {
		log.Fatalf("构建 GRE 包失败: %v", err)
	}

	fmt.Printf("GRE 隧道包构建成功!\n")
	fmt.Printf("  外层: IP 10.0.0.1 → 10.0.0.2\n")
	fmt.Printf("  GRE 协议类型: 0x0800 (IPv4)\n")
	fmt.Printf("  GRE Key: 0x12345678\n")
	fmt.Printf("  GRE 序列号: 1\n")
	fmt.Printf("  总长度: %d 字节\n", len(greBytes))
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(greBytes))

	// -----------------------------------------------------------------------
	// 第二部分: GRE 封装 Ethernet 帧
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: GRE 封装 Ethernet ---")
	fmt.Println()

	innerPayload := []byte{
		// 内层 Ethernet 头 (14 字节)
		0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, // 目标 MAC
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 源 MAC
		0x08, 0x00, // EtherType: IPv4
		// 内层 IP 头 (简化)
		0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, // TTL=64, TCP
		192, 168, 1, 1, // 源 IP
		192, 168, 2, 1, // 目标 IP
	}

	greEtherBytes, err := goscapy.EtherIPGRE(
		"00:11:22:33:44:55",     // 外层源 MAC
		"00:aa:bb:cc:dd:ee",     // 外层目标 MAC
		"10.0.0.1",               // 外层源 IP
		"10.0.0.2",               // 外层目标 IP
		gre.ProtoEthernet,        // 内层: Ethernet
		0xABCD,                   // GRE Key
		innerPayload,             // 内层 Ethernet + IP 数据
	)
	if err != nil {
		log.Fatalf("构建 GRE Ethernet 包失败: %v", err)
	}

	fmt.Printf("GRE 封装 Ethernet 帧: %d 字节\n", len(greEtherBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: VXLAN 隧道
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: VXLAN 隧道 ---")
	fmt.Println()
	fmt.Println("VXLAN (Virtual eXtensible LAN) 常用于数据中心网络虚拟化。")
	fmt.Println("它将二层 Ethernet 帧封装在 UDP 包中，支持 1600 万个虚拟网络。")
	fmt.Println()

	innerVXLANPayload := []byte{
		// 内层 Ethernet 头
		0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// 内层 IP + payload (简化)
		0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00,
		192, 168, 1, 1,
		192, 168, 2, 1,
	}

	vxlanBytes, err := goscapy.EtherIPUDPVXLAN(
		"00:11:22:33:44:55",     // 外层源 MAC
		"00:aa:bb:cc:dd:ee",     // 外层目标 MAC
		"10.0.0.1",               // 外层源 IP
		"10.0.0.2",               // 外层目标 IP
		10001,                    // VNI: VXLAN 网络标识符
		innerVXLANPayload,        // 内层 Ethernet 帧
	)
	if err != nil {
		log.Fatalf("构建 VXLAN 包失败: %v", err)
	}

	fmt.Printf("VXLAN 隧道包构建成功!\n")
	fmt.Printf("  外层: Ethernet → IP → UDP(4789) → VXLAN\n")
	fmt.Printf("  VNI: 10001 (VXLAN 网络标识符)\n")
	fmt.Printf("  总长度: %d 字节\n", len(vxlanBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第四部分: VXLAN Builder API 详细控制
	// -----------------------------------------------------------------------
	fmt.Println("--- 第四部分: VXLAN Builder API ---")
	fmt.Println()

	vxlanPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("10.0.0.1").
			DstIP("10.0.0.2").
			Proto(17)).
		Over(goscapy.NewUDP().
			SrcPort(4789).                     // VXLAN 标准端口
			DstPort(4789)).
		Over(goscapy.NewVXLAN().
			VNI(100).                           // VNI: 100
			Flags(0x08))                        // I flag (VNI 有效)

	vxlanBytes2, err := vxlanPkt.Build()
	if err != nil {
		log.Fatalf("构建 VXLAN Builder 包失败: %v", err)
	}

	fmt.Printf("VXLAN Builder API: %d 字节\n", len(vxlanBytes2))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 隧道协议对比
	// -----------------------------------------------------------------------
	fmt.Println("--- GRE vs VXLAN 对比 ---")
	fmt.Println()
	fmt.Println("  GRE:")
	fmt.Println("    - 通用隧道协议，可封装任意协议")
	fmt.Println("    - 没有标准端口号")
	fmt.Println("    - 支持 Key 和序列号")
	fmt.Println("    - 常用于站点间 VPN")
	fmt.Println()
	fmt.Println("  VXLAN:")
	fmt.Println("    - 专为数据中心设计")
	fmt.Println("    - UDP 封装 (端口 4789)")
	fmt.Println("    - VNI 支持 1600 万个虚拟网络")
	fmt.Println("    - 常用于云环境网络虚拟化")
	fmt.Println()
	fmt.Println("下一步: 运行 10-dissect 示例，学习数据包解析")
}
