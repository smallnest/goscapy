// 示例 07: DHCP 包构建示例
//
// 本示例演示如何构建 DHCP (Dynamic Host Configuration Protocol) 包。
// 你将学到:
//   - DHCP 四步交互流程（DORA: Discover → Offer → Request → ACK）
//   - 如何构建 DHCP Discover 包
//   - 如何构建 DHCP Request 包
//   - DHCP 选项（Option 53 消息类型等）的添加
//   - DHCP 的广播特性和端口（客户端 68 / 服务器 67）
//
// 运行方式: go run main.go
// 注意: 本示例仅构建数据包，不需要 root 权限。

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers/dhcp"
)

func main() {
	fmt.Println("=== goscapy 示例 07: DHCP 包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// DHCP 协议简介
	// -----------------------------------------------------------------------
	// DHCP 用于自动给设备分配 IP 地址。标准的四步交互 (DORA):
	//
	//   1. Discover (发现):  客户端广播 "有没有 DHCP 服务器?"
	//   2. Offer (提供):     服务器回应 "我可以给你 192.168.1.100"
	//   3. Request (请求):   客户端确认 "我要 192.168.1.100"
	//   4. ACK (确认):       服务器确认 "好的, 192.168.1.100 分配给你了"
	//
	// DHCP 使用 UDP 协议:
	//   - 客户端端口: 68
	//   - 服务器端口: 67
	//   - Discover 和 Request 使用广播地址 255.255.255.255

	// -----------------------------------------------------------------------
	// 第一部分: DHCP Discover
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: DHCP Discover ---")
	fmt.Println()

	// 客户端 MAC 地址（用于标识设备）
	clientMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// 构建 DHCP Discover 包
	discoverPkt := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").         // 广播
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").                  // 客户端还没有 IP
			DstIP("255.255.255.255").           // 广播
			Proto(17)).                         // UDP
		Over(goscapy.NewUDP().
			SrcPort(68).                         // DHCP 客户端端口
			DstPort(67)).                        // DHCP 服务器端口
		Over(goscapy.NewDHCP().
			Op(dhcp.BOOTREQUEST).                // BOOTP 操作: 请求
			XID(0x12345678).                     // 事务 ID (随机)
			CHAddr(clientMAC).                   // 客户端 MAC
			MessageType(dhcp.DHCPDISCOVER))      // Option 53: Discover

	discoverBytes, err := discoverPkt.Build()
	if err != nil {
		log.Fatalf("构建 DHCP Discover 失败: %v", err)
	}

	fmt.Printf("DHCP Discover 构建成功!\n")
	fmt.Printf("  事务 ID: 0x12345678\n")
	fmt.Printf("  客户端 MAC: 00:11:22:33:44:55\n")
	fmt.Printf("  消息类型: Discover (1)\n")
	fmt.Printf("  总长度: %d 字节\n", len(discoverBytes))
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(discoverBytes))

	// -----------------------------------------------------------------------
	// 第二部分: DHCP Request
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: DHCP Request ---")
	fmt.Println()

	// 收到 Offer 后，客户端发送 Request 确认想要的 IP
	requestPkt := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP("255.255.255.255").
			Proto(17)).
		Over(goscapy.NewUDP().
			SrcPort(68).
			DstPort(67)).
		Over(goscapy.NewDHCP().
			Op(dhcp.BOOTREQUEST).
			XID(0x12345678).                     // 同一个事务 ID
			CHAddr(clientMAC).
			MessageType(dhcp.DHCPREQUEST))        // Option 53: Request

	requestBytes, err := requestPkt.Build()
	if err != nil {
		log.Fatalf("构建 DHCP Request 失败: %v", err)
	}

	fmt.Printf("DHCP Request 构建成功! %d 字节\n", len(requestBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: DHCP Offer (服务器回应)
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: DHCP Offer (服务器端) ---")
	fmt.Println()

	offerPkt := goscapy.NewEthernet().
		DstMAC("00:11:22:33:44:55").         // 发给客户端
		SrcMAC("aa:bb:cc:dd:ee:ff").          // 服务器 MAC
		Over(goscapy.NewIP().
			SrcIP("192.168.1.1").               // 服务器 IP
			DstIP("255.255.255.255").
			Proto(17)).
		Over(goscapy.NewUDP().
			SrcPort(67).
			DstPort(68)).
		Over(goscapy.NewDHCP().
			Op(dhcp.BOOTREPLY).                 // BOOTP 操作: 应答
			XID(0x12345678).
			YIAddr("192.168.1.100").             // 提供给客户端的 IP
			SIAddr("192.168.1.1").               // 服务器 IP
			CHAddr(clientMAC).
			MessageType(dhcp.DHCPOFFER))         // Option 53: Offer

	offerBytes, err := offerPkt.Build()
	if err != nil {
		log.Fatalf("构建 DHCP Offer 失败: %v", err)
	}

	fmt.Printf("DHCP Offer 构建成功! %d 字节\n", len(offerBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第四部分: DHCP ACK
	// -----------------------------------------------------------------------
	fmt.Println("--- 第四部分: DHCP ACK ---")
	fmt.Println()

	ackPkt := goscapy.NewEthernet().
		DstMAC("00:11:22:33:44:55").
		SrcMAC("aa:bb:cc:dd:ee:ff").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.1").
			DstIP("255.255.255.255").
			Proto(17)).
		Over(goscapy.NewUDP().
			SrcPort(67).
			DstPort(68)).
		Over(goscapy.NewDHCP().
			Op(dhcp.BOOTREPLY).
			XID(0x12345678).
			YIAddr("192.168.1.100").
			SIAddr("192.168.1.1").
			CHAddr(clientMAC).
			MessageType(dhcp.DHCPACK))           // Option 53: ACK

	ackBytes, err := ackPkt.Build()
	if err != nil {
		log.Fatalf("构建 DHCP ACK 失败: %v", err)
	}

	fmt.Printf("DHCP ACK 构建成功! %d 字节\n", len(ackBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第五部分: 使用 Shortcut 函数
	// -----------------------------------------------------------------------
	fmt.Println("--- 第五部分: Shortcut 函数 ---")
	fmt.Println()

	shortcutBytes, err := goscapy.EtherIPUDPDHCP(
		"00:11:22:33:44:55",    // 源 MAC (客户端)
		"ff:ff:ff:ff:ff:ff",    // 目标 MAC (广播)
		0x12345678,              // 事务 ID
		dhcp.DHCPDISCOVER,       // 消息类型
	)
	if err != nil {
		log.Fatalf("Shortcut DHCP 构建失败: %v", err)
	}

	fmt.Printf("Shortcut DHCP Discover: %d 字节\n", len(shortcutBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// DHCP 消息类型参考
	// -----------------------------------------------------------------------
	fmt.Println("--- DHCP 消息类型参考 ---")
	fmt.Println()
	fmt.Println("  dhcp.DHCPDISCOVER (1) = 发现: 客户端寻找 DHCP 服务器")
	fmt.Println("  dhcp.DHCPOFFER    (2) = 提供: 服务器提供 IP 地址")
	fmt.Println("  dhcp.DHCPREQUEST  (3) = 请求: 客户端请求 IP 地址")
	fmt.Println("  dhcp.DHCPDECLINE  (4) = 拒绝: 客户端发现 IP 冲突")
	fmt.Println("  dhcp.DHCPACK      (5) = 确认: 服务器确认分配")
	fmt.Println("  dhcp.DHCPNAK      (6) = 否认: 服务器拒绝请求")
	fmt.Println("  dhcp.DHCPRELEASE  (7) = 释放: 客户端释放 IP")
	fmt.Println("  dhcp.DHCPINFORM   (8) = 通知: 客户端告知已配置")
	fmt.Println()
	fmt.Println("下一步: 运行 08-vlan 示例，学习 VLAN 标签")
}
