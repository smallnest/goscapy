// 示例 06: DNS 查询包构建示例
//
// 本示例演示如何构建 DNS 查询数据包。
// 你将学到:
//   - DNS 协议的查询/响应模型
//   - 如何构建 DNS 查询包（A 记录、AAAA 记录）
//   - 如何使用 DNS Builder 设置查询问题
//   - DNS 记录类型（A、AAAA、CNAME、MX 等）
//
// 运行方式: go run main.go
// 注意: 本示例仅构建数据包，不需要 root 权限。

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers/dns"
)

func main() {
	fmt.Println("=== goscapy 示例 06: DNS 查询包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// DNS 协议简介
	// -----------------------------------------------------------------------
	// DNS (Domain Name System) 将域名解析为 IP 地址。
	// 工作流程:
	//   1. 客户端发送 DNS 查询: "example.com 的 IP 是多少?"
	//   2. DNS 服务器返回响应: "example.com 的 A 记录是 93.184.216.34"
	//
	// DNS 消息结构:
	//   - Header: ID、标志、计数器
	//   - Question: 查询的域名和类型
	//   - Answer: 响应的资源记录
	//   - Authority: 权威名称服务器
	//   - Additional: 附加信息

	// -----------------------------------------------------------------------
	// 第一部分: 构建 DNS A 记录查询
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: DNS A 记录查询 ---")
	fmt.Println()

	// DNSQuestion 定义要查询的域名和记录类型
	questions := []dns.DNSQuestion{
		{
			Name:  "example.com",      // 查询的域名
			Type:  dns.QtypeA,         // 记录类型: A (IPv4 地址)
			Class: dns.QclassIN,       // 类别: IN (Internet)
		},
	}

	// 使用 Builder API 构建完整的 DNS 查询包
	dnsPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").
			DstIP("8.8.8.8").                // Google DNS 服务器
			Proto(17)).                       // UDP
		Over(goscapy.NewUDP().
			SrcPort(54321).
			DstPort(53)).                     // DNS 端口
		Over(goscapy.NewDNS().
			ID(0x1234).                        // 事务 ID
			Flags(0x0100).                     // 标志: 标准查询, RD=1
			Questions(questions))              // 设置查询问题

	dnsBytes, err := dnsPkt.Build()
	if err != nil {
		log.Fatalf("构建 DNS 包失败: %v", err)
	}

	fmt.Printf("DNS A 记录查询构建成功!\n")
	fmt.Printf("  查询域名: example.com\n")
	fmt.Printf("  记录类型: A (IPv4)\n")
	fmt.Printf("  总长度: %d 字节\n", len(dnsBytes))
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(dnsBytes))

	// -----------------------------------------------------------------------
	// 第二部分: 构建 DNS AAAA 记录查询 (IPv6)
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: DNS AAAA 记录查询 ---")
	fmt.Println()

	aaaaQuestions := []dns.DNSQuestion{
		{
			Name:  "google.com",
			Type:  dns.QtypeAAAA,       // AAAA: IPv6 地址
			Class: dns.QclassIN,
		},
	}

	aaaaPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").
			DstIP("8.8.8.8").
			Proto(17)).
		Over(goscapy.NewUDP().
			SrcPort(54321).
			DstPort(53)).
		Over(goscapy.NewDNS().
			ID(0x5678).
			Questions(aaaaQuestions))

	aaaaBytes, err := aaaaPkt.Build()
	if err != nil {
		log.Fatalf("构建 DNS AAAA 包失败: %v", err)
	}

	fmt.Printf("DNS AAAA 查询构建成功! %d 字节\n", len(aaaaBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: 使用 Shortcut 函数
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: Shortcut 函数 ---")
	fmt.Println()

	shortcutQuestions := []dns.DNSQuestion{
		{Name: "example.com", Type: dns.QtypeA, Class: dns.QclassIN},
	}

	shortcutBytes, err := goscapy.EtherIPUDPDNS(
		"00:11:22:33:44:55",    // 源 MAC
		"00:aa:bb:cc:dd:ee",    // 目标 MAC
		"192.168.1.100",         // 源 IP
		"8.8.8.8",               // 目标 IP (DNS 服务器)
		53,                      // DNS 端口
		shortcutQuestions,       // DNS 查询问题
	)
	if err != nil {
		log.Fatalf("Shortcut DNS 构建失败: %v", err)
	}

	fmt.Printf("Shortcut DNS 查询包: %d 字节\n", len(shortcutBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第四部分: 多个 DNS 查询问题
	// -----------------------------------------------------------------------
	fmt.Println("--- 第四部分: 多个 DNS 查询问题 ---")
	fmt.Println()

	multiQuestions := []dns.DNSQuestion{
		{Name: "example.com", Type: dns.QtypeA, Class: dns.QclassIN},
		{Name: "example.com", Type: dns.QtypeAAAA, Class: dns.QclassIN},
		{Name: "example.com", Type: dns.QtypeMX, Class: dns.QclassIN},
	}

	multiPkt := goscapy.NewDNS().
		ID(0xABCD).
		Questions(multiQuestions)

	pkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").
			DstIP("8.8.8.8").
			Proto(17)).
		Over(goscapy.NewUDP().
			SrcPort(54321).
			DstPort(53)).
		Over(multiPkt)

	multiBytes, err := pkt.Build()
	if err != nil {
		log.Fatalf("构建多问题 DNS 包失败: %v", err)
	}

	fmt.Printf("多问题 DNS 查询 (A + AAAA + MX): %d 字节\n", len(multiBytes))
	fmt.Println()

	// -----------------------------------------------------------------------
	// DNS 记录类型参考
	// -----------------------------------------------------------------------
	fmt.Println("--- DNS 记录类型参考 ---")
	fmt.Println()
	fmt.Println("  dns.QtypeA     (1)  = IPv4 地址")
	fmt.Println("  dns.QtypeNS    (2)  = 名称服务器")
	fmt.Println("  dns.QtypeCNAME (5)  = 别名")
	fmt.Println("  dns.QtypeSOA   (6)  = 起始授权")
	fmt.Println("  dns.QtypePTR   (12) = 指针 (反向 DNS)")
	fmt.Println("  dns.QtypeMX    (15) = 邮件交换")
	fmt.Println("  dns.QtypeTXT   (16) = 文本记录")
	fmt.Println("  dns.QtypeAAAA  (28) = IPv6 地址")
	fmt.Println()
	fmt.Println("下一步: 运行 07-dhcp 示例，学习 DHCP 包构建")
}
