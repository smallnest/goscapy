// 示例 16: Shortcut 快捷函数综合示例
//
// 本示例演示 goscapy 提供的所有 Shortcut 函数。
// 你将学到:
//   - 每个 Shortcut 函数的用法和参数
//   - Shortcut 函数和 Builder API 的代码量对比
//   - 何时用 Shortcut、何时用 Builder
//
// 运行方式: go run main.go
// 注意: 本示例仅构建数据包，不需要 root 权限。

package main

import (
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dhcp"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/layers/gre"
)

func main() {
	fmt.Println("=== goscapy 示例 16: Shortcut 快捷函数 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// Shortcut 函数简介
	// -----------------------------------------------------------------------
	// Shortcut 函数是一行构建常见协议栈的便捷方法。
	// 它们使用合理的默认值，适合快速原型开发和简单场景。
	//
	// 何时用 Shortcut:
	//   - 快速测试和原型
	//   - 不需要自定义所有字段
	//   - 标准协议栈组合
	//
	// 何时用 Builder API:
	//   - 需要精细控制每个字段
	//   - 非标准协议组合
	//   - 需要访问 Packet 对象（如发送/接收）

	// -----------------------------------------------------------------------
	// 1. EtherIPICMP - Ethernet + IPv4 + ICMP
	// -----------------------------------------------------------------------
	fmt.Println("1. EtherIPICMP - ICMP Echo Request")
	fmt.Println("   用法: EtherIPICMP(目标MAC, 目标IP, ICMP类型, ICMP代码)")

	data, err := goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 2. EtherIPTCP - Ethernet + IPv4 + TCP
	// -----------------------------------------------------------------------
	fmt.Println("2. EtherIPTCP - TCP SYN 包")
	fmt.Println("   用法: EtherIPTCP(源MAC, 目标MAC, 源IP, 目标IP, 源端口, 目标端口, 标志)")

	data, err = goscapy.EtherIPTCP(
		"00:11:22:33:44:55", "00:aa:bb:cc:dd:ee",
		"192.168.1.100", "10.0.0.1",
		12345, 80,
		layers.TCPSyn,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 3. EtherIPUDP - Ethernet + IPv4 + UDP
	// -----------------------------------------------------------------------
	fmt.Println("3. EtherIPUDP - UDP 数据报")
	fmt.Println("   用法: EtherIPUDP(源MAC, 目标MAC, 源IP, 目标IP, 源端口, 目标端口)")

	data, err = goscapy.EtherIPUDP(
		"00:11:22:33:44:55", "00:aa:bb:cc:dd:ee",
		"192.168.1.100", "8.8.8.8",
		12345, 53,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 4. EtherARP - Ethernet + ARP
	// -----------------------------------------------------------------------
	fmt.Println("4. EtherARP - ARP 请求")
	fmt.Println("   用法: EtherARP(源MAC, 目标MAC, 发送方IP, 目标IP, 操作码)")

	data, err = goscapy.EtherARP(
		"00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff",
		"192.168.1.100", "192.168.1.1",
		layers.ARPWhoHas,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 5. EtherIP - Ethernet + IPv4 (带原始载荷)
	// -----------------------------------------------------------------------
	fmt.Println("5. EtherIP - Ethernet + IPv4 + 原始载荷")
	fmt.Println("   用法: EtherIP(源MAC, 目标MAC, 源IP, 目标IP, 载荷)")

	data, err = goscapy.EtherIP(
		"00:11:22:33:44:55", "00:aa:bb:cc:dd:ee",
		"192.168.1.100", "10.0.0.1",
		[]byte("Hello, World!"),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 6. IPICMP - IPv4 + ICMP (无 Ethernet 头)
	// -----------------------------------------------------------------------
	fmt.Println("6. IPICMP - L3 层 ICMP (无 Ethernet)")
	fmt.Println("   用法: IPICMP(源IP, 目标IP, ICMP类型, ICMP代码)")

	data, err = goscapy.IPICMP("192.168.1.100", "8.8.8.8", 8, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节 (无 Ethernet 头)\n\n", len(data))

	// -----------------------------------------------------------------------
	// 7. IPTCP - IPv4 + TCP (无 Ethernet 头)
	// -----------------------------------------------------------------------
	fmt.Println("7. IPTCP - L3 层 TCP")
	fmt.Println("   用法: IPTCP(源IP, 目标IP, 源端口, 目标端口, 标志)")

	data, err = goscapy.IPTCP("192.168.1.100", "10.0.0.1", 12345, 80, layers.TCPSyn)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 8. IPUDP - IPv4 + UDP (无 Ethernet 头)
	// -----------------------------------------------------------------------
	fmt.Println("8. IPUDP - L3 层 UDP")
	fmt.Println("   用法: IPUDP(源IP, 目标IP, 源端口, 目标端口)")

	data, err = goscapy.IPUDP("192.168.1.100", "8.8.8.8", 12345, 53)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 9. IPv6ICMPv6Echo - IPv6 + ICMPv6 Echo
	// -----------------------------------------------------------------------
	fmt.Println("9. IPv6ICMPv6Echo - IPv6 Ping6")
	fmt.Println("   用法: IPv6ICMPv6Echo(源IPv6, 目标IPv6, ID, 序列号)")

	data, err = goscapy.IPv6ICMPv6Echo("fe80::1", "fe80::2", 0x1234, 1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 10. EtherDot1QIP - Ethernet + VLAN + IPv4
	// -----------------------------------------------------------------------
	fmt.Println("10. EtherDot1QIP - 带 VLAN 标签的 IP 包")
	fmt.Println("    用法: EtherDot1QIP(源MAC, 目标MAC, 源IP, 目标IP, VLAN_ID)")

	data, err = goscapy.EtherDot1QIP(
		"00:11:22:33:44:55", "00:aa:bb:cc:dd:ee",
		"192.168.100.10", "192.168.100.20",
		100,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 11. EtherIPUDPVXLAN - Ethernet + IP + UDP + VXLAN
	// -----------------------------------------------------------------------
	fmt.Println("11. EtherIPUDPVXLAN - VXLAN 隧道包")
	fmt.Println("    用法: EtherIPUDPVXLAN(源MAC, 目标MAC, 源IP, 目标IP, VNI, 内层载荷)")

	innerPayload := []byte{0x00, 0x01, 0x02, 0x03}
	data, err = goscapy.EtherIPUDPVXLAN(
		"00:11:22:33:44:55", "00:aa:bb:cc:dd:ee",
		"10.0.0.1", "10.0.0.2",
		10001,
		innerPayload,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 12. EtherIPGRE - Ethernet + IP + GRE
	// -----------------------------------------------------------------------
	fmt.Println("12. EtherIPGRE - GRE 隧道包")
	fmt.Println("    用法: EtherIPGRE(源MAC, 目标MAC, 源IP, 目标IP, 协议类型, Key, 内层载荷)")

	data, err = goscapy.EtherIPGRE(
		"00:11:22:33:44:55", "00:aa:bb:cc:dd:ee",
		"10.0.0.1", "10.0.0.2",
		gre.ProtoIP, 0xABCD,
		[]byte("inner payload"),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 13. EtherIPUDPDNS - Ethernet + IP + UDP + DNS
	// -----------------------------------------------------------------------
	fmt.Println("13. EtherIPUDPDNS - DNS 查询包")
	fmt.Println("    用法: EtherIPUDPDNS(源MAC, 目标MAC, 源IP, 目标IP, DNS端口, 查询问题)")

	data, err = goscapy.EtherIPUDPDNS(
		"00:11:22:33:44:55", "00:aa:bb:cc:dd:ee",
		"192.168.1.100", "8.8.8.8", 53,
		[]dns.DNSQuestion{
			{Name: "example.com", Type: dns.QtypeA, Class: dns.QclassIN},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// 14. EtherIPUDPDHCP - Ethernet + IP + UDP + DHCP
	// -----------------------------------------------------------------------
	fmt.Println("14. EtherIPUDPDHCP - DHCP Discover 包")
	fmt.Println("    用法: EtherIPUDPDHCP(源MAC, 目标MAC, 事务ID, 消息类型)")

	data, err = goscapy.EtherIPUDPDHCP(
		"00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff",
		0x12345678,
		dhcp.DHCPDISCOVER,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    结果: %d 字节\n\n", len(data))

	// -----------------------------------------------------------------------
	// Shortcut vs Builder 对比总结
	// -----------------------------------------------------------------------
	fmt.Println("--- Shortcut vs Builder 对比 ---")
	fmt.Println()
	fmt.Println("Shortcut 一行代码:")
	fmt.Println("  goscapy.EtherIPICMP(\"ff:ff:ff:ff:ff:ff\", \"8.8.8.8\", 8, 0)")
	fmt.Println()
	fmt.Println("Builder API 等价写法:")
	fmt.Println("  goscapy.NewEthernet().")
	fmt.Println("    SrcMAC(\"00:00:00:00:00:00\").DstMAC(\"ff:ff:ff:ff:ff:ff\").")
	fmt.Println("    Over(goscapy.NewIP().SrcIP(\"0.0.0.0\").DstIP(\"8.8.8.8\")).")
	fmt.Println("    Over(goscapy.NewICMP().Type(8).Code(0)).")
	fmt.Println("    Build()")
	fmt.Println()
	fmt.Println("Builder API 的优势:")
	fmt.Println("  - 可以设置所有字段（TTL、ID、Window 等）")
	fmt.Println("  - 可以获取 Packet 对象用于发送")
	fmt.Println("  - 支持非标准协议组合")
}
