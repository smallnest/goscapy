// 示例 58: 包内省 API — Show/Summary/ListLayers/Describe
//
// 本示例演示如何使用 goscapy 的包内省 API 进行数据包的格式化显示、
// 一行摘要、已注册协议列表和层字段描述。
//
// 功能:
//   - pkt.Show() — 格式化多行显示所有层和字段值
//   - pkt.Summary() — 一行摘要（如 "IP 192.168.1.1 > 10.0.0.1 TCP S 80 > 12345"）
//   - packet.ListLayers() — 列出所有已注册的协议层名称
//   - layer.Describe() — 显示层的字段、类型和默认值
//   - fmt.Printf("%s", pkt) 和 fmt.Printf("%s", layer) — String() 方法集成
//
// 运行方式: go run main.go

package main

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 58: 包内省 API ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第一部分: pkt.Show() — 格式化多行显示
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: pkt.Show() 格式化显示 ---")
	fmt.Println()

	eth := layers.NewEthernet()
	_ = eth.Set("src", net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	_ = eth.Set("dst", net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	_ = eth.Set("type", uint16(0x0800))

	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.100")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("ttl", uint8(64))
	_ = ip.Set("proto", uint8(6))

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(54321))
	_ = tcp.Set("dport", uint16(443))
	_ = tcp.Set("flags", uint8(0x02)) // SYN

	pkt := packet.NewFrom(eth, ip, tcp)
	fmt.Print(pkt.Show())

	// -----------------------------------------------------------------------
	// 第二部分: pkt.Summary() — 一行摘要
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第二部分: pkt.Summary() 一行摘要 ---")
	fmt.Println()

	fmt.Printf("摘要: %s\n", pkt.Summary())

	// SYN+ACK response
	ip2 := layers.NewIP()
	_ = ip2.Set("src", "10.0.0.1")
	_ = ip2.Set("dst", "192.168.1.100")
	_ = ip2.Set("proto", uint8(6))

	tcp2 := layers.NewTCP()
	_ = tcp2.Set("sport", uint16(443))
	_ = tcp2.Set("dport", uint16(54321))
	_ = tcp2.Set("flags", uint8(0x12)) // SYN+ACK

	pkt2 := packet.NewFrom(ip2, tcp2)
	fmt.Printf("摘要: %s\n", pkt2.Summary())

	// UDP packet
	ipUdp := layers.NewIP()
	_ = ipUdp.Set("src", "192.168.1.100")
	_ = ipUdp.Set("dst", "10.0.0.1")
	_ = ipUdp.Set("proto", uint8(17))

	udp := layers.NewUDP()
	_ = udp.Set("sport", uint16(53))
	_ = udp.Set("dport", uint16(12345))

	pkt3 := packet.NewFrom(ipUdp, udp)
	fmt.Printf("摘要: %s\n", pkt3.Summary())

	// -----------------------------------------------------------------------
	// 第三部分: packet.ListLayers() — 已注册协议列表
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第三部分: packet.ListLayers() 已注册协议 ---")
	fmt.Println()

	layerNames := packet.ListLayers()
	fmt.Printf("共 %d 个已注册协议:\n", len(layerNames))
	for i, name := range layerNames {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(name)
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第四部分: layer.Describe() — 层字段描述
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第四部分: layer.Describe() 字段描述 ---")
	fmt.Println()

	fmt.Print(layers.NewIP().Describe())
	fmt.Print(layers.NewTCP().Describe())

	// -----------------------------------------------------------------------
	// 第五部分: String() 方法集成
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第五部分: String() 方法集成 ---")
	fmt.Println()

	// Packet.String() returns layer stack like "Ethernet / IP / TCP"
	fmt.Printf("Packet: %s\n", pkt)

	// Layer.String() returns detailed field representation
	fmt.Printf("Layer:  %s\n", ip)
}
