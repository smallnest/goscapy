// 示例 60: hexdump 与字段自省 — Hexdump/Show2/Ls/FieldNames
//
// 本示例演示 goscapy 借鉴 Scapy 的调试与自省 API:
//   - packet.Hexdump(data) / pkt.Hexdump() — 经典 hex+ASCII 转储
//   - pkt.Show2() — 构建后重新解析并显示（自动填充长度/校验和）
//   - packet.Ls("IP") — 列出某协议的字段、类型、默认值
//   - packet.Ls("") — 列出所有已注册协议
//   - packet.FieldNames("TCP") — 程序化获取字段名列表
//
// 运行方式: go run main.go

package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 60: hexdump 与字段自省 ===")
	fmt.Println()

	// 构建一个 Ethernet / IP / TCP 包。
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", layers.IPProtoTCP)
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", layers.TCPSyn)
	pkt := packet.NewFrom(eth, ip, tcp)

	// --- 第一部分: Hexdump ---
	fmt.Println("--- pkt.Hexdump() ---")
	fmt.Print(pkt.Hexdump())
	fmt.Println()

	// --- 第二部分: Show2（构建后重新解析）---
	fmt.Println("--- pkt.Show2()（注意 len/chksum 已自动填充）---")
	fmt.Print(pkt.Show2())
	fmt.Println()

	// --- 第三部分: Ls 协议自省 ---
	fmt.Println("--- packet.Ls(\"IP\") ---")
	fmt.Print(packet.Ls("IP"))
	fmt.Println()

	// --- 第四部分: FieldNames 程序化字段列表 ---
	fmt.Println("--- packet.FieldNames(\"TCP\") ---")
	fmt.Println(packet.FieldNames("TCP"))
	fmt.Println()

	// --- 第五部分: 所有已注册协议 ---
	fmt.Println("--- packet.ListLayers()（前 10 个）---")
	all := packet.ListLayers()
	for i, name := range all {
		if i >= 10 {
			fmt.Printf("... 共 %d 个协议\n", len(all))
			break
		}
		fmt.Printf("  %s\n", name)
	}
}
