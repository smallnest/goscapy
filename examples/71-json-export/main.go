// 示例 71: JSON 序列化与外部工具联动 — ToJSON / Tcpdump / Wireshark
//
// 本示例演示 goscapy 的易用性增强:
//   - pkt.ToJSON / pkt.ToJSONIndent — 把包结构序列化为 JSON，便于与其他工具链集成
//   - goscapy.Tcpdump  — 把包写入临时 pcap 并用 tcpdump 解析（需安装 tcpdump）
//   - goscapy.Wireshark — 把包写入临时 pcap 并用 Wireshark 打开（需安装 wireshark）
//
// 运行方式: go run main.go
// （JSON 部分无需任何外部依赖；tcpdump 部分仅在已安装时运行）

package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 71: JSON 序列化与外部工具联动 ===")
	fmt.Println()

	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "8.8.8.8")
	_ = ip.Set("proto", layers.IPProtoTCP)
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(40000))
	_ = tcp.Set("dport", uint16(443))
	_ = tcp.Set("flags", layers.TCPSyn)
	pkt := packet.NewFrom(eth, ip, tcp)

	// --- JSON 序列化 ---
	fmt.Println("--- pkt.ToJSONIndent ---")
	data, err := pkt.ToJSONIndent("", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
	fmt.Println()

	// --- tcpdump 联动（如已安装）---
	fmt.Println("--- goscapy.Tcpdump（如已安装 tcpdump）---")
	out, err := goscapy.Tcpdump([]string{"-n", "-v"}, pkt)
	if err != nil {
		fmt.Printf("  跳过: %v\n", err)
	} else {
		fmt.Print(out)
	}
	fmt.Println()

	fmt.Println("提示: goscapy.Wireshark(pkt) 会把包写入临时 pcap 并打开 Wireshark。")
}
