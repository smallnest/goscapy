// 示例 41: 协议模糊测试 (Fuzzing)
//
// 本示例演示如何使用 goscapy 的 Fuzz 引擎进行协议模糊测试。
// 你将学到:
//   - 如何使用 Fuzz() 随机化未设置的字段
//   - 如何使用 FuzzPacket() 模糊化整个数据包
//   - 如何与 Builder API 组合使用
//   - 如何构建模糊测试循环发送变异数据包
//
// 运行: sudo go run main.go
package main

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy Fuzzing 示例 ===")
	fmt.Println()

	// 1. 基础 Fuzz: 随机化一个层的所有默认值字段
	fmt.Println("--- 1. 基础 Fuzz ---")
	tcp := layers.NewTCP()
	tcp.Set("dport", uint16(80)) // 只设置目标端口

	fmt.Println("Fuzz 前 TCP:")
	printFields(tcp)

	goscapy.Fuzz(tcp)
	fmt.Println("Fuzz 后 TCP (dport=80 被保留, 其余随机化):")
	printFields(tcp)
	fmt.Println()

	// 2. FuzzPacket: 模糊化整个数据包的所有层
	fmt.Println("--- 2. FuzzPacket ---")
	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP("10.0.0.1"))
	icmp := layers.NewICMP()
	icmp.Set("type", uint8(8)) // Echo Request

	pkt := packet.NewFrom(ip, icmp)
	goscapy.FuzzPacket(pkt)

	fmt.Println("Fuzz 后 IP 层 (dst=10.0.0.1 保留):")
	printFields(pkt.Layers()[0])
	fmt.Println()

	// 3. 与 Builder API 组合
	fmt.Println("--- 3. Builder API 组合 ---")
	tcpFuzz := layers.NewTCP()
	goscapy.Fuzz(tcpFuzz)

	ipFuzz := layers.NewIP()
	ipFuzz.Set("dst", net.ParseIP("192.168.1.1"))
	goscapy.Fuzz(ipFuzz)

	pkt2 := ipFuzz.Over(tcpFuzz)
	raw, err := pkt2.Build()
	if err != nil {
		fmt.Printf("Build 失败: %v\n", err)
		return
	}
	fmt.Printf("构建成功: %d 字节\n", len(raw))
	fmt.Printf("  IP src=%v dst=%v\n", mustGet(ipFuzz, "src"), mustGet(ipFuzz, "dst"))
	fmt.Printf("  TCP sport=%v dport=%v\n", mustGet(tcpFuzz, "sport"), mustGet(tcpFuzz, "dport"))
	fmt.Println()

	// 4. 模糊测试循环: 生成并打印多个变异包
	fmt.Println("--- 4. 模糊测试循环 (生成 5 个变异包) ---")
	for i := 0; i < 5; i++ {
		tcp := layers.NewTCP()
		tcp.Set("dport", uint16(80))
		goscapy.Fuzz(tcp)

		ip := layers.NewIP()
		ip.Set("dst", net.ParseIP("10.0.0.1"))
		goscapy.Fuzz(ip)

		pkt := ip.Over(tcp)
		raw, err := pkt.Build()
		if err != nil {
			fmt.Printf("  [#%d] Build 失败: %v\n", i+1, err)
			continue
		}

		src, _ := ip.Get("src")
		sport, _ := tcp.Get("sport")
		flags, _ := tcp.Get("flags")
		fmt.Printf("  [#%d] %d bytes | src=%v sport=%v flags=0x%02x\n",
			i+1, len(raw), src, sport, flags)
	}
}

func printFields(l *packet.Layer) {
	for _, f := range l.Fields() {
		v, err := l.Get(f.Name())
		if err != nil {
			continue
		}
		fmt.Printf("  %s = %v\n", f.Name(), v)
	}
}

func mustGet(l *packet.Layer, name string) any {
	v, _ := l.Get(name)
	return v
}
