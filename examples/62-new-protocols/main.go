// 示例 62: 新增协议 — SCTP / IGMP / MPLS / PPPoE
//
// 本示例演示 goscapy 新增的四个常见协议的构造与解析:
//   - SCTP（IP 协议号 132，CRC32c 校验自动计算）
//   - IGMP（组播管理，IP 协议号 2）
//   - MPLS（标签栈，可多层堆叠）
//   - PPPoE + PPP（宽带接入封装）
//
// 运行方式: go run main.go

package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 62: SCTP / IGMP / MPLS / PPPoE ===")
	fmt.Println()

	// --- SCTP ---
	fmt.Println("--- SCTP（带 INIT chunk）---")
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", layers.IPProtoSCTP)
	sctp := layers.NewSCTPWith(40000, 80, 0xDEADBEEF)
	chunk := layers.NewSCTPChunk()
	_ = chunk.Set("type", layers.SCTPChunkInit)
	scpkt := packet.NewFrom(ip, sctp, chunk)
	raw, _ := scpkt.Build()
	fmt.Printf("  %s（%d 字节，CRC32c 自动计算）\n", scpkt.String(), len(raw))
	d, _ := packet.DissectByProto(raw, "IP")
	fmt.Printf("  解析: %s\n\n", d.String())

	// --- IGMP ---
	fmt.Println("--- IGMP v2 成员报告 ---")
	ip2 := layers.NewIP()
	_ = ip2.Set("src", "192.168.1.10")
	_ = ip2.Set("dst", "224.0.0.22")
	_ = ip2.Set("proto", layers.IPProtoIGMP)
	igmp := layers.NewIGMPWith(layers.IGMPv2MembershipReport, "239.1.2.3")
	igpkt := packet.NewFrom(ip2, igmp)
	raw2, _ := igpkt.Build()
	fmt.Printf("  %s（%d 字节）\n", igpkt.String(), len(raw2))
	d2, _ := packet.DissectByProto(raw2, "IP")
	fmt.Printf("  解析: %s\n\n", d2.String())

	// --- MPLS 标签栈 ---
	fmt.Println("--- MPLS 双层标签栈 ---")
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeMPLSUnicast)
	outer := layers.NewMPLSWith(100, 0, false, 64) // 非栈底
	inner := layers.NewMPLSWith(200, 0, true, 64)  // 栈底
	ip3 := layers.NewIP()
	_ = ip3.Set("src", "192.168.1.1")
	_ = ip3.Set("dst", "10.0.0.1")
	_ = ip3.Set("proto", layers.IPProtoICMP)
	mpkt := packet.NewFrom(eth, outer, inner, ip3, layers.NewICMP())
	raw3, _ := mpkt.Build()
	fmt.Printf("  %s（%d 字节）\n", mpkt.String(), len(raw3))
	d3, _ := packet.DissectByProto(raw3, "Ethernet")
	fmt.Printf("  解析: %s\n\n", d3.String())

	// --- PPPoE 会话 ---
	fmt.Println("--- PPPoE 会话承载 IP ---")
	eth2 := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypePPPoESession)
	pppoe := layers.NewPPPoEWith(layers.PPPoECodeSession, 0x0001)
	ppp := layers.NewPPPWith(layers.PPPProtoIPv4)
	ip4 := layers.NewIP()
	_ = ip4.Set("src", "10.0.0.1")
	_ = ip4.Set("dst", "10.0.0.2")
	_ = ip4.Set("proto", layers.IPProtoICMP)
	ppkt := packet.NewFrom(eth2, pppoe, ppp, ip4, layers.NewICMP())
	raw4, _ := ppkt.Build()
	fmt.Printf("  %s（%d 字节）\n", ppkt.String(), len(raw4))
	d4, _ := packet.DissectByProto(raw4, "Ethernet")
	fmt.Printf("  解析: %s\n", d4.String())
}
