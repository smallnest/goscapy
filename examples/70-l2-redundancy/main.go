// 示例 70: 二层/冗余协议 — VRRP / HSRP / STP / EAPOL
//
// 本示例演示 goscapy 新增的四个二层与网关冗余协议:
//   - VRRP（虚拟路由器冗余，IP 协议号 112，自动校验和）
//   - HSRP（Cisco 热备份路由，UDP 1985）
//   - STP（生成树 BPDU，IEEE 802.1D）
//   - EAPOL + EAP（IEEE 802.1X 端口接入认证）
//
// 运行方式: go run main.go

package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 70: VRRP / HSRP / STP / EAPOL ===")
	fmt.Println()

	// --- VRRP ---
	fmt.Println("--- VRRP（IP 协议号 112）---")
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "224.0.0.18") // VRRP 组播地址
	_ = ip.Set("proto", layers.IPProtoVRRP)
	vrrp := layers.NewVRRPWith(1, 100, "192.168.1.254")
	vpkt := packet.NewFrom(ip, vrrp)
	raw, _ := vpkt.Build()
	fmt.Printf("  %s（%d 字节，VRID=1 优先级=100）\n", vpkt.String(), len(raw))
	d, _ := packet.DissectByProto(raw, "IP")
	fmt.Printf("  解析: %s\n\n", d.String())

	// --- HSRP ---
	fmt.Println("--- HSRP（UDP 1985）---")
	ip2 := layers.NewIP()
	_ = ip2.Set("src", "192.168.1.1")
	_ = ip2.Set("dst", "224.0.0.2")
	_ = ip2.Set("proto", layers.IPProtoUDP)
	udp := layers.NewUDP()
	_ = udp.Set("sport", layers.HSRPPort)
	_ = udp.Set("dport", layers.HSRPPort)
	hsrp := layers.NewHSRPWith(1, 110, "192.168.1.254")
	hpkt := packet.NewFrom(ip2, udp, hsrp)
	raw2, _ := hpkt.Build()
	fmt.Printf("  %s（%d 字节，组=1 优先级=110）\n", hpkt.String(), len(raw2))
	d2, _ := packet.DissectByProto(raw2, "IP")
	fmt.Printf("  解析: %s\n\n", d2.String())

	// --- STP ---
	fmt.Println("--- STP 配置 BPDU（IEEE 802.1D）---")
	stp := layers.NewSTPConfig(0x8000, "aa:bb:cc:dd:ee:ff")
	spkt := packet.NewFrom(stp)
	raw3, _ := spkt.Build()
	fmt.Printf("  STP BPDU（%d 字节，桥优先级=0x8000）\n", len(raw3))
	d3, _ := packet.DissectByProto(raw3, "STP")
	fmt.Printf("  解析: %s\n\n", d3.String())

	// --- EAPOL + EAP ---
	fmt.Println("--- EAPOL / EAP（IEEE 802.1X）---")
	eth := layers.NewEthernetWith("01:80:c2:00:00:03", "11:22:33:44:55:66", layers.EtherTypeEAPOL)
	eapol := layers.NewEAPOLWith(layers.EAPOLTypeEAP)
	eap := layers.NewEAPWith(layers.EAPCodeResponse, 1)
	_ = eap.Set("data", append([]byte{0x01}, []byte("user")...)) // EAP-Identity: user
	epkt := packet.NewFrom(eth, eapol, eap)
	raw4, _ := epkt.Build()
	fmt.Printf("  %s（%d 字节，EAP-Response/Identity）\n", epkt.String(), len(raw4))
	d4, _ := packet.DissectByProto(raw4, "Ethernet")
	fmt.Printf("  解析: %s\n", d4.String())
}
