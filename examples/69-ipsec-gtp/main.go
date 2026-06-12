// 示例 69: IPsec 与 GTP — ESP / AH / GTP-U
//
// 本示例演示 goscapy 新增的三个协议:
//   - ESP（封装安全载荷，IP 协议号 50）— 把密文作为不透明数据承载
//   - AH（认证头，IP 协议号 51）— payload len 由 ICV 长度自动计算，nh 链接上层
//   - GTP-U（移动核心网用户面，UDP 2152）— G-PDU 承载内层 IP 包
//
// 运行方式: go run main.go

package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 69: IPsec 与 GTP ===")
	fmt.Println()

	// --- ESP ---
	fmt.Println("--- ESP（IP 协议号 50）---")
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", layers.IPProtoESP)
	esp := layers.NewESPWith(0xDEADBEEF, 1)
	_ = esp.Set("data", []byte{0xAA, 0xBB, 0xCC, 0xDD})
	epkt := packet.NewFrom(ip, esp)
	raw, _ := epkt.Build()
	fmt.Printf("  %s（%d 字节）\n", epkt.String(), len(raw))
	d, _ := packet.DissectByProto(raw, "IP")
	fmt.Printf("  解析: %s\n\n", d.String())

	// --- AH ---
	fmt.Println("--- AH（IP 协议号 51，保护 TCP）---")
	ip2 := layers.NewIP()
	_ = ip2.Set("src", "192.168.1.1")
	_ = ip2.Set("dst", "10.0.0.1")
	_ = ip2.Set("proto", layers.IPProtoAH)
	ah := layers.NewAHWith(layers.IPProtoTCP, 0x11223344, 5)
	_ = ah.Set("icv", make([]byte, 12)) // 12 字节 ICV → len 字段自动算为 4
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(1234))
	_ = tcp.Set("dport", uint16(443))
	apkt := packet.NewFrom(ip2, ah, tcp)
	raw2, _ := apkt.Build()
	fmt.Printf("  %s（%d 字节）\n", apkt.String(), len(raw2))
	d2, _ := packet.DissectByProto(raw2, "IP")
	fmt.Printf("  解析: %s（AH.nh 链接到 TCP）\n\n", d2.String())

	// --- GTP-U ---
	fmt.Println("--- GTP-U（UDP 2152，G-PDU 承载内层 IP）---")
	oIP := layers.NewIP()
	_ = oIP.Set("src", "10.0.0.1")
	_ = oIP.Set("dst", "10.0.0.2")
	_ = oIP.Set("proto", layers.IPProtoUDP)
	oUDP := layers.NewUDP()
	_ = oUDP.Set("sport", layers.GTPUPort)
	_ = oUDP.Set("dport", layers.GTPUPort)
	gtp := layers.NewGTPWith(layers.GTPMsgGPDU, 0xCAFEBABE)
	iIP := layers.NewIP()
	_ = iIP.Set("src", "192.168.1.1")
	_ = iIP.Set("dst", "8.8.8.8")
	_ = iIP.Set("proto", layers.IPProtoICMP)
	gpkt := packet.NewFrom(oIP, oUDP, gtp, iIP, layers.NewICMP())
	raw3, _ := gpkt.Build()
	fmt.Printf("  %s（%d 字节）\n", gpkt.String(), len(raw3))
	d3, _ := packet.DissectByProto(raw3, "IP")
	fmt.Printf("  解析: %s（GTP 后还原内层 IP/ICMP）\n", d3.String())
}
