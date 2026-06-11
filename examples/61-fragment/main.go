// 示例 61: IP/IPv6 分片构造 — Fragment / Fragment6
//
// 本示例演示 goscapy 借鉴 Scapy fragment()/fragment6() 的构造侧分片:
//   - layers.Fragment(pkt, fragSize) — 将大 IPv4 包切成分片序列
//   - layers.Fragment6(pkt, fragSize, id) — 使用 IPv6 分片扩展头切片
//
// 分片是与 pkg/reassembly（重组）对称的能力，可用于构造测试 IDS/防火墙
// 分片重组逻辑的流量。
//
// 运行方式: go run main.go

package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 61: IP/IPv6 分片构造 ===")
	fmt.Println()

	// --- IPv4 分片 ---
	fmt.Println("--- layers.Fragment（IPv4）---")
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.1")
	_ = ip.Set("dst", "10.0.0.1")
	_ = ip.Set("proto", layers.IPProtoUDP)
	_ = ip.Set("id", uint16(0x1234))
	udp := layers.NewUDP()
	_ = udp.Set("sport", uint16(1111))
	_ = udp.Set("dport", uint16(2222))
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := packet.NewFrom(ip, udp, layers.NewRawWith(payload))

	frags, err := layers.Fragment(pkt, 1000)
	if err != nil {
		panic(err)
	}
	fmt.Printf("原始 L4 负载约 3008 字节，按 1000 字节分片 → %d 个分片\n", len(frags))
	for i, f := range frags {
		fl := f.GetLayer("IP")
		fragVal, _ := fl.Get("frag")
		frag := fragVal.(uint16)
		mf := frag&0x2000 != 0
		off := (frag & 0x1FFF) * 8
		raw, _ := f.Build()
		fmt.Printf("  分片 %d: offset=%-5d MF=%-5v 总长=%d 字节\n", i, off, mf, len(raw))
	}
	fmt.Println()

	// --- IPv6 分片 ---
	fmt.Println("--- layers.Fragment6（IPv6）---")
	ip6 := layers.NewIPv6()
	_ = ip6.Set("src", "2001:db8::1")
	_ = ip6.Set("dst", "2001:db8::2")
	_ = ip6.Set("nh", layers.IPv6NextHdrUDP)
	udp6 := layers.NewUDP()
	_ = udp6.Set("sport", uint16(1111))
	_ = udp6.Set("dport", uint16(2222))
	pkt6 := packet.NewFrom(ip6, udp6, layers.NewRawWith(payload))

	frags6, err := layers.Fragment6(pkt6, 1000, 0xCAFEBABE)
	if err != nil {
		panic(err)
	}
	fmt.Printf("IPv6 分片 → %d 个分片（共享 id=0xCAFEBABE）\n", len(frags6))
	for i, f := range frags6 {
		fh := f.GetLayer("IPv6 Fragment")
		fragVal, _ := fh.Get("frag")
		frag := fragVal.(uint16)
		mf := frag&0x0001 != 0
		off := (frag >> 3) * 8
		raw, _ := f.Build()
		fmt.Printf("  分片 %d: offset=%-5d M=%-5v 总长=%d 字节\n", i, off, mf, len(raw))
	}
}
