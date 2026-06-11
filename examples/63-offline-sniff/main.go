// 示例 63: 离线嗅探 — 从 pcap/pcapng 文件读取并走嗅探回调管线
//
// 本示例演示 goscapy 借鉴 Scapy sniff(offline=...) 的离线嗅探:
//   - sniff.SniffOffline — 从文件逐包解析并调用 handler
//   - OfflineConfig.Filter — Go 层过滤（无需 tcpdump/BPF）
//   - OfflineConfig.Count  — 限制处理包数
//
// 本示例先在内存中生成一个 pcap，再用离线嗅探读回，因此无需 root。
//
// 运行方式: go run main.go

package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/pcap"
	"github.com/smallnest/goscapy/pkg/sniff"
)

func main() {
	fmt.Println("=== goscapy 示例 63: 离线嗅探 ===")
	fmt.Println()

	// 1) 生成一个临时 pcap 文件，含 8 个 ICMP 包。
	var buf bytes.Buffer
	w, _ := pcap.NewWriter(&buf, pcap.LinkTypeEthernet, 65535)
	for i := 0; i < 8; i++ {
		eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
		ip := layers.NewIP()
		_ = ip.Set("src", "192.168.1.1")
		_ = ip.Set("dst", "10.0.0.1")
		_ = ip.Set("proto", layers.IPProtoICMP)
		icmp := layers.NewICMP()
		_ = icmp.Set("seq", uint16(i))
		_ = w.WritePkt(packet.NewFrom(eth, ip, icmp))
	}
	tmp, _ := os.CreateTemp("", "goscapy-*.pcap")
	defer os.Remove(tmp.Name())
	_, _ = tmp.Write(buf.Bytes())
	_ = tmp.Close()

	// 2) 离线嗅探全部包。
	fmt.Println("--- 读取全部包 ---")
	total := 0
	_ = sniff.SniffOffline(sniff.OfflineConfig{Path: tmp.Name()}, func(pkt *packet.Packet) bool {
		total++
		fmt.Printf("  包 %d: %s\n", total, pkt.Summary())
		return true
	})
	fmt.Printf("共处理 %d 个包\n\n", total)

	// 3) Go 层过滤：仅 seq 为偶数的包。
	fmt.Println("--- Go 层过滤（seq 偶数）---")
	matched := 0
	_ = sniff.SniffOffline(sniff.OfflineConfig{
		Path: tmp.Name(),
		Filter: func(pkt *packet.Packet) bool {
			ic := pkt.GetLayer("ICMP")
			if ic == nil {
				return false
			}
			seq, _ := ic.Get("seq")
			return seq.(uint16)%2 == 0
		},
	}, func(pkt *packet.Packet) bool {
		matched++
		ic := pkt.GetLayer("ICMP")
		seq, _ := ic.Get("seq")
		fmt.Printf("  匹配: seq=%d\n", seq)
		return true
	})
	fmt.Printf("过滤后匹配 %d 个包\n", matched)
}
