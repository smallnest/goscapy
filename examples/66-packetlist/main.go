// 示例 66: PacketList — 批量分析、过滤、会话分组与统计
//
// 本示例演示 goscapy 借鉴 Scapy PacketList（rdpcap/sniff 的返回值）的离线
// 分析能力:
//   - packetlist.ReadPcap / pl.WritePcap — 读写整个 pcap 文件
//   - pl.Filter / pl.FilterProto         — 批量过滤
//   - pl.Sessions                        — 按 5 元组分组成双向会话
//   - pl.Statistics / pl.ProtoCounts     — 协议栈与协议出现统计
//   - pl.Summary                         — 逐包一行摘要
//
// 本示例先在内存中生成一个 pcap，再读回分析，因此无需 root。
//
// 运行方式: go run main.go

package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/packetlist"
	"github.com/smallnest/goscapy/pkg/pcap"
)

// timeAt returns a fixed base time plus n seconds, for deterministic timestamps.
func timeAt(n int) time.Time {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(n) * time.Second)
}

func mkPkt(src, dst string, proto uint8, sport, dport uint16) *packet.Packet {
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", src)
	_ = ip.Set("dst", dst)
	_ = ip.Set("proto", proto)
	if proto == layers.IPProtoTCP {
		tcp := layers.NewTCP()
		_ = tcp.Set("sport", sport)
		_ = tcp.Set("dport", dport)
		return packet.NewFrom(eth, ip, tcp)
	}
	udp := layers.NewUDP()
	_ = udp.Set("sport", sport)
	_ = udp.Set("dport", dport)
	return packet.NewFrom(eth, ip, udp)
}

func main() {
	fmt.Println("=== goscapy 示例 66: PacketList 批量分析 ===")
	fmt.Println()

	// 1) 生成一个含多条流的 pcap。
	pl := packetlist.New("demo")
	pl.Append(mkPkt("1.1.1.1", "2.2.2.2", layers.IPProtoTCP, 12345, 80), timeAt(0))
	pl.Append(mkPkt("2.2.2.2", "1.1.1.1", layers.IPProtoTCP, 80, 12345), timeAt(1))
	pl.Append(mkPkt("1.1.1.1", "2.2.2.2", layers.IPProtoTCP, 12345, 80), timeAt(2))
	pl.Append(mkPkt("3.3.3.3", "8.8.8.8", layers.IPProtoUDP, 53000, 53), timeAt(3))
	pl.Append(mkPkt("8.8.8.8", "3.3.3.3", layers.IPProtoUDP, 53, 53000), timeAt(4))

	var buf bytes.Buffer
	_ = pl.WritePcapWriter(&buf, pcap.LinkTypeEthernet)
	tmp, _ := os.CreateTemp("", "goscapy-*.pcap")
	defer os.Remove(tmp.Name())
	_, _ = tmp.Write(buf.Bytes())
	_ = tmp.Close()

	// 2) 读回。
	loaded, err := packetlist.ReadPcap(tmp.Name())
	if err != nil {
		panic(err)
	}
	fmt.Printf("读取: %s\n\n", loaded)

	// 3) 逐包摘要。
	fmt.Println("--- Summary ---")
	fmt.Print(loaded.Summary())
	fmt.Println()

	// 4) 协议统计。
	fmt.Println("--- ProtoCounts ---")
	for proto, n := range loaded.ProtoCounts() {
		fmt.Printf("  %-8s %d\n", proto, n)
	}
	fmt.Println()

	// 5) 协议栈统计。
	fmt.Println("--- Statistics（按完整协议栈）---")
	for stack, n := range loaded.Statistics() {
		fmt.Printf("  %-20s %d\n", stack, n)
	}
	fmt.Println()

	// 6) 会话分组（双向流合并）。
	fmt.Println("--- Sessions（双向 5 元组）---")
	sessions := loaded.Sessions()
	for _, key := range loaded.SessionKeys() {
		fmt.Printf("  %s  → %d 个包\n", key, sessions[key].Len())
	}
	fmt.Println()

	// 7) 过滤。
	tcps := loaded.FilterProto("TCP")
	fmt.Printf("--- FilterProto(\"TCP\") → %d 个包 ---\n", tcps.Len())
}
