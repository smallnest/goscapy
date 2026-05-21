// 示例 38: pcap/pcapng 文件读写
//
// 本示例演示 goscapy 的纯 Go pcap/pcapng 文件读写功能:
//   - 将构造的包写入 pcap 文件
//   - 从 pcap 文件中读取并解析包
//   - 自动检测 pcap vs pcapng 格式
//   - 支持读取 Wireshark/tcpdump 生成的文件
//
// 运行方式: go run main.go [-f <pcap文件>] [-w <输出文件>] [-n <写入包数>]
// 示例:     go run main.go                          # 写入并读回
//           go run main.go -f capture.pcap          # 读取已有文件
//           go run main.go -w output.pcap -n 100    # 写入 100 个包
//
// 无需 root 权限，不需要 libpcap。

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/pcap"
)

func main() {
	readFile := flag.String("f", "demp.pcap", "要读取的 pcap/pcapng 文件")
	writeFile := flag.String("w", "", "输出 pcap 文件路径 (默认: /tmp/goscapy-demo.pcap)")
	numPkts := flag.Int("n", 10, "写入的包数量")
	flag.Parse()

	if *readFile != "" {
		readPcapFile(*readFile)
		return
	}

	outFile := *writeFile
	if outFile == "" {
		outFile = "/tmp/goscapy-demo.pcap"
	}

	// 步骤 1: 写入 pcap 文件
	fmt.Printf("=== 写入 pcap 文件: %s (%d 包) ===\n\n", outFile, *numPkts)
	writePcapFile(outFile, *numPkts)

	// 步骤 2: 读回并解析
	fmt.Printf("\n=== 读取 pcap 文件: %s ===\n\n", outFile)
	readPcapFile(outFile)
}

func writePcapFile(filename string, count int) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建文件失败: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// 创建 pcap writer (Ethernet 链路类型)
	w, err := pcap.NewWriter(f, pcap.LinkTypeEthernet, 65535)
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建 writer 失败: %v\n", err)
		os.Exit(1)
	}

	baseTime := time.Now()

	for i := range count {
		// 构造不同类型的包
		var pkt *packet.Packet
		switch i % 3 {
		case 0:
			pkt = buildICMPPacket(i)
		case 1:
			pkt = buildTCPPacket(i)
		case 2:
			pkt = buildUDPPacket(i)
		}

		// 方式 1: 用 WritePkt 直接写入结构化包
		ts := baseTime.Add(time.Duration(i) * 100 * time.Millisecond)

		data, err := pkt.Build()
		if err != nil {
			fmt.Fprintf(os.Stderr, "构建包 %d 失败: %v\n", i, err)
			continue
		}

		if err := w.WritePacket(data, ts); err != nil {
			fmt.Fprintf(os.Stderr, "写入包 %d 失败: %v\n", i, err)
			continue
		}
		fmt.Printf("  写入包 #%d: %d 字节, ts=%s\n", i, len(data), ts.Format("15:04:05.000"))
	}

	fmt.Printf("\n成功写入 %d 个包到 %s\n", count, filename)
}

func readPcapFile(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开文件失败: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := pcap.NewReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建 reader 失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("链路类型: %d (%s)\n\n", r.LinkType(), linkTypeName(r.LinkType()))

	count := 0
	var errp error
	for rec := range r.Packets(&errp) {
		count++
		fmt.Printf("包 #%d: %d 字节 (原始 %d), 时间 %s\n",
			count, rec.CaptureLen, rec.OrigLen,
			rec.Timestamp.Format("2006-01-02 15:04:05.000000"))

		// 解析为结构化包
		pkt, err := rec.Packet()
		if err != nil {
			fmt.Printf("  解析失败: %v\n", err)
			continue
		}

		// 打印各层信息
		for _, layer := range pkt.Layers() {
			fmt.Printf("  层: %s\n", layer.Proto())
		}

		// 显示 IP 信息
		ipLayer := pkt.GetLayer("IP")
		if ipLayer != nil {
			src, _ := ipLayer.Get("src")
			dst, _ := ipLayer.Get("dst")
			proto, _ := ipLayer.Get("proto")
			fmt.Printf("  IP: %v -> %v, proto=%v\n", src, dst, proto)
		}

		if count >= 20 {
			fmt.Printf("  ... (仅显示前 20 个包)\n")
			break
		}
	}
	if errp != nil {
		fmt.Fprintf(os.Stderr, "读取错误: %v\n", errp)
	}
	fmt.Printf("\n共读取 %d 个包\n", count)
}

func buildICMPPacket(seq int) *packet.Packet {
	eth := layers.NewEthernetWith("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0800)
	ip := layers.NewIP()
	ip.Set("src", "192.168.1.100")
	ip.Set("dst", "192.168.1.1")
	ip.Set("proto", layers.IPProtoICMP)
	icmp := layers.NewICMPEcho(0x1234, uint16(seq))
	payload := layers.NewRawWith([]byte("goscapy pcap demo"))
	return packet.NewFrom(eth, ip, icmp, payload)
}

func buildTCPPacket(seq int) *packet.Packet {
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800)
	ip := layers.NewIP()
	ip.Set("src", "10.0.0.100")
	ip.Set("dst", "10.0.0.1")
	ip.Set("proto", layers.IPProtoTCP)
	tcp := layers.NewTCPWith(uint16(40000+seq), 80, layers.TCPSyn|layers.TCPAck)
	tcp.Set("seq", uint32(seq*1000))
	tcp.Set("ack", uint32(1))
	return packet.NewFrom(eth, ip, tcp)
}

func buildUDPPacket(seq int) *packet.Packet {
	eth := layers.NewEthernetWith("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800)
	ip := layers.NewIP()
	ip.Set("src", "172.16.0.50")
	ip.Set("dst", "8.8.8.8")
	ip.Set("proto", layers.IPProtoUDP)
	udp := layers.NewUDP()
	udp.Set("sport", uint16(12345))
	udp.Set("dport", uint16(53))
	payload := layers.NewRawWith([]byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional: 0
	})
	return packet.NewFrom(eth, ip, udp, payload)
}

func linkTypeName(lt uint32) string {
	switch lt {
	case pcap.LinkTypeNull:
		return "NULL/Loopback"
	case pcap.LinkTypeEthernet:
		return "Ethernet"
	case pcap.LinkTypeRaw:
		return "Raw IP"
	case pcap.LinkTypeIPv4:
		return "Raw IPv4"
	case pcap.LinkTypeIPv6:
		return "Raw IPv6"
	default:
		return "Unknown"
	}
}
