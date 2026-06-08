// 示例 57: p0f 被动 OS 指纹识别
//
// 本示例演示如何使用 goscapy 的 p0f 包进行被动操作系统指纹识别。
// 通过分析 TCP/IP 头部特征（TTL、窗口大小、MSS、窗口缩放等），
// 无需主动探测即可识别远端操作系统。
//
// 功能:
//   - 使用内置签名数据库进行指纹匹配
//   - 从 p0f.fp 格式文件加载自定义签名库
//   - 捕获实时流量并实时识别 OS
//   - 构造测试包验证指纹识别
//
// 运行方式:
//   构造测试包:  go run main.go
//   实时嗅探:    sudo go run main.go -sniff [-iface en0]
//   加载签名库:  go run main.go -db /path/to/p0f.fp
//
// ⚠️  实时嗅探需要 root 权限 (sudo) 或 CAP_NET_RAW。

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/p0f"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sniff"
)

func main() {
	sniffMode := flag.Bool("sniff", false, "启用实时嗅探模式（需要 root）")
	iface := flag.String("iface", "", "嗅探使用的网络接口")
	dbPath := flag.String("db", "", "p0f 签名数据库文件路径（默认使用内置库）")
	flag.Parse()

	db := loadDB(*dbPath)

	if *sniffMode {
		runSniff(db, *iface)
	} else {
		runDemo(db)
	}
}

func loadDB(path string) *p0f.Database {
	if path != "" {
		db, err := p0f.LoadDatabase(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "加载数据库失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("已从文件加载签名库: %s (SYN=%d, SYN+ACK=%d)\n",
			path, len(db.Syn), len(db.SynAck))
		return db
	}
	db := p0f.DefaultDatabase()
	fmt.Printf("使用内置签名库 (SYN=%d, SYN+ACK=%d)\n",
		len(db.Syn), len(db.SynAck))
	return db
}

// runDemo 使用构造的测试包演示指纹识别。
func runDemo(db *p0f.Database) {
	fmt.Println("\n=== p0f 被动 OS 指纹识别演示 ===")

	testCases := []struct {
		name   string
		pkt    *packet.Packet
		expect string
	}{
		{
			name:   "Linux 4.x-6.x",
			pkt:    linuxSynPkt(29200, 64, 1460, 7),
			expect: "Linux",
		},
		{
			name:   "Windows 7",
			pkt:    linuxSynPkt(8192, 128, 1460, 8),
			expect: "Windows",
		},
		{
			name:   "macOS / iOS",
			pkt:    macSynPkt(65535, 64, 1460, 5),
			expect: "macOS",
		},
		{
			name:   "FreeBSD",
			pkt:    linuxSynPkt(65535, 64, 1460, 6),
			expect: "FreeBSD",
		},
	}

	for _, tc := range testCases {
		result := p0f.P0fFingerprint(tc.pkt, db)
		status := "OK"
		if result.OS == "" {
			status = "MISS"
		}
		fmt.Printf("[%s] %s\n", status, tc.name)
		fmt.Printf("  OS:         %s\n", result.OS)
		fmt.Printf("  Confidence: %s\n", result.Confidence)
		fmt.Printf("  Matched:    %v\n", result.Matched)
		fmt.Printf("  Details:    %s\n", result.Details)
		fmt.Println()
	}
}

// runSniff 捕获实时流量并识别 OS。
func runSniff(db *p0f.Database, iface string) {
	if iface == "" {
		iface = defaultIface()
	}
	fmt.Printf("\n=== 在接口 %s 上嗅探 SYN/SYN+ACK 包 ===\n\n", iface)
	fmt.Println("按 Ctrl+C 停止")

	cfg := sniff.SniffConfig{
		Iface:   iface,
		Filter:  "tcp[tcpflags] & (tcp-syn) != 0",
		Timeout: 60 * time.Second,
	}

	handler := func(pkt *packet.Packet) bool {
		result := p0f.P0fFingerprint(pkt, db)
		if result.OS != "" {
			fmt.Printf("[%-12s] %s  (confidence: %s, %v)\n",
				result.OS, result.Details, result.Confidence, result.Matched)
		}
		return true
	}

	if err := sniff.Sniff(cfg, handler); err != nil {
		fmt.Fprintf(os.Stderr, "嗅探错误: %v\n", err)
		os.Exit(1)
	}
}

func linuxSynPkt(window uint16, ttl uint8, mss uint16, wscale uint8) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("ttl", ttl)
	_ = ip.Set("proto", uint8(6))
	_ = ip.Set("src", "10.0.0.1")
	_ = ip.Set("dst", "10.0.0.2")
	frag, _ := ip.Get("frag")
	_ = ip.Set("frag", frag.(uint16)|0x4000)

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(layers.TCPSyn))
	_ = tcp.Set("window", window)

	var opts []layers.TCPOption
	opts = append(opts, layers.TCPOptMSSVal(mss))
	opts = append(opts, layers.TCPOptSACKPermVal())
	opts = append(opts, layers.TCPOptWScaleVal(wscale))
	opts = append(opts, layers.TCPOptNOPVal())
	_ = tcp.Set("options", opts)

	return packet.NewFrom(ip, tcp)
}

func macSynPkt(window uint16, ttl uint8, mss uint16, wscale uint8) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("ttl", ttl)
	_ = ip.Set("proto", uint8(6))
	_ = ip.Set("src", "10.0.0.1")
	_ = ip.Set("dst", "10.0.0.2")
	frag, _ := ip.Get("frag")
	_ = ip.Set("frag", frag.(uint16)|0x4000)

	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(12345))
	_ = tcp.Set("dport", uint16(80))
	_ = tcp.Set("flags", uint8(layers.TCPSyn))
	_ = tcp.Set("window", window)

	// macOS-style options: MSS + SACK + NOP + WScale + Timestamp = 20 bytes
	var opts []layers.TCPOption
	opts = append(opts, layers.TCPOptMSSVal(mss))
	opts = append(opts, layers.TCPOptSACKPermVal())
	opts = append(opts, layers.TCPOptNOPVal())
	opts = append(opts, layers.TCPOptWScaleVal(wscale))
	opts = append(opts, layers.TCPOptTimestampVal(0, 0))
	_ = tcp.Set("options", opts)

	return packet.NewFrom(ip, tcp)
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
			return i.Name
		}
	}
	return "eth0"
}
