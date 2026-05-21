// 示例 37: TCP Options 解析与构造
//
// 本示例演示如何使用 goscapy 的 TCP Options API 构造带选项的 TCP SYN 包，
// 以及如何解析接收到的 TCP 包中的选项字段。
//
// 功能:
//   - 构造带 MSS/Window Scale/SACK Permitted/Timestamps 选项的 SYN 包
//   - 解析 TCP SYN-ACK 中返回的选项
//
// 运行方式: sudo go run main.go [-dst <目标IP>] [-port <端口>] [-I <接口>]
// 示例:     sudo go run main.go -dst 93.184.216.34 -port 80
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW。

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	dst := flag.String("dst", "93.184.216.34", "目标 IP 地址")
	port := flag.Int("port", 80, "目标端口")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	timeout := flag.Duration("t", 3*time.Second, "超时时间")
	flag.Parse()

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	srcIP := getLocalIP(ifaceVal)
	if srcIP == nil {
		fmt.Fprintf(os.Stderr, "无法获取接口 %s 的本地 IP\n", ifaceVal)
		os.Exit(1)
	}

	fmt.Printf("TCP Options 示例: %s:%d -> %s:%d, iface=%s\n\n", srcIP, 54321, *dst, *port, ifaceVal)

	// 构造 TCP 选项
	opts := []layers.TCPOption{
		layers.TCPOptMSSVal(1460),             // MSS = 1460
		layers.TCPOptNOPVal(),                 // NOP (padding)
		layers.TCPOptWScaleVal(7),             // Window Scale = 7 (multiply by 128)
		layers.TCPOptNOPVal(),                 // NOP
		layers.TCPOptNOPVal(),                 // NOP
		layers.TCPOptTimestampVal(12345, 0),   // Timestamps: TSval=12345, TSecr=0
		layers.TCPOptSACKPermVal(),            // SACK Permitted
	}

	fmt.Println("构造的 TCP 选项:")
	for _, opt := range opts {
		printOption(opt)
	}
	fmt.Println()

	// 序列化选项查看字节
	serialized := layers.SerializeTCPOptions(opts)
	fmt.Printf("序列化后: %d 字节 (已 4 字节对齐): %x\n\n", len(serialized), serialized)

	// 构造 SYN 包
	ip := layers.NewIP()
	ip.Set("src", srcIP.String())
	ip.Set("dst", *dst)
	ip.Set("proto", layers.IPProtoTCP)

	tcp := layers.NewTCPWith(54321, uint16(*port), layers.TCPSyn)
	tcp.Set("seq", uint32(1000))
	tcp.Set("win", uint16(65535))
	tcp.Set("options", opts)

	pkt := packet.NewFrom(ip, tcp)

	fmt.Println("发送 SYN (带选项)...")
	_, reply, err := sendrecv.SendRecv1(pkt, ifaceVal, *timeout)
	if err != nil {
		if errors.Is(err, sendrecv.ErrTimeout) {
			fmt.Fprintln(os.Stderr, "超时: 未收到 SYN-ACK 回复")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("收到回复!")
	fmt.Println()

	// 解析回复中的 TCP 选项
	tcpLayer := reply.GetLayer("TCP")
	if tcpLayer == nil {
		fmt.Fprintln(os.Stderr, "回复中未找到 TCP 层")
		os.Exit(1)
	}

	flagsVal, _ := tcpLayer.Get("flags")
	if flags, ok := flagsVal.(uint8); ok {
		fmt.Printf("TCP Flags: 0x%02x", flags)
		if flags&layers.TCPSyn != 0 {
			fmt.Print(" SYN")
		}
		if flags&layers.TCPAck != 0 {
			fmt.Print(" ACK")
		}
		if flags&layers.TCPRst != 0 {
			fmt.Print(" RST")
		}
		fmt.Println()
	}

	optsVal, _ := tcpLayer.Get("options")
	if replyOpts, ok := optsVal.([]layers.TCPOption); ok && len(replyOpts) > 0 {
		fmt.Printf("\n回复中的 TCP 选项 (%d 个):\n", len(replyOpts))
		for _, opt := range replyOpts {
			printOption(opt)
		}
	} else {
		fmt.Println("回复中无 TCP 选项")
	}

	// 演示纯解析（不需要网络）
	fmt.Println("\n--- 纯解析演示 ---")
	rawOpts := []byte{
		0x02, 0x04, 0x05, 0xb4, // MSS 1460
		0x01,                   // NOP
		0x03, 0x03, 0x07,      // WScale 7
		0x04, 0x02,            // SACK Permitted
	}
	parsed := layers.ParseTCPOptions(rawOpts)
	fmt.Printf("解析 %d 字节原始选项:\n", len(rawOpts))
	for _, opt := range parsed {
		printOption(opt)
	}
}

func printOption(opt layers.TCPOption) {
	switch opt.Kind {
	case layers.TCPOptEOL:
		fmt.Println("  EOL (End of Options)")
	case layers.TCPOptNOP:
		fmt.Println("  NOP (No-Operation)")
	case layers.TCPOptMSS:
		if len(opt.Data) >= 2 {
			mss := uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
			fmt.Printf("  MSS: %d\n", mss)
		}
	case layers.TCPOptWScale:
		if len(opt.Data) >= 1 {
			fmt.Printf("  Window Scale: %d (multiply by %d)\n", opt.Data[0], 1<<opt.Data[0])
		}
	case layers.TCPOptSACKPerm:
		fmt.Println("  SACK Permitted")
	case layers.TCPOptTimestamp:
		if len(opt.Data) >= 8 {
			tsVal := uint32(opt.Data[0])<<24 | uint32(opt.Data[1])<<16 | uint32(opt.Data[2])<<8 | uint32(opt.Data[3])
			tsEcr := uint32(opt.Data[4])<<24 | uint32(opt.Data[5])<<16 | uint32(opt.Data[6])<<8 | uint32(opt.Data[7])
			fmt.Printf("  Timestamps: TSval=%d, TSecr=%d\n", tsVal, tsEcr)
		}
	default:
		fmt.Printf("  Option Kind=%d, Len=%d, Data=%x\n", opt.Kind, opt.Length, opt.Data)
	}
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			return iface.Name
		}
	}
	return "eth0"
}

func getLocalIP(ifaceName string) net.IP {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4
			}
		}
	}
	return nil
}
