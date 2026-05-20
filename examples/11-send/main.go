// 示例 11: 发送数据包示例（Send/Sendp）
//
// ⚠️  需要 root 权限: sudo go run main.go
//
// 本示例演示如何使用 goscapy 发送构建好的数据包到网络。
// 你将学到:
//   - Send() 和 Sendp() 的区别（L3 vs L2 发送）
//   - L2 发送包含完整的 Ethernet 帧
//   - L3 发送由操作系统处理 Ethernet 头
//   - 如何选择网络接口
//   - 错误处理最佳实践
//
// 运行方式: sudo go run main.go [接口名]
// 示例:     sudo go run main.go en0       (macOS)
//           sudo go run main.go eth0      (Linux)
//
// 注意: 发送原始数据包需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	fmt.Println("=== goscapy 示例 11: 发送数据包 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 选择网络接口
	// -----------------------------------------------------------------------
	// 网络接口是发送数据包的出口，例如:
	//   macOS: en0 (Wi-Fi), en1 (以太网), lo0 (回环)
	//   Linux: eth0, wlan0, lo
	iface := sendrecv.LoopbackName() // 因为本示例默认目的地是 127.0.0.1 (回环地址)
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	fmt.Printf("使用网络接口: %s\n", iface)
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第一部分: L3 发送 (Send) - IP 层发送
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: L3 发送 (Send) ---")
	fmt.Println()
	fmt.Println("Send() 在 IP 层发送数据包。操作系统会自动添加 Ethernet 帧。")
	fmt.Println("如果包中包含 Ethernet 层，会被自动跳过。")
	fmt.Println()

	// 构建一个 ICMP Echo Request 包
	// 注意: 即使包含 Ethernet 层，Send() 也会跳过它
	l3Pkt := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").
			DstIP("127.0.0.1").              // 发送到回环地址
			TTL(64).
			Proto(layers.IPProtoICMP)).
		Over(goscapy.NewICMP().
			Type(layers.ICMPEchoRequest).
			Code(0).
			ID(0x1234).
			Seq(1))

	pkt := l3Pkt.Packet()

	fmt.Println("发送 ICMP Echo Request (L3)...")
	err := sendrecv.Send(pkt, iface)
	if err != nil {
		fmt.Printf("  L3 发送失败 (需要 root 权限): %v\n", err)
		fmt.Println("  请使用: sudo go run main.go")
	} else {
		fmt.Println("  发送成功!")
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第二部分: L2 发送 (Sendp) - Ethernet 层发送
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: L2 发送 (Sendp) ---")
	fmt.Println()
	fmt.Println("Sendp() 在 Ethernet 层发送完整的帧。")
	fmt.Println("包中必须包含 Ethernet 层，整个帧会被原样写入网络。")
	fmt.Println()

	// 构建一个 Ethernet + IP + TCP SYN 包
	l2Pkt := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").
		SrcMAC("00:11:22:33:44:55").
		Over(goscapy.NewIP().
			SrcIP("192.168.1.100").
			DstIP("127.0.0.1").
			TTL(64).
			Proto(layers.IPProtoTCP)).
		Over(goscapy.NewTCP().
			SrcPort(12345).
			DstPort(80).
			Flags(layers.TCPSyn))

	pkt2 := l2Pkt.Packet()

	fmt.Println("发送 Ethernet + IP + TCP SYN (L2)...")
	err = sendrecv.Sendp(pkt2, iface)
	if err != nil {
		fmt.Printf("  L2 发送失败 (需要 root 权限): %v\n", err)
		fmt.Println("  请使用: sudo go run main.go")
	} else {
		fmt.Println("  发送成功!")
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// L2 vs L3 对比
	// -----------------------------------------------------------------------
	fmt.Println("--- Send vs Sendp 对比 ---")
	fmt.Println()
	fmt.Println("  Send()  (L3):                       Sendp() (L2):")
	fmt.Println("  ┌───────────────────┐               ┌───────────────────┐")
	fmt.Println("  │ IP + TCP + Data   │               │ Ethernet + IP +   │")
	fmt.Println("  └───────────────────┘               │ TCP + Data        │")
	fmt.Println("  OS 自动添加 Ethernet 头              └───────────────────┘")
	fmt.Println("  不需要知道目标 MAC                    完全控制 Ethernet 帧")
	fmt.Println()
	fmt.Println("  适用场景:                            适用场景:")
	fmt.Println("  - 快速发送 IP 包                     - 需要 MAC 层控制")
	fmt.Println("  - 不关心 Ethernet 头                 - ARP 包")
	fmt.Println("  - Ping、端口扫描                     - 自定义 Ethernet 帧")
	fmt.Println()
	fmt.Println("下一步: 运行 12-sendrecv 示例，学习发送并接收响应")
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "en0"
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
	return "en0"
}
