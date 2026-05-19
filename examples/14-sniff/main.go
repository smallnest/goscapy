// 示例 14: 包嗅探（Sniff）示例
//
// ⚠️  需要 root 权限: sudo go run main.go
//
// 本示例演示如何使用 goscapy 捕获网络上的实时流量。
// 你将学到:
//   - Sniff() 回调方式的包捕获
//   - SniffChan() 通道方式的包捕获
//   - BPF 过滤器的使用
//   - 如何控制捕获数量和超时
//
// 运行方式: sudo go run main.go [接口名]
// 示例:     sudo go run main.go en0       (macOS)
//           sudo go run main.go eth0      (Linux)
//
// 注意: 包嗅探需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sniff"
)

func main() {
	fmt.Println("=== goscapy 示例 14: 包嗅探 ===")
	fmt.Println()

	iface := "en0"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	fmt.Printf("使用网络接口: %s\n", iface)
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第一部分: 回调方式 (Sniff) - 捕获 10 个包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: 回调方式捕获 10 个包 ---")
	fmt.Println()

	// SniffConfig 配置嗅探参数
	cfg := sniff.SniffConfig{
		Iface:   iface,                 // 网络接口
		Count:   10,                    // 最多捕获 10 个包
		Timeout: 10 * time.Second,      // 总超时 10 秒
	}

	count := 0
	handler := func(pkt *packet.Packet) bool {
		count++
		fmt.Printf("  包 %d: ", count)

		// 打印每个协议层
		for i, layer := range pkt.Layers() {
			if i > 0 {
				fmt.Print(" → ")
			}
			fmt.Print(layer.Proto())
		}
		fmt.Println()

		// 返回 true 继续捕获，false 停止
		return true
	}

	fmt.Println("开始嗅探 (最多 10 个包, 超时 10s)...")
	err := sniff.Sniff(cfg, handler)
	if err != nil {
		fmt.Printf("  嗅探失败 (需要 root 权限): %v\n", err)
		fmt.Println("  请使用: sudo go run main.go")
	} else {
		fmt.Printf("  嗅探完成, 共捕获 %d 个包\n", count)
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第二部分: 通道方式 (SniffChan) - 带超时控制
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: 通道方式捕获 ---")
	fmt.Println()

	chanCfg := sniff.SniffConfig{
		Iface:   iface,
		Count:   5,                     // 最多 5 个包
		Timeout: 5 * time.Second,       // 超时 5 秒
	}

	fmt.Println("开始通道嗅探...")
	ch, stop := sniff.SniffChan(chanCfg)

	chanCount := 0
	timeout := time.After(6 * time.Second)

	loop:
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				break loop // 通道关闭
			}
			chanCount++
			fmt.Printf("  收到包 %d: ", chanCount)
			for i, layer := range pkt.Layers() {
				if i > 0 {
					fmt.Print(" → ")
				}
				fmt.Print(layer.Proto())
			}
			fmt.Println()
		case <-timeout:
			fmt.Println("  超时!")
			stop() // 手动停止
			break loop
		}
	}

	fmt.Printf("  通道方式捕获完成, 共 %d 个包\n", chanCount)
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: 带 BPF 过滤的嗅探
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: BPF 过滤嗅探 ---")
	fmt.Println()
	fmt.Println("BPF (Berkeley Packet Filter) 可以在内核层面过滤数据包，")
	fmt.Println("只捕获你感兴趣的流量，大幅提高效率。")
	fmt.Println()

	// 只捕获 TCP 包
	filterCfg := sniff.SniffConfig{
		Iface:   iface,
		Filter:  "tcp",                 // BPF 过滤: 只捕获 TCP
		Count:   3,                     // 最多 3 个 TCP 包
		Timeout: 10 * time.Second,
	}

	filterCount := 0
	filterHandler := func(pkt *packet.Packet) bool {
		filterCount++
		fmt.Printf("  TCP 包 %d: ", filterCount)
		for i, layer := range pkt.Layers() {
			if i > 0 {
				fmt.Print(" → ")
			}
			fmt.Print(layer.Proto())
		}
		fmt.Println()
		return true
	}

	fmt.Println("开始过滤嗅探 (只捕获 TCP, 最多 3 个, 超时 10s)...")
	err = sniff.Sniff(filterCfg, filterHandler)
	if err != nil {
		fmt.Printf("  过滤嗅探失败: %v\n", err)
	} else {
		fmt.Printf("  过滤嗅探完成, 共 %d 个 TCP 包\n", filterCount)
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// 常用 BPF 过滤表达式
	// -----------------------------------------------------------------------
	fmt.Println("--- 常用 BPF 过滤表达式 ---")
	fmt.Println()
	fmt.Println("  \"tcp\"               - 所有 TCP 流量")
	fmt.Println("  \"udp\"               - 所有 UDP 流量")
	fmt.Println("  \"icmp\"              - 所有 ICMP 流量")
	fmt.Println("  \"tcp port 80\"       - HTTP 流量")
	fmt.Println("  \"tcp port 443\"      - HTTPS 流量")
	fmt.Println("  \"host 8.8.8.8\"      - 与 8.8.8.8 的通信")
	fmt.Println("  \"src host 10.0.0.1\" - 来自 10.0.0.1 的包")
	fmt.Println("  \"dst port 53\"       - 目标端口 53 (DNS)")
	fmt.Println("  \"tcp and port 80\"   - 组合条件")
	fmt.Println("  \"not port 22\"       - 排除 SSH")
	fmt.Println()
	fmt.Println("下一步: 运行 15-bpf-filter 示例，学习 BPF 过滤器编译")
}
