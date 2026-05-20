// 示例 15: BPF 过滤器示例
//
// 本示例演示如何使用 BPF (Berkeley Packet Filter) 过滤器。
// 你将学到:
//   - BPF 过滤表达式语法
//   - 如何编译 BPF 过滤器
//   - 常用的过滤模式
//   - 过滤器与嗅探的配合使用
//
// 运行方式: go run main.go
// 注意: 编译 BPF 过滤器需要系统上安装 tcpdump。
//       macOS 上可能需要 root 权限才能编译过滤器。

package main

import (
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/sendrecv"
	"github.com/smallnest/goscapy/pkg/sniff"
)

func main() {
	fmt.Println("=== goscapy 示例 15: BPF 过滤器 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// BPF 过滤器简介
	// -----------------------------------------------------------------------
	// BPF (Berkeley Packet Filter) 是内核级别的包过滤机制。
	// goscapy 使用 tcpdump 的过滤语法，通过 CompileFilter() 编译为
	// 原始的 BPF 指令，然后传给接收器在内核层面过滤。
	//
	// 优点:
	//   - 内核层面过滤，性能极高
	//   - 不需要的包不会从内核拷贝到用户空间
	//   - 类 tcpdump 语法，易于使用

	// -----------------------------------------------------------------------
	// 第一部分: 编译基本过滤器
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: 编译基本过滤器 ---")
	fmt.Println()

	filters := []string{
		"tcp",
		"udp",
		"icmp",
		"tcp port 80",
		"host 8.8.8.8",
		"src net 192.168.0.0/16",
	}

	for _, f := range filters {
		insns, err := sniff.CompileFilter(f)
		if err != nil {
			fmt.Printf("  过滤器 %q: 编译失败 (%v)\n", f, err)
			continue
		}
		fmt.Printf("  过滤器 %q: %d 条 BPF 指令\n", f, len(insns))
		for i, ins := range insns {
			fmt.Printf("    [%d] code=0x%04x jt=%d jf=%d k=0x%08x\n",
				i, ins.Code, ins.Jt, ins.Jf, ins.K)
		}
		fmt.Println()
	}

	// -----------------------------------------------------------------------
	// 第二部分: 使用预编译的 BPF 指令
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: 预编译 BPF 指令 ---")
	fmt.Println()
	fmt.Println("你可以预先编译过滤器，然后传给 SniffConfig.Instructions:")
	fmt.Println()

	// 编译 "tcp port 80" 过滤器
	instructions, err := sniff.CompileFilter("tcp port 80")
	if err != nil {
		log.Fatalf("编译过滤器失败: %v", err)
	}

	// 使用预编译的指令创建 SniffConfig
	_ = sniff.SniffConfig{
		Iface:        sendrecv.LoopbackName(),
		Instructions: instructions,  // 预编译的 BPF 指令
		Count:        10,
	}
	fmt.Println("  预编译 'tcp port 80' 成功，可传给 SniffConfig.Instructions")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第三部分: 使用 BPFInstruction 直接构造
	// -----------------------------------------------------------------------
	fmt.Println("--- 第三部分: 手动构造 BPF 指令 ---")
	fmt.Println()
	fmt.Println("你也可以直接构造 BPFInstruction，不需要 tcpdump:")
	fmt.Println()

	// 示例: 一个简单的 "accept all" 过滤器
	// BPF 指令: ret #65535 (接受所有包，最大抓取 65535 字节)
	manualInstructions := []sendrecv.BPFInstruction{
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x0000FFFF}, // RET #65535
	}
	fmt.Printf("  手动构造的 'accept all' 过滤器: %d 条指令\n", len(manualInstructions))
	fmt.Println()

	// 也可以用于 OpenFilteredReceiver
	_, _ = sendrecv.OpenFilteredReceiver(sendrecv.LoopbackName(), manualInstructions)
	fmt.Println("  可传给 sendrecv.OpenFilteredReceiver 或 SniffConfig.Instructions")
	fmt.Println()

	// -----------------------------------------------------------------------
	// BPF 过滤语法参考
	// -----------------------------------------------------------------------
	fmt.Println("--- BPF 过滤语法参考 ---")
	fmt.Println()
	fmt.Println("协议限定:")
	fmt.Println("  tcp, udp, icmp, icmp6, ip, ip6, arp, rarp")
	fmt.Println()
	fmt.Println("地址过滤:")
	fmt.Println("  host 8.8.8.8              - 指定主机")
	fmt.Println("  src host 192.168.1.1      - 源主机")
	fmt.Println("  dst host 10.0.0.1         - 目标主机")
	fmt.Println("  net 192.168.0.0/16        - 网段")
	fmt.Println()
	fmt.Println("端口过滤:")
	fmt.Println("  port 80                   - 源或目标端口")
	fmt.Println("  src port 53               - 源端口")
	fmt.Println("  dst port 443              - 目标端口")
	fmt.Println("  portrange 80-90           - 端口范围")
	fmt.Println()
	fmt.Println("组合条件:")
	fmt.Println("  and / &&    - 与")
	fmt.Println("  or  / ||    - 或")
	fmt.Println("  not / !     - 非")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  \"tcp port 80 and host 10.0.0.1\"")
	fmt.Println("  \"not port 22 and not port 53\"")
	fmt.Println("  \"tcp[tcpflags] & tcp-syn != 0\"    - SYN 包")
	fmt.Println("  \"greater 1000\"                      - 大于 1000 字节")
	fmt.Println()
	fmt.Println("下一步: 运行 16-shortcuts 示例，学习所有 Shortcut 函数")
}
