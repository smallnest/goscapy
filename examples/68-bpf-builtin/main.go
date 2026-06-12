// 示例 68: 内置 BPF 汇编器 — 纯 Go 编译过滤表达式（无需 tcpdump）
//
// 本示例演示 pkg/bpf 内置的纯 Go 经典 BPF 汇编器与解释器:
//   - bpf.Compile(expr)   — 把过滤表达式编译成 BPF 指令（无外部依赖）
//   - bpf.Match(prog, raw) — 在 Go 内对原始字节执行过滤
//   - bpf.MatchFunc(expr)  — 返回一个对原始字节的谓词
//
// sniff.CompileFilter 现在优先用内置汇编器，仅在表达式超出支持范围时才回退
// 到 tcpdump。支持的语法: ip/ip6/arp/rarp、tcp/udp/icmp、host、port、
// src/dst 限定、and/or/not 及括号分组。
//
// 运行方式: go run main.go

package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/bpf"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func ethIPTCP(dport uint16) []byte {
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", "10.0.0.1")
	_ = ip.Set("dst", "10.0.0.2")
	_ = ip.Set("proto", layers.IPProtoTCP)
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", uint16(40000))
	_ = tcp.Set("dport", dport)
	raw, _ := packet.NewFrom(eth, ip, tcp).Build()
	return raw
}

func main() {
	fmt.Println("=== goscapy 示例 68: 内置 BPF 汇编器 ===")
	fmt.Println()

	web := ethIPTCP(80)
	ssh := ethIPTCP(22)

	// 1) 编译一个过滤表达式，查看生成的指令数。
	filter := "tcp and (port 80 or port 443)"
	prog, err := bpf.Compile(filter)
	if err != nil {
		panic(err)
	}
	fmt.Printf("过滤表达式: %q\n", filter)
	fmt.Printf("编译为 %d 条 BPF 指令\n\n", len(prog))

	// 2) 用解释器执行。
	fmt.Printf("匹配 :80 包 → %v\n", bpf.Match(prog, web))
	fmt.Printf("匹配 :22 包 → %v\n", bpf.Match(prog, ssh))
	fmt.Println()

	// 3) MatchFunc 谓词。
	pred, _ := bpf.MatchFunc("tcp port 22")
	fmt.Printf("tcp port 22 谓词: web=%v ssh=%v\n", pred(web), pred(ssh))
	fmt.Println()

	// 4) 各种表达式演示。
	for _, expr := range []string{"ip", "tcp", "host 10.0.0.2", "dst port 80", "not port 80"} {
		p, err := bpf.Compile(expr)
		if err != nil {
			fmt.Printf("  %-18s 编译失败: %v\n", expr, err)
			continue
		}
		fmt.Printf("  %-18s web=%-5v ssh=%-5v\n", expr, bpf.Match(p, web), bpf.Match(p, ssh))
	}
}
