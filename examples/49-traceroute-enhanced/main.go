// 示例 49: 增强版 Traceroute（AS 解析 + 可视化）
//
// 运行: sudo go run main.go [选项] <目标>
// 示例: sudo go run main.go 8.8.8.8
//       sudo go run main.go -proto tcp google.com
//
// 需要 root 权限。
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/traceroute"
)

func main() {
	maxTTL := flag.Int("m", 30, "最大跳数")
	timeout := flag.Duration("w", 2*time.Second, "超时")
	probes := flag.Int("q", 3, "每跳探测数")
	port := flag.Uint("p", 80, "目标端口 (TCP/UDP)")
	proto := flag.String("proto", "icmp", "协议: icmp, tcp, udp")
	noAS := flag.Bool("no-as", false, "禁用 AS 解析")
	graphviz := flag.Bool("graph", false, "输出 Graphviz DOT 格式")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go [选项] <目标>\n")
		os.Exit(1)
	}

	dst := flag.Arg(0)
	opts := traceroute.DefaultOptions()
	opts.MaxTTL = *maxTTL
	opts.Timeout = *timeout
	opts.Probes = *probes
	opts.Port = uint16(*port)
	opts.ResolveAS = !*noAS

	switch *proto {
	case "tcp":
		opts.Protocol = traceroute.ProtoTCP
	case "udp":
		opts.Protocol = traceroute.ProtoUDP
	default:
		opts.Protocol = traceroute.ProtoICMP
	}

	result, err := traceroute.Traceroute(dst, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "traceroute 失败: %v\n", err)
		os.Exit(1)
	}

	if *graphviz {
		fmt.Println(result.Graph())
	} else {
		fmt.Println(result.String())
	}
}
