// 示例 50: 增强版 Arping 网络发现
//
// 运行: sudo go run main.go [选项] <目标>
// 示例: sudo go run main.go 192.168.1.0/24
//       sudo go run main.go -c 20 10.0.0.1
//
// 需要 root 权限。
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/arping"
)

func main() {
	timeout := flag.Duration("w", 1500*time.Millisecond, "超时")
	concurrency := flag.Int("c", 50, "并发数")
	iface := flag.String("I", "", "网络接口")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go [选项] <目标>\n")
		fmt.Fprintf(os.Stderr, "目标可以是单 IP 或 CIDR\n")
		fmt.Fprintf(os.Stderr, "示例: sudo go run main.go 192.168.1.0/24\n")
		os.Exit(1)
	}

	target := flag.Arg(0)

	opts := arping.DefaultOptions()
	opts.Timeout = *timeout
	opts.Concurrency = *concurrency
	opts.Interface = *iface

	result, err := arping.Arping(target, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arping 失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(result.String())
}
