// 示例 20: TCP Echo Client
//
// 本示例演示如何连接到 TCP Echo Server，发送消息并接收回显。
// 支持交互模式（持续 stdin）和单次模式（-msg 参数）。
//
// 运行方式: go run main.go [选项] [服务器地址]
// 示例:     go run main.go 127.0.0.1:7777
//           go run main.go -msg "hello" 127.0.0.1:7777
//
// 无需 root 权限。

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	msg := flag.String("msg", "", "单次发送消息（非交互模式）")
	flag.Parse()

	addr := "127.0.0.1:7777"
	if flag.NArg() > 0 {
		addr = flag.Arg(0)
	}

	if *msg != "" {
		sendOnce(addr, *msg)
	} else {
		interactive(addr)
	}
}

func sendOnce(addr, msg string) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Fatalf("连接 %s 失败: %v", addr, err)
	}
	defer conn.Close()

	start := time.Now()
	fmt.Fprintf(conn, "%s\n", msg)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatalf("读取失败: %v", err)
	}
	rtt := time.Since(start)

	fmt.Printf("发送: %s\n", msg)
	fmt.Printf("回显: %s\n", string(buf[:n]))
	fmt.Printf("RTT: %.2f ms\n", rtt.Seconds()*1000)
}

func interactive(addr string) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Fatalf("连接 %s 失败: %v", addr, err)
	}
	defer conn.Close()

	fmt.Printf("已连接到 %s (交互模式, 输入 quit 退出)\n", addr)

	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					fmt.Printf("\n连接断开: %v\n", err)
				}
				os.Exit(0)
			}
			fmt.Printf("← %s", string(buf[:n]))
		}
	}()

	for scanner.Scan() {
		text := scanner.Text()
		if text == "quit" {
			return
		}
		fmt.Fprintf(conn, "%s\n", text)
	}
}