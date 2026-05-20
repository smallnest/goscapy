// 示例 22: UDP Echo Client
//
// 本示例演示如何向 UDP Echo Server 发送数据报并接收回显。
// 支持交互模式和单次模式。
//
// 运行方式: go run main.go [选项] [服务器地址]
// 示例:     go run main.go 127.0.0.1:7778
//           go run main.go -msg "hello" 127.0.0.1:7778
//
// 无需 root 权限。

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	msg := flag.String("msg", "", "单次发送消息（非交互模式）")
	flag.Parse()

	addr := "127.0.0.1:7778"
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
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("解析地址 %s 失败: %v", addr, err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatalf("连接 %s 失败: %v", addr, err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	start := time.Now()
	_, err = conn.Write([]byte(msg))
	if err != nil {
		log.Fatalf("发送失败: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("超时: 未收到回显")
			return
		}
		log.Fatalf("接收失败: %v", err)
	}
	rtt := time.Since(start)

	fmt.Printf("发送: %s\n", msg)
	fmt.Printf("回显: %s\n", string(buf[:n]))
	fmt.Printf("RTT: %.2f ms\n", rtt.Seconds()*1000)
}

func interactive(addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("解析地址 %s 失败: %v", addr, err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatalf("连接 %s 失败: %v", addr, err)
	}
	defer conn.Close()

	fmt.Printf("已连接到 %s (交互模式, 输入 quit 退出)\n", addr)

	go func() {
		buf := make([]byte, 65535)
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			fmt.Printf("← %s\n", string(buf[:n]))
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "quit" {
			return
		}
		_, err := conn.Write([]byte(text))
		if err != nil {
			fmt.Printf("发送失败: %v\n", err)
		}
	}
}