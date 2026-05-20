// 示例 19: TCP Echo Server
//
// 本示例演示如何使用 Go 标准库实现 TCP Echo 服务器。
// 收到客户端数据后原样返回，支持多客户端并发连接。
//
// 运行方式: go run main.go [-port PORT]
// 示例:     go run main.go
//           go run main.go -port 8888
//
// 无需 root 权限。

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	port := flag.Int("port", 7777, "监听端口")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", addr, err)
	}
	defer ln.Close()

	fmt.Printf("TCP Echo Server 启动在端口 %d\n", *port)
	fmt.Println("按 Ctrl+C 停止")

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\n正在关闭...")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}
			log.Printf("接受连接失败: %v", err)
			continue
		}

		fmt.Printf("[%s] 客户端连接: %s\n", time.Now().Format("15:04:05"), conn.RemoteAddr())
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer func() {
		fmt.Printf("[%s] 客户端断开: %s\n", time.Now().Format("15:04:05"), conn.RemoteAddr())
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("读取错误: %v", err)
			}
			return
		}
		fmt.Printf("[%s] 收到 %d bytes: %s\n", time.Now().Format("15:04:05"), n, string(buf[:n]))
		_, err = conn.Write(buf[:n])
		if err != nil {
			log.Printf("写入错误: %v", err)
			return
		}
	}
}