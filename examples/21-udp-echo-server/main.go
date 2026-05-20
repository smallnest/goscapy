// 示例 21: UDP Echo Server
//
// 本示例演示如何使用 Go 标准库实现 UDP Echo 服务器。
// 收到数据报后原样返回给发送方，适合调试 UDP 通信。
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
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	port := flag.Int("port", 7778, "监听端口")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		log.Fatalf("监听 UDP %s 失败: %v", addr, err)
	}
	defer conn.Close()

	fmt.Printf("UDP Echo Server 启动在端口 %d\n", *port)
	fmt.Println("按 Ctrl+C 停止")

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\n正在关闭...")
		conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}
			log.Printf("读取错误: %v", err)
			continue
		}

		fmt.Printf("[%s] 收到 %d bytes 来自 %s\n", time.Now().Format("15:04:05"), n, remoteAddr)

		_, err = conn.WriteToUDP(buf[:n], remoteAddr)
		if err != nil {
			log.Printf("回显失败: %v", err)
		}
	}
}