// 示例 40: RecvInto — 零分配高性能收包
//
// 本示例演示如何使用 RawConn.RecvInto 将包读入预分配的缓冲区，
// 避免每次 Recv 都分配新的 []byte，适合高性能包处理场景。
//
// 功能:
//   - 使用 DialRaw 创建 ICMP raw socket
//   - 使用 RecvInto 复用缓冲区接收包
//   - 与 Recv (每次分配) 对比使用方式
//
// 运行方式: sudo go run main.go [-proto <协议号>] [-t <超时秒>] [-n <接收包数>]
// 示例:     sudo go run main.go -proto 1 -t 10 -n 50
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW。

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	proto := flag.Int("proto", 1, "IP 协议号 (1=ICMP, 6=TCP, 17=UDP)")
	timeout := flag.Int("t", 10, "总运行时间 (秒)")
	maxPkts := flag.Int("n", 20, "最大接收包数 (0=无限)")
	bufSize := flag.Int("buf", 65536, "接收缓冲区大小")
	flag.Parse()

	fmt.Printf("RecvInto 示例: proto=%d, timeout=%ds, maxPkts=%d, bufSize=%d\n\n",
		*proto, *timeout, *maxPkts, *bufSize)

	// 创建 raw socket
	conn, err := sendrecv.DialRaw(*proto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DialRaw 失败: %v\n", err)
		fmt.Fprintln(os.Stderr, "提示: 需要 root 权限 (sudo)")
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("Raw socket 已创建，开始接收...")
	fmt.Println()

	// 预分配缓冲区 — RecvInto 的核心优势
	buf := make([]byte, *bufSize)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	deadline := time.After(time.Duration(*timeout) * time.Second)
	received := 0
	totalBytes := 0

	for {
		select {
		case <-sig:
			fmt.Println("\n收到中断信号...")
			goto summary
		case <-deadline:
			fmt.Println("\n超时...")
			goto summary
		default:
		}

		// RecvInto: 复用 buf，无内存分配
		n, src, err := conn.RecvInto(buf, 1*time.Second)
		if err != nil {
			// 超时是正常的，继续循环
			continue
		}

		received++
		totalBytes += n

		// buf[:n] 是本次收到的数据（有效到下次 RecvInto 调用）
		fmt.Printf("  #%d: %d 字节 from %s", received, n, src)
		if n >= 20 {
			// 打印 IP header 摘要
			version := buf[0] >> 4
			ihl := buf[0] & 0x0f
			ttl := buf[8]
			ipProto := buf[9]
			fmt.Printf(" [IPv%d, IHL=%d, TTL=%d, Proto=%d]", version, ihl, ttl, ipProto)
		}
		fmt.Println()

		if *maxPkts > 0 && received >= *maxPkts {
			fmt.Println("\n达到最大接收数...")
			goto summary
		}
	}

summary:
	fmt.Printf("\n--- 统计 ---\n")
	fmt.Printf("接收: %d 包, %d 字节\n", received, totalBytes)
	fmt.Printf("缓冲区大小: %d (全程复用同一块内存，零分配)\n", *bufSize)

	fmt.Println("\n--- RecvInto vs Recv 对比 ---")
	fmt.Println("  Recv(timeout):          每次调用分配 65536 字节")
	fmt.Println("  RecvInto(buf, timeout):  复用预分配 buf，0 alloc/op")
	fmt.Println("  适用场景: 高速抓包、性能敏感的包处理管线")
}
