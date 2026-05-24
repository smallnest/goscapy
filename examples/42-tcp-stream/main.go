// 示例 42: TCP 流重组
//
// 本示例演示如何使用 goscapy 的 TCP 流重组功能。
// 你将学到:
//   - 如何创建 TCPReassembler 并配置超时和最大流数
//   - 如何提交数据包进行流重组
//   - 如何读取重组后的双向字节流
//   - 如何处理乱序、重传和重叠段
//
// 运行: go run main.go
package main

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/tcpstream"
)

func main() {
	fmt.Println("=== TCP 流重组示例 ===")
	fmt.Println()

	// 创建 Reassembler
	r := tcpstream.New(
		tcpstream.WithStreamTimeout(30*1e9),
		tcpstream.WithMaxStreams(1024),
	)
	defer r.Close()

	// 模拟一个 HTTP TCP 会话: 10.0.0.1:5000 ↔ 10.0.0.2:80

	// 1. 三次握手
	fmt.Println("--- 1. TCP 三次握手 ---")
	r.Submit(mkPkt("10.0.0.1", "10.0.0.2", 5000, 80, 1000, layers.TCPSyn, nil))
	fmt.Println("  SYN sent")
	r.Submit(mkPkt("10.0.0.2", "10.0.0.1", 80, 5000, 2000, layers.TCPSyn|layers.TCPAck, nil))
	fmt.Println("  SYN-ACK sent")
	r.Submit(mkPkt("10.0.0.1", "10.0.0.2", 5000, 80, 1001, layers.TCPAck, nil))
	fmt.Println("  ACK sent")
	fmt.Println()

	// 2. 客户端发送请求 (乱序到达)
	fmt.Println("--- 2. 客户端 HTTP 请求 (乱序) ---")
	r.Submit(mkPkt("10.0.0.1", "10.0.0.2", 5000, 80, 1005, layers.TCPAck, []byte("/HTTP/1.1\r\nHost: example.com\r\n\r\n")))
	fmt.Println("  seq=1005 (乱序，先到)")
	result := r.Submit(mkPkt("10.0.0.1", "10.0.0.2", 5000, 80, 1001, layers.TCPAck, []byte("GET ")))
	fmt.Println("  seq=1001 (填满间隙)")
	if result != nil {
		fmt.Printf("  重组: %q\n", string(result.ClientBytes))
	}
	fmt.Println()

	// 3. 服务器响应
	fmt.Println("--- 3. 服务器 HTTP 响应 ---")
	result = r.Submit(mkPkt("10.0.0.2", "10.0.0.1", 80, 5000, 2001, layers.TCPAck,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!")))
	if result != nil {
		fmt.Printf("  重组: %q\n", string(result.ServerBytes))
	}
	fmt.Println()

	// 4. 查看活跃流
	fmt.Println("--- 4. 流统计 ---")
	fmt.Printf("  活跃流: %d\n", r.Stats())
	for _, id := range r.StreamIDs() {
		s := r.ReadStream(id)
		if s != nil {
			fmt.Printf("  流: 客户端→服务器 %d bytes, 服务器→客户端 %d bytes\n",
				len(s.ClientBytes), len(s.ServerBytes))
		}
	}
}

// mkPkt creates an IP+TCP(+payload) packet for testing.
func mkPkt(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, flags uint8, payload []byte) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", net.ParseIP(srcIP))
	ip.Set("dst", net.ParseIP(dstIP))

	tcp := layers.NewTCP()
	tcp.Set("sport", srcPort)
	tcp.Set("dport", dstPort)
	tcp.Set("seq", seq)
	tcp.Set("flags", flags)

	pkt := ip.Over(tcp)
	if len(payload) > 0 {
		raw := layers.NewRaw()
		raw.Set("load", payload)
		pkt.Push(raw)
	}
	return pkt
}
