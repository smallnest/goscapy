// 示例 28: Wake-on-LAN 发送器
//
// 本示例演示如何发送 WoL (Wake-on-LAN) 魔术包来唤醒局域网内的计算机。
// 魔术包格式: 6 字节 0xFF + 目标 MAC 重复 16 次。
//
// 运行方式: go run main.go [选项] <MAC地址>
// 示例:     go run main.go 00:11:22:33:44:55
//           go run main.go -broadcast 192.168.1.255 AA-BB-CC-DD-EE-FF
//
// 无需 root 权限（使用 Go net UDP 发送）。

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
)

func main() {
	broadcast := flag.String("broadcast", "255.255.255.255", "广播地址")
	port := flag.Int("port", 9, "目标端口 (9 或 7)")
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatalf("用法: go run main.go <MAC地址>\n示例: go run main.go 00:11:22:33:44:55")
	}

	mac := parseMAC(flag.Arg(0))
	if mac == nil {
		log.Fatalf("无效的 MAC 地址: %s", flag.Arg(0))
	}

	// 构造魔术包: 6 bytes FF + MAC × 16
	packet := make([]byte, 6+16*6)
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], mac)
	}

	addr := fmt.Sprintf("%s:%d", *broadcast, *port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("解析地址 %s 失败: %v", addr, err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatalf("创建 UDP 连接失败: %v", err)
	}
	defer conn.Close()

	n, err := conn.Write(packet)
	if err != nil {
		log.Fatalf("发送失败: %v", err)
	}

	fmt.Printf("WoL 魔术包已发送!\n")
	fmt.Printf("  目标 MAC:  %s\n", formatMAC(mac))
	fmt.Printf("  广播地址:  %s\n", *broadcast)
	fmt.Printf("  端口:      %d\n", *port)
	fmt.Printf("  包大小:    %d bytes\n", n)
}

func parseMAC(s string) []byte {
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ".", "")
	if len(s) != 12 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func formatMAC(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}