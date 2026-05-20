// 示例 29: TFTP 客户端
//
// 本示例演示如何从 TFTP (Trivial File Transfer Protocol) 服务器下载文件。
// TFTP 使用简单的请求-确认机制，常用于嵌入式设备固件更新。
//
// 运行方式: go run main.go [选项] <服务器> <文件名>
// 示例:     go run main.go 192.168.1.1 firmware.bin
//
// 无需 root 权限。

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const (
	tftpRRQ   = 1 // Read Request
	tftpDATA  = 3 // Data
	tftpACK   = 4 // Acknowledgment
	tftpERROR = 5 // Error
	maxRetries = 3
)

func main() {
	flag.Parse()

	if flag.NArg() < 2 {
		log.Fatalf("用法: go run main.go <服务器> <文件名>\n示例: go run main.go 192.168.1.1 firmware.bin")
	}

	server := flag.Arg(0)
	filename := flag.Arg(1)

	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(server, "69"))
	if err != nil {
		log.Fatalf("解析服务器地址失败: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Fatalf("连接服务器失败: %v", err)
	}
	defer conn.Close()

	start := time.Now()

	// 发送 Read Request (RRQ)
	rrq := buildRRQ(filename)
	_, err = conn.Write(rrq)
	if err != nil {
		log.Fatalf("发送 RRQ 失败: %v", err)
	}

	// 接收数据块
	var dataAddr *net.UDPAddr
	buf := make([]byte, 516) // 4 header + 512 data
	var fileData []byte
	expectedBlock := uint16(1)

	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Println("传输超时")
				return
			}
			log.Fatalf("接收失败: %v", err)
		}

		if dataAddr == nil {
			dataAddr = addr
		}

		if n < 4 {
			continue
		}

		opcode := binary.BigEndian.Uint16(buf[0:2])

		switch opcode {
		case tftpDATA:
			blockNum := binary.BigEndian.Uint16(buf[2:4])
			if blockNum != expectedBlock {
				continue
			}
			fileData = append(fileData, buf[4:n]...)
			fmt.Printf("\r接收中... %d bytes (block %d)", len(fileData), blockNum)

			// 发送 ACK
			ack := make([]byte, 4)
			binary.BigEndian.PutUint16(ack[0:2], tftpACK)
			binary.BigEndian.PutUint16(ack[2:4], blockNum)
			conn.WriteToUDP(ack, dataAddr)

			if n < 516 {
				// 最后一个数据块 (< 512 bytes data)
				elapsed := time.Since(start)
				fmt.Printf("\n\n传输完成!\n")
				fmt.Printf("  文件名: %s\n", filename)
				fmt.Printf("  文件大小: %d bytes\n", len(fileData))
				fmt.Printf("  耗时: %.2f s\n", elapsed.Seconds())
				fmt.Printf("  平均速率: %.2f KB/s\n", float64(len(fileData))/elapsed.Seconds()/1024)
				return
			}
			expectedBlock++

		case tftpERROR:
			errMsg := string(buf[4:n])
			fmt.Fprintf(os.Stderr, "\nTFTP 错误: %s\n", errMsg)
			return
		}
	}
}

func buildRRQ(filename string) []byte {
	rrq := make([]byte, 2)
	binary.BigEndian.PutUint16(rrq, tftpRRQ)
	rrq = append(rrq, []byte(filename)...)
	rrq = append(rrq, 0)
	rrq = append(rrq, []byte("octet")...)
	rrq = append(rrq, 0)
	return rrq
}