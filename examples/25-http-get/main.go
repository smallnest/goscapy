// 示例 25: HTTP GET 客户端
//
// 本示例演示如何手动构造 HTTP/1.1 GET 请求（通过原始 TCP 连接发送），
// 帮助理解 HTTP 协议的底层工作原理。
//
// 运行方式: go run main.go [选项] <URL>
// 示例:     go run main.go http://example.com
//           go run main.go -L http://example.com
//
// 无需 root 权限。

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

func main() {
	follow := flag.Bool("L", false, "跟随重定向")
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatalf("用法: go run main.go <URL>\n示例: go run main.go http://example.com")
	}

	rawURL := flag.Arg(0)
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Fatalf("解析 URL 失败: %v", err)
	}

	host := parsedURL.Host
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}

	fetch(parsedURL.Scheme, host, path, *follow, 0)
}

func fetch(scheme, host, path string, follow bool, depth int) {
	if depth > 5 {
		fmt.Println("重定向次数过多")
		return
	}

	port := "80"
	if scheme == "https" {
		port = "443"
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	connectStart := time.Now()

	var conn io.ReadWriteCloser
	if scheme == "https" {
		tlsConn, err := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{})
		if err != nil {
			log.Fatalf("TLS 连接失败: %v", err)
		}
		conn = tlsConn
	} else {
		tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
		if err != nil {
			log.Fatalf("连接失败: %v", err)
		}
		conn = tcpConn
	}
	defer conn.Close()

	connectTime := time.Since(connectStart)

	// 手动构造 HTTP/1.1 请求
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: goscapy-http/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host)

	reqStart := time.Now()
	_, err := fmt.Fprint(conn, request)
	if err != nil {
		log.Fatalf("发送请求失败: %v", err)
	}

	// 读取响应
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		log.Fatalf("读取响应失败: %v", err)
	}
	totalTime := time.Since(reqStart)
	firstByteTime := time.Since(reqStart) // simplified

	resp := string(respBytes)

	// 解析响应行和头部
	lines := strings.SplitN(resp, "\r\n\r\n", 2)
	headerPart := lines[0]
	bodyPart := ""
	if len(lines) > 1 {
		bodyPart = lines[1]
	}

	headerLines := strings.Split(headerPart, "\r\n")
	statusLine := headerLines[0]

	fmt.Printf("=== HTTP 响应 ===\n")
	fmt.Printf("状态行: %s\n", statusLine)
	fmt.Printf("连接时间: %.2f ms\n", connectTime.Seconds()*1000)
	fmt.Printf("首字节时间: %.2f ms\n", firstByteTime.Seconds()*1000)
	fmt.Printf("总时间: %.2f ms\n\n", totalTime.Seconds()*1000)

	fmt.Println("--- 响应头 ---")
	headers := headerLines[1:]
	for _, h := range headers {
		fmt.Println(h)
	}

	bodyLen := len(bodyPart)
	displayLen := bodyLen
	if bodyLen > 500 {
		displayLen = 500
	}
	fmt.Printf("\n--- 响应体 (%d bytes, 显示前 %d bytes) ---\n", bodyLen, displayLen)
	fmt.Println(bodyPart[:displayLen])
	if bodyLen > 500 {
		fmt.Println("... (截断)")
	}

	// 跟随重定向
	if follow {
		for _, h := range headers {
			if strings.HasPrefix(strings.ToLower(h), "location:") {
				loc := strings.TrimSpace(h[len("location:"):])
				fmt.Printf("\n→ 重定向到: %s\n", loc)
				parsed, _ := url.Parse(loc)
				fetch(parsed.Scheme, parsed.Host, parsed.Path, true, depth+1)
				return
			}
		}
	}
	_ = firstByteTime
}