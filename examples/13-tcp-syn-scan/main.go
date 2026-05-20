// 示例 13: TCP SYN 扫描示例
//
// ⚠️  需要 root 权限: sudo go run main.go
//
// 本示例演示如何使用 goscapy 实现 TCP SYN 半开放端口扫描。
// 你将学到:
//   - TCP 三次握手原理
//   - SYN 扫描的工作原理
//   - 如何判断端口开放/关闭/被过滤
//   - 超时控制和错误处理
//
// ⚠️  重要提示: 仅在授权的网络环境中使用端口扫描技术。
//     未经授权扫描他人网络是违法行为。
//
// 运行方式: sudo go run main.go [接口名] [目标IP]
// 示例:     sudo go run main.go en0 127.0.0.1

package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	fmt.Println("=== goscapy 示例 13: TCP SYN 端口扫描 ===")
	fmt.Println()

	targetIP := "127.0.0.1"
	if len(os.Args) > 2 {
		targetIP = os.Args[2]
	}

	iface := ""
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	if iface == "" {
		if isLocalIP(targetIP) {
			iface = sendrecv.LoopbackName()
		} else {
			iface = defaultIface()
		}
	}

	fmt.Printf("目标: %s, 接口: %s\n", targetIP, iface)
	fmt.Println()

	// -----------------------------------------------------------------------
	// TCP SYN 扫描原理
	// -----------------------------------------------------------------------
	// TCP 三次握手:
	//   1. 客户端 → SYN → 服务器        (我们发送)
	//   2. 服务器 → SYN+ACK → 客户端    (端口开放)
	//      或者 服务器 → RST → 客户端    (端口关闭)
	//   3. 客户端 → ACK → 服务器         (完成连接)
	//
	// SYN 扫描只完成前两步，不发送最后的 ACK，因此称为"半开放扫描"。
	// 优点: 不建立完整连接，速度快，不容易被日志记录。

	// -----------------------------------------------------------------------
	// 定义要扫描的端口
	// -----------------------------------------------------------------------
	ports := []uint16{22, 80, 443, 8080} // SSH, HTTP, HTTPS, HTTP-Alt
	fmt.Printf("扫描端口: %v\n\n", ports)

	// -----------------------------------------------------------------------
	// 逐端口扫描
	// -----------------------------------------------------------------------
	for _, port := range ports {
		status := scanPort(iface, targetIP, port)
		fmt.Printf("  端口 %5d: %s\n", port, status)
	}
	fmt.Println()

	// -----------------------------------------------------------------------
	// 端口状态参考
	// -----------------------------------------------------------------------
	fmt.Println("--- 端口状态说明 ---")
	fmt.Println()
	fmt.Println("  OPEN (开放):     收到 SYN+ACK → 端口开放，有服务监听")
	fmt.Println("  CLOSED (关闭):   收到 RST → 端口关闭，没有服务监听")
	fmt.Println("  FILTERED (过滤): 超时无响应 → 可能被防火墙过滤")
	fmt.Println()
	fmt.Println("下一步: 运行 14-sniff 示例，学习包嗅探")
}

// scanPort 扫描单个端口并返回状态描述
func scanPort(iface, targetIP string, port uint16) string {
	// 构建 TCP SYN 包
	synPkt := goscapy.NewEthernet().
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP(targetIP).
			TTL(64).
			Proto(layers.IPProtoTCP)).
		Over(goscapy.NewTCP().
			SrcPort(54321).                   // 源端口
			DstPort(port).                    // 目标端口
			Seq(1000).                        // 序列号
			Flags(layers.TCPSyn).             // SYN 标志
			Window(65535)).
		Packet()

	// 发送并等待响应 (超时 2 秒)
	_, received, err := sendrecv.SendRecv1(synPkt, iface, 2*time.Second)
	if err != nil {
		return fmt.Sprintf("错误: %v", err)
	}

	if received == nil {
		return "FILTERED (超时无响应)"
	}

	// 检查响应中的 TCP 层
	tcpLayer := received.GetLayer("TCP")
	if tcpLayer == nil {
		return "未知 (无 TCP 层)"
	}

	flags, _ := tcpLayer.Get("flags")
	if flags == nil {
		return "未知 (无 TCP 标志)"
	}

	tcpFlags := flags.(uint8)

	// SYN+ACK (0x12) 表示端口开放
	if tcpFlags&layers.TCPSyn != 0 && tcpFlags&layers.TCPAck != 0 {
		return "OPEN (收到 SYN+ACK)"
	}

	// RST (0x04) 表示端口关闭
	if tcpFlags&layers.TCPRst != 0 {
		return "CLOSED (收到 RST)"
	}

	return fmt.Sprintf("未知 (TCP 标志: 0x%02x)", tcpFlags)
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "en0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			return iface.Name
		}
	}
	return "en0"
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}
