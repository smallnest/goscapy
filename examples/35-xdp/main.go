// 示例 35: AF_XDP 高性能收发包
//
// 本示例演示如何使用 AF_XDP 进行用户态高性能网络 I/O。
// AF_XDP 通过内核 bypass 和共享内存 (UMEM) 实现零拷贝或低拷贝网络访问。
//
// 前置条件:
//   1. Linux >= 5.4
//   2. 已在目标接口上加载 XDP 程序（将流量重定向到 XSK map）
//      例如: ip link set dev eth0 xdp obj xdp_redirect.o
//   3. root 权限或 CAP_NET_ADMIN + CAP_BPF
//
// 运行方式: sudo go run main.go [-I <接口>] [-q <队列>] [-mode copy|zerocopy]
// 示例:     sudo go run main.go -I eth0 -q 0 -mode copy
//
// ⚠️  仅支持 Linux。

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	queue := flag.Int("q", 0, "NIC 队列 ID")
	mode := flag.String("mode", "copy", "模式: copy 或 zerocopy")
	duration := flag.Duration("d", 10*time.Second, "抓包持续时间")
	showHex := flag.Bool("hex", false, "显示包的十六进制内容")
	txData := flag.String("tx", "", "发送指定十六进制数据包 (仅发送模式)")
	flag.Parse()

	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "错误: AF_XDP 仅支持 Linux")
		os.Exit(1)
	}

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	var flags uint16
	switch *mode {
	case "copy":
		flags = sendrecv.XDPCopy
	case "zerocopy":
		flags = sendrecv.XDPZeroCopy
	default:
		fmt.Fprintf(os.Stderr, "未知模式: %s (支持: copy, zerocopy)\n", *mode)
		os.Exit(1)
	}

	fmt.Printf("AF_XDP: 接口=%s, 队列=%d, 模式=%s, 时长=%v\n",
		ifaceVal, *queue, *mode, *duration)

	conn, err := sendrecv.OpenXDP(ifaceVal,
		sendrecv.WithXDPQueueID(*queue),
		sendrecv.WithXDPFlags(flags),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("XDP socket 已创建 (fd=%d), 可用帧: %d\n\n", conn.Fd(), conn.FreeFrames())

	// 如果提供了 TX 数据，发送后退出
	if *txData != "" {
		data, err := hex.DecodeString(*txData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "无效十六进制: %v\n", err)
			os.Exit(1)
		}
		if err := conn.Send(data); err != nil {
			fmt.Fprintf(os.Stderr, "发送失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("已发送 %d 字节\n", len(data))
		return
	}

	// 接收模式
	var totalPkts int64
	var totalBytes int64

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			data, err := conn.Recv()
			if err != nil {
				return
			}
			atomic.AddInt64(&totalPkts, 1)
			atomic.AddInt64(&totalBytes, int64(len(data)))

			if *showHex && len(data) > 0 {
				n := len(data)
				if n > 64 {
					n = 64
				}
				fmt.Printf("[%d bytes] %x...\n", len(data), data[:n])
			}
		}
	}()

	// 信号处理
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	timer := time.NewTimer(*duration)
	defer timer.Stop()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	start := time.Now()
	lastPkts := int64(0)
	lastBytes := int64(0)

	for {
		select {
		case <-sig:
			fmt.Println("\n收到中断信号...")
			conn.Close()
			goto summary
		case <-timer.C:
			fmt.Println("\n时间到...")
			conn.Close()
			goto summary
		case <-ticker.C:
			pkts := atomic.LoadInt64(&totalPkts)
			bytes := atomic.LoadInt64(&totalBytes)
			pps := pkts - lastPkts
			bps := float64((bytes - lastBytes) * 8)
			lastPkts = pkts
			lastBytes = bytes
			elapsed := time.Since(start).Seconds()
			fmt.Printf("[%5.1fs] 包数: %d, pps: %d, bps: %s, 可用帧: %d\n",
				elapsed, pkts, pps, formatBits(bps), conn.FreeFrames())
		}
	}

summary:
	<-done
	elapsed := time.Since(start)
	pkts := atomic.LoadInt64(&totalPkts)
	bytes := atomic.LoadInt64(&totalBytes)

	fmt.Printf("\n--- 统计 ---\n")
	fmt.Printf("总包数: %d, 总字节: %d, 耗时: %.2fs\n", pkts, bytes, elapsed.Seconds())
	if elapsed.Seconds() > 0 {
		fmt.Printf("平均: %.0f pps, %s\n",
			float64(pkts)/elapsed.Seconds(),
			formatBits(float64(bytes)*8/elapsed.Seconds()))
	}
}

func formatBits(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func defaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
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
	return "eth0"
}
