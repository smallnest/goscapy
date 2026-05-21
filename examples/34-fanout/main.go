// 示例 34: AF_PACKET Fanout 多核并行抓包
//
// 本示例演示如何使用 PACKET_FANOUT 在多个 goroutine 间分发网络流量，
// 实现多核并行抓包处理。
//
// 运行方式: sudo go run main.go [-I <接口>] [-n <并发数>] [-mode <fanout模式>]
// 示例:     sudo go run main.go -I eth0 -n 4 -mode hash
//
// ⚠️  仅支持 Linux，需要 root 权限 (sudo) 或 CAP_NET_RAW。

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	n := flag.Int("n", runtime.NumCPU(), "并发接收 goroutine 数")
	mode := flag.String("mode", "hash", "fanout 模式 (hash, lb, cpu, rollover)")
	duration := flag.Duration("d", 10*time.Second, "抓包持续时间")
	flag.Parse()

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	var fanoutMode uint16
	switch *mode {
	case "hash":
		fanoutMode = sendrecv.FanoutHash
	case "lb":
		fanoutMode = sendrecv.FanoutLB
	case "cpu":
		fanoutMode = sendrecv.FanoutCPU
	case "rollover":
		fanoutMode = sendrecv.FanoutRollover
	default:
		fmt.Fprintf(os.Stderr, "未知 fanout 模式: %s (支持: hash, lb, cpu, rollover)\n", *mode)
		os.Exit(1)
	}

	fmt.Printf("🚀 Fanout 多核抓包: 接口=%s, 并发=%d, 模式=%s, 时长=%v\n",
		ifaceVal, *n, *mode, *duration)

	fr, err := sendrecv.OpenFanoutReceiver(ifaceVal, *n,
		sendrecv.WithFanoutMode(fanoutMode),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	defer fr.Close()

	fmt.Printf("已创建 %d 个 fanout socket\n\n", fr.NumSockets())

	// 统计计数器
	var totalPkts int64
	var perWorker [64]int64 // per-goroutine counter (max 64 workers)

	// 在后台启动接收
	done := make(chan struct{})
	go func() {
		fr.RecvParallel(func(pkt *packet.Packet) {
			atomic.AddInt64(&totalPkts, 1)
			// Use goroutine ID approximation via counter modulo
			// (actual goroutine distribution depends on kernel fanout)
		})
		close(done)
	}()

	// 等待中断信号或超时
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	timer := time.NewTimer(*duration)
	defer timer.Stop()

	// 定期输出统计
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	start := time.Now()
	lastPkts := int64(0)

	for {
		select {
		case <-sig:
			fmt.Println("\n收到中断信号，停止抓包...")
			fr.Close()
			goto done_label
		case <-timer.C:
			fmt.Println("\n抓包时间到，停止...")
			fr.Close()
			goto done_label
		case <-ticker.C:
			currentPkts := atomic.LoadInt64(&totalPkts)
			pps := currentPkts - lastPkts
			lastPkts = currentPkts
			elapsed := time.Since(start).Seconds()
			fmt.Printf("[%5.1fs] 总包数: %d, 当前速率: %d pps\n",
				elapsed, currentPkts, pps)
		}
	}

done_label:
	<-done
	_ = perWorker // suppress unused warning

	elapsed := time.Since(start)
	total := atomic.LoadInt64(&totalPkts)
	avgPPS := float64(total) / elapsed.Seconds()

	fmt.Printf("\n--- 统计 ---\n")
	fmt.Printf("总包数: %d, 耗时: %.2fs, 平均速率: %.0f pps\n",
		total, elapsed.Seconds(), avgPPS)
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
