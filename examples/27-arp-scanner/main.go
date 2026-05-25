// 示例 27: ARP 扫描器
//
// 本示例演示如何使用 goscapy 发送 ARP 请求来扫描局域网内的活跃主机。
// 你将学到:
//   - ARP 请求/响应的工作原理
//   - CIDR 子网计算和 IP 范围遍历
//   - 并发扫描提高速度
//   - SendRecv 收集多个 ARP 响应
//
// 运行方式: sudo go run main.go -cidr <CIDR> [选项]
// 示例:     sudo go run main.go -cidr 192.168.1.0/24
//           sudo go run main.go -cidr 10.0.0.0/28 -workers 20
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"cmp"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	cidr := flag.String("cidr", "", "扫描的 IP 范围 (CIDR 格式, 如 192.168.1.0/24)")
	workers := flag.Int("workers", 50, "并发扫描数")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	flag.Parse()

	if *cidr == "" {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go -cidr <CIDR> [选项]\n")
		fmt.Fprintf(os.Stderr, "示例: sudo go run main.go -cidr 192.168.1.0/24\n")
		os.Exit(1)
	}

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	srcMAC := getSrcMAC(ifaceVal)
	srcIP := getSrcIP(ifaceVal)

	ips := cidrToIPs(*cidr)
	fmt.Printf("ARP 扫描: %s\n", *cidr)
	fmt.Printf("接口: %s, 源 IP: %s, 源 MAC: %s\n", ifaceVal, srcIP, srcMAC)
	fmt.Printf("目标数: %d, 并发: %d\n\n", len(ips), *workers)
	fmt.Printf("%-16s %-18s\n", "IP", "MAC")
	fmt.Println("------------------------------------")

	start := time.Now()

	type result struct {
		ip  string
		mac string
	}

	var mu sync.Mutex
	var results []result
	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()

			mac := arpProbe(ifaceVal, srcMAC, srcIP, ip)
			if mac != "" {
				mu.Lock()
				results = append(results, result{ip, mac})
				fmt.Printf("%-16s %s\n", ip, mac)
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	elapsed := time.Since(start)

	slices.SortFunc(results, func(a, b result) int { return cmp.Compare(a.ip, b.ip) })

	fmt.Println("------------------------------------")
	fmt.Printf("\n扫描完成: 总数 %d, 存活 %d, 耗时 %.2f s\n", len(ips), len(results), elapsed.Seconds())
}

func arpProbe(iface, srcMAC, srcIP, targetIP string) string {
	pkt := goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").
		SrcMAC(srcMAC).
		Type(layers.EtherTypeARP).
		Over(goscapy.NewARP().
			Op(layers.ARPWhoHas).
			SrcMAC(srcMAC).
			DstMAC("00:00:00:00:00:00").
			SrcIP(srcIP).
			DstIP(targetIP)).
		Packet()

	_, reply, err := sendrecv.Srp1(pkt, iface, 1500*time.Millisecond, nil)
	if err != nil || reply == nil {
		return ""
	}

	arpLayer := reply.GetLayer("ARP")
	if arpLayer == nil {
		return ""
	}

	hwSrc, _ := arpLayer.Get("hwsrc")
	if hwSrc == nil {
		return ""
	}

	macVal, ok := hwSrc.(net.HardwareAddr)
	if !ok {
		return ""
	}
	mac := macVal.String()
	if mac == "00:00:00:00:00:00" {
		return ""
	}
	return mac
}

func cidrToIPs(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无效的 CIDR: %s\n", cidr)
		os.Exit(1)
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func getSrcMAC(iface string) string {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return "00:00:00:00:00:00"
	}
	return i.HardwareAddr.String()
}

func getSrcIP(iface string) string {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return "0.0.0.0"
	}
	addrs, err := i.Addrs()
	if err != nil || len(addrs) == 0 {
		return "0.0.0.0"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "0.0.0.0"
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