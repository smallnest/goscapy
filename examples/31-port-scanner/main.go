// 示例 31: TCP 端口扫描器 (纯 goscapy 实现)
//
// 本示例演示如何使用 goscapy 实现 TCP SYN 半开放端口扫描。
// 支持自定义端口范围、常用端口预设、服务名称识别、并发扫描和统计。
//
// 运行方式: sudo go run main.go [选项] <目标>
// 示例:     sudo go run main.go 127.0.0.1
//           sudo go run main.go -p 20-100 192.168.1.1
//           sudo go run main.go --top-ports 100 scanme.nmap.org
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

var wellKnownPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
	135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
	445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
	6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

var top100 = []int{
	7, 9, 13, 21, 22, 23, 25, 37, 53, 79, 80, 88, 106, 110,
	111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
	465, 513, 514, 543, 548, 554, 587, 631, 646, 873, 990, 993, 995,
	1025, 1026, 1027, 1080, 1194, 1433, 1701, 1723, 1900, 2000, 2049, 2082, 2083,
	2222, 2375, 2483, 2484, 3000, 3128, 3260, 3306, 3389, 3899, 4000, 4369, 4444,
	4500, 5000, 5353, 5432, 5555, 5632, 5800, 5900, 5984, 6379, 7001, 7002, 7077,
	8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017, 27018,
	27019, 28015, 50000, 50070, 50090,
}

func main() {
	ports := flag.String("p", "", "端口范围: 80 或 20-100 或 22,80,443")
	topPorts := flag.Int("top-ports", 0, "扫描前 N 个常用端口")
	workers := flag.Int("workers", 100, "并发数")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(flag.CommandLine.Output(), "用法: sudo go run main.go [选项] <目标>\n")
		return
	}

	target := flag.Arg(0)
	portList := getPortList(*ports, *topPorts)

	targetIPs, err := net.LookupIP(target)
	if err != nil || len(targetIPs) == 0 {
		fmt.Fprintf(os.Stderr, "无法解析目标: %s, 错误: %v\n", target, err)
		os.Exit(1)
	}
	var targetIP net.IP
	for _, ip := range targetIPs {
		if ip.To4() != nil {
			targetIP = ip.To4()
			break
		}
	}
	if targetIP == nil {
		fmt.Fprintf(os.Stderr, "目标 %s 没有 IPv4 地址\n", target)
		os.Exit(1)
	}

	ifaceVal := *iface
	if isLocalIP(targetIP.String()) {
		if ifaceVal != "" && ifaceVal != sendrecv.LoopbackName() {
			fmt.Printf("提示: 检测到目标 IP 是本地地址，自动切换网络接口从 %s 至回环接口 %s\n", ifaceVal, sendrecv.LoopbackName())
		}
		ifaceVal = sendrecv.LoopbackName()
	} else if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	srcIP := getSrcIP(ifaceVal)
	if isLocalIP(targetIP.String()) {
		srcIP = targetIP.String()
	} else if srcIP == "0.0.0.0" {
		fmt.Fprintf(os.Stderr, "无法获取接口 %s 的有效 IPv4 地址\n", ifaceVal)
		os.Exit(1)
	}

	fmt.Printf("扫描目标: %s (%s)\n", target, targetIP)
	fmt.Printf("网络接口: %s, 源 IP: %s\n", ifaceVal, srcIP)
	fmt.Printf("端口数量: %d, 并发数: %d\n\n", len(portList), *workers)
	fmt.Printf("%-8s %-12s %s\n", "PORT", "STATE", "SERVICE")
	fmt.Println(strings.Repeat("-", 35))

	start := time.Now()
	var mu sync.Mutex
	var results []scanResult
	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup

	for _, port := range portList {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := scanPort(ifaceVal, srcIP, targetIP.String(), p)
			if res.state == "OPEN" {
				mu.Lock()
				results = append(results, res)
				fmt.Printf("%-8d %-12s %s\n", p, "OPEN", res.service)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	elapsed := time.Since(start)
	sort.Slice(results, func(i, j int) bool { return results[i].port < results[j].port })

	fmt.Println(strings.Repeat("-", 35))
	fmt.Printf("\n扫描完成: 扫描 %d 端口, %d 开放, 耗时 %.2f s\n",
		len(portList), len(results), elapsed.Seconds())
}

type scanResult struct {
	port    int
	state   string
	service string
}

func scanPort(iface, srcIP, targetIP string, port int) scanResult {
	srcPort := uint16(30000 + rand.Intn(20000))
	pkt := goscapy.NewIP().
		SrcIP(srcIP).
		DstIP(targetIP).
		TTL(64).
		Proto(layers.IPProtoTCP).
		Over(goscapy.NewTCP().
			SrcPort(srcPort).
			DstPort(uint16(port)).
			Seq(1000).
			Flags(layers.TCPSyn).
			Window(65535)).
		Packet()

	service := wellKnownPorts[port]
	if service == "" {
		service = "unknown"
	}

	matchFunc := func(sent, received *packet.Packet) bool {
		ipLayer := received.GetLayer("IP")
		if ipLayer == nil {
			return false
		}
		srcVal, _ := ipLayer.Get("src")
		srcIPNet, ok := srcVal.(net.IP)
		if !ok || !srcIPNet.Equal(net.ParseIP(targetIP)) {
			return false
		}

		tcpLayer := received.GetLayer("TCP")
		if tcpLayer == nil {
			return false
		}
		sportVal, _ := tcpLayer.Get("sport")
		dportVal, _ := tcpLayer.Get("dport")
		sport, _ := sportVal.(uint16)
		dport, _ := dportVal.(uint16)

		return sport == uint16(port) && dport == srcPort
	}

	_, received, err := sendrecv.Sr1(pkt, iface, 1*time.Second, matchFunc)
	if err != nil || received == nil {
		return scanResult{port, "FILTERED", service}
	}

	tcpLayer := received.GetLayer("TCP")
	if tcpLayer == nil {
		return scanResult{port, "UNKNOWN", service}
	}

	flagsVal, _ := tcpLayer.Get("flags")
	if flagsVal == nil {
		return scanResult{port, "UNKNOWN", service}
	}

	flags := flagsVal.(uint8)
	if flags&layers.TCPSyn != 0 && flags&layers.TCPAck != 0 {
		return scanResult{port, "OPEN", service}
	} else if flags&layers.TCPRst != 0 {
		return scanResult{port, "CLOSED", service}
	}

	return scanResult{port, "UNKNOWN", service}
}

func getPortList(spec string, topN int) []int {
	if topN > 0 {
		if topN > len(top100) {
			topN = len(top100)
		}
		return top100[:topN]
	}

	var ports []int
	if spec == "" {
		for p := 1; p <= 1024; p++ {
			ports = append(ports, p)
		}
		return ports
	}

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, _ := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			p, _ := strconv.Atoi(part)
			ports = append(ports, p)
		}
	}
	return ports
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