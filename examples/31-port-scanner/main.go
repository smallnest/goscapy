// 示例 31: TCP 端口扫描器
//
// 本示例演示如何实现 TCP Connect 端口扫描器，使用 Go 标准库并发扫描。
// 支持自定义端口范围、常用端口预设、服务名称识别。
//
// 运行方式: go run main.go [选项] <目标>
// 示例:     go run main.go 127.0.0.1
//           go run main.go -p 20-100 192.168.1.1
//           go run main.go --top-ports 100 scanme.nmap.org
//
// 无需 root 权限。

package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(flag.CommandLine.Output(), "用法: go run main.go [选项] <目标>\n")
		return
	}

	target := flag.Arg(0)
	portList := getPortList(*ports, *topPorts)

	fmt.Printf("扫描目标: %s\n", target)
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

			addr := net.JoinHostPort(target, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				service := wellKnownPorts[p]
				if service == "" {
					service = "unknown"
				}
				mu.Lock()
				results = append(results, scanResult{p, "OPEN", service})
				mu.Unlock()
				fmt.Printf("%-8d %-12s %s\n", p, "OPEN", service)
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