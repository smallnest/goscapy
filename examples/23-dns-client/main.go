// 示例 23: DNS 客户端
//
// 本示例演示如何使用 goscapy 实现真实的 DNS 查询客户端。
// 你将学到:
//   - 使用 DNS Builder 构造查询包
//   - 通过 UDP/53 发送 DNS 查询并接收响应
//   - 解析 DNS 响应中的 Answer 资源记录
//   - 支持多种记录类型 (A, AAAA, MX, NS, TXT, CNAME)
//
// 运行方式: sudo go run main.go [选项] <域名>
// 示例:     sudo go run main.go example.com
//           sudo go run main.go -type MX -server 1.1.1.1 google.com
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

var typeNames = map[string]uint16{
	"A":     dns.QtypeA,
	"AAAA":  dns.QtypeAAAA,
	"MX":    dns.QtypeMX,
	"NS":    dns.QtypeNS,
	"TXT":   dns.QtypeTXT,
	"CNAME": dns.QtypeCNAME,
	"PTR":   dns.QtypePTR,
	"SOA":   dns.QtypeSOA,
}

var typeLabels = map[uint16]string{
	dns.QtypeA:     "A",
	dns.QtypeAAAA:  "AAAA",
	dns.QtypeMX:    "MX",
	dns.QtypeNS:    "NS",
	dns.QtypeTXT:   "TXT",
	dns.QtypeCNAME: "CNAME",
	dns.QtypePTR:   "PTR",
	dns.QtypeSOA:   "SOA",
}

func main() {
	qtype := flag.String("type", "A", "查询类型: A, AAAA, MX, NS, TXT, CNAME, PTR, SOA")
	server := flag.String("server", "8.8.8.8", "DNS 服务器地址")
	iface := flag.String("I", "", "网络接口 (默认自动选择)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "用法: sudo go run main.go [选项] <域名>\n")
		fmt.Fprintf(os.Stderr, "示例: sudo go run main.go example.com\n")
		fmt.Fprintf(os.Stderr, "      sudo go run main.go -type MX -server 1.1.1.1 google.com\n")
		os.Exit(1)
	}

	domain := flag.Arg(0)
	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	qt, ok := typeNames[strings.ToUpper(*qtype)]
	if !ok {
		fmt.Fprintf(os.Stderr, "不支持的查询类型: %s\n", *qtype)
		fmt.Fprintf(os.Stderr, "支持的类型: A, AAAA, MX, NS, TXT, CNAME, PTR, SOA\n")
		os.Exit(1)
	}

	fmt.Printf("DNS 查询: %s (%s) → %s\n\n", domain, strings.ToUpper(*qtype), *server)

	questions := []dns.DNSQuestion{
		{Name: domain, Type: qt, Class: dns.QclassIN},
	}

	start := time.Now()
	pkt := buildDNSQuery(*server, questions)
	_, reply, err := sendrecv.SendRecv1(pkt, ifaceVal, 3*time.Second)
	rtt := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "查询失败: %v\n", err)
		os.Exit(1)
	}

	if reply == nil {
		fmt.Println("查询超时: 未收到响应")
		os.Exit(1)
	}

	dnsLayer := reply.GetLayer("DNS")
	if dnsLayer == nil {
		fmt.Println("响应中没有 DNS 层")
		os.Exit(1)
	}

	answers, err := dns.GetAnswers(dnsLayer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 DNS 响应失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("查询时间: %.2f ms\n", rtt.Seconds()*1000)
	fmt.Printf("回答记录数: %d\n\n", len(answers))

	if len(answers) == 0 {
		fmt.Println("无回答记录（可能域名不存在或记录类型不匹配）")
		return
	}

	for i, rr := range answers {
		label := typeLabels[rr.Type]
		if label == "" {
			label = fmt.Sprintf("TYPE%d", rr.Type)
		}
		value := formatRData(rr)
		fmt.Printf("[%d] %-30s %-6s %s\n", i+1, rr.Name, label, value)
	}
}

func buildDNSQuery(serverIP string, questions []dns.DNSQuestion) *packet.Packet {
	return goscapy.NewEthernet().
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP(serverIP).
			TTL(64).
			Proto(layers.IPProtoUDP)).
		Over(goscapy.NewUDP().
			SrcPort(54321).
			DstPort(53)).
		Over(goscapy.NewDNS().
			ID(0x1234).
			Flags(0x0100).
			Questions(questions)).
		Packet()
}

func formatRData(rr dns.DNSRR) string {
	switch rr.Type {
	case dns.QtypeA:
		return dns.ParseARData(rr.RData)
	case dns.QtypeAAAA:
		return dns.ParseAAAARData(rr.RData)
	case dns.QtypeCNAME:
		name, err := dns.ParseCNAMERData(rr.RData, -len(rr.RData))
		if err != nil {
			return fmt.Sprintf("<解析错误: %v>", err)
		}
		return name
	case dns.QtypeMX:
		if len(rr.RData) < 3 {
			return "<无效 MX 记录>"
		}
		pref := binary.BigEndian.Uint16(rr.RData[:2])
		name, _, err := dns.DecodeName(rr.RData, 2, -len(rr.RData))
		if err != nil {
			return fmt.Sprintf("pref=%d <解析错误: %v>", pref, err)
		}
		return fmt.Sprintf("pref=%d → %s", pref, name)
	case dns.QtypeNS:
		name, _, err := dns.DecodeName(rr.RData, 0, -len(rr.RData))
		if err != nil {
			return fmt.Sprintf("<解析错误: %v>", err)
		}
		return name
	case dns.QtypeTXT:
		if len(rr.RData) > 0 {
			return string(rr.RData)
		}
		return "(空)"
	case dns.QtypeSOA:
		return formatSOA(rr.RData)
	default:
		return fmt.Sprintf("%d bytes: %x", len(rr.RData), rr.RData)
	}
}

func formatSOA(rdata []byte) string {
	mname, consumed, err := dns.DecodeName(rdata, 0, -len(rdata))
	if err != nil {
		return fmt.Sprintf("<SOA 解析错误>")
	}
	rname, _, err := dns.DecodeName(rdata, consumed, -len(rdata))
	if err != nil {
		return fmt.Sprintf("<SOA 解析错误>")
	}
	return fmt.Sprintf("mname=%s rname=%s", mname, rname)
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