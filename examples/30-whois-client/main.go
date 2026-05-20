// 示例 30: WHOIS 客户端
//
// 本示例演示如何查询域名的 WHOIS 信息（注册商、到期时间等）。
// WHOIS 协议 (RFC 3912) 使用 TCP 端口 43，纯文本请求/响应。
//
// 运行方式: go run main.go [选项] <域名>
// 示例:     go run main.go example.com
//           go run main.go -server whois.verisign-grs.com example.com
//
// 无需 root 权限。

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

func main() {
	server := flag.String("server", "", "WHOIS 服务器 (为空则自动选择)")
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatalf("用法: go run main.go <域名>\n示例: go run main.go example.com")
	}

	domain := flag.Arg(0)
	whoisServer := *server
	if whoisServer == "" {
		whoisServer = detectWhoisServer(domain)
	}

	fmt.Printf("WHOIS 查询: %s → %s\n\n", domain, whoisServer)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(whoisServer, "43"), 10*time.Second)
	if err != nil {
		log.Fatalf("连接 %s 失败: %v", whoisServer, err)
	}
	defer conn.Close()

	// 发送查询 (CRLF 结尾)
	fmt.Fprintf(conn, "%s\r\n", domain)

	resp, err := io.ReadAll(conn)
	if err != nil {
		log.Fatalf("读取响应失败: %v", err)
	}

	text := string(resp)
	fmt.Println(text)

	// 提取关键信息
	fmt.Println("\n--- 关键信息摘要 ---")
	extractField(text, "Registrar:", "注册商")
	extractField(text, "Creation Date:", "创建时间")
	extractField(text, "Registry Expiry Date:", "到期时间")
	extractField(text, "Name Server:", "DNS 服务器")
}

func detectWhoisServer(domain string) string {
	tld := domain
	if idx := strings.LastIndex(domain, "."); idx >= 0 {
		tld = domain[idx+1:]
	}
	switch strings.ToUpper(tld) {
	case "COM", "NET":
		return "whois.verisign-grs.com"
	case "ORG":
		return "whois.pir.org"
	case "CN":
		return "whois.cnnic.cn"
	default:
		return "whois.iana.org"
	}
}

func extractField(text, field, label string) {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)%s\s*(.+)`, regexp.QuoteMeta(field)))
	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		fmt.Printf("  %s: %s\n", label, strings.TrimSpace(matches[1]))
	}
}