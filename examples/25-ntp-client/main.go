// 示例 25: NTP 客户端
//
// 本示例演示如何使用 goscapy 构造 NTP 请求并通过标准 UDP socket
// 发送到 NTP 服务器，然后解析 NTP 响应获取时间信息。
// 你将学到:
//   - NTP 协议包格式
//   - 使用 goscapy 构建 UDP/NTP 包
//   - 通过标准 UDP socket 发送和接收
//   - NTP 时间戳解析和时钟偏移计算
//
// 运行方式: go run main.go [选项]
// 示例:     go run main.go
//           go run main.go -server time.google.com
//
// 无需 root 权限。

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"time"
)

const ntpEpochOffset = 2208988800

func main() {
	server := flag.String("server", "time.google.com", "NTP server address")
	flag.Parse()

	serverAddr, err := resolveHost(*server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve %s: %v\n", *server, err)
		os.Exit(1)
	}

	fmt.Printf("NTP query: %s (%s)\n\n", *server, serverAddr)

	// Build NTP request packet (48 bytes).
	ntpReq := buildNTPRequest()
	start := time.Now()

	// Send via standard UDP socket and receive response.
	respData, err := sendNTPQuery(serverAddr, ntpReq, 3*time.Second)
	rtt := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
		os.Exit(1)
	}

	if len(respData) < 48 {
		fmt.Fprintf(os.Stderr, "NTP response too short: %d bytes\n", len(respData))
		os.Exit(1)
	}

	// Parse NTP response fields.
	li := (respData[0] >> 6) & 0x03
	vn := (respData[0] >> 3) & 0x07
	stratum := respData[1]
	refTS := ntpToTime(respData[16:24])
	origTS := ntpToTime(respData[24:32])
	recvTS := ntpToTime(respData[32:40])
	xmitTS := ntpToTime(respData[40:48])

	offset := float64(recvTS.UnixNano()-origTS.UnixNano()) / 1e9

	fmt.Printf("LI: %d  VN: %d  Stratum: %d\n", li, vn, stratum)
	fmt.Printf("Ref Timestamp:     %s\n", refTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Orig Timestamp:    %s\n", origTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Recv Timestamp:    %s\n", recvTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Xmit Timestamp:    %s\n", xmitTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("\nLocal time:        %s\n", time.Now().Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Server ref time:   %s\n", xmitTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("RTT:               %.3f ms\n", rtt.Seconds()*1000)
	fmt.Printf("Clock offset:      %.3f ms\n", offset*1000)
	fmt.Printf("      (local clock is %s)\n", offsetStr(offset))
}

// buildNTPRequest constructs a 48-byte NTP client request.
func buildNTPRequest() []byte {
	buf := make([]byte, 48)
	buf[0] = (4 << 3) | 3 // VN=4, Mode=3 (client)
	putNTPTimestamp(buf[40:48], time.Now())
	return buf
}

// sendNTPQuery sends the NTP request via standard UDP and returns the response.
func sendNTPQuery(server string, req []byte, timeout time.Duration) ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(server, "123"))
	if err != nil {
		return nil, fmt.Errorf("resolve NTP server: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial NTP server: %w", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("send NTP request: %w", err)
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read NTP response: %w", err)
	}

	return resp[:n], nil
}

func putNTPTimestamp(b []byte, t time.Time) {
	sec := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32(uint64(t.UnixNano()%1e9) * (1 << 32) / 1e9)
	binary.BigEndian.PutUint32(b[0:4], sec)
	binary.BigEndian.PutUint32(b[4:8], frac)
}

func ntpToTime(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	if sec == 0 {
		return time.Time{}
	}
	nanos := uint64(frac) * 1e9 / (1 << 32)
	return time.Unix(int64(sec)-ntpEpochOffset, int64(nanos))
}

func offsetStr(offset float64) string {
	if math.Abs(offset) < 0.001 {
		return "synced"
	}
	if offset > 0 {
		return fmt.Sprintf("%.1f ms fast", offset*1000)
	}
	return fmt.Sprintf("%.1f ms slow", -offset*1000)
}

func resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}
