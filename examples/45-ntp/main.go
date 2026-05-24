// 示例 45: NTP 层构建与解析
//
// 运行: go run main.go
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/ntp"
)

const ntpEpochOffset = 2208988800

func main() {
	fmt.Println("=== NTP 层示例 ===")
	fmt.Println()

	// 1. 使用 Builder API 构建 NTP 客户端请求
	fmt.Println("--- 1. 构建 NTP 客户端请求 ---")
	n := goscapy.NewNTP().
		Mode(ntp.LINoWarning, 4, ntp.ModeClient).
		Stratum(0).
		Poll(4).
		XmitTimestamp(timeToNTP(time.Now()))

	pkt := goscapy.NewIP().
		SrcIP("192.168.1.100").
		DstIP("216.239.35.0").
		Over(goscapy.NewUDP().SrcPort(12345).DstPort(123)).
		Over(n)

	raw, err := pkt.Build()
	if err != nil {
		fmt.Printf("Build 失败: %v\n", err)
		return
	}
	fmt.Printf("  IP+UDP+NTP 数据包大小: %d bytes\n", len(raw))

	// 2. 手动构建 NTP 层
	fmt.Println("--- 2. 手动构建 NTP 层 ---")
	ntpLayer := ntp.NewNTP()
	ntpLayer.Set("lvm", ntp.SetLVM(ntp.LINoWarning, 4, ntp.ModeClient))
	ntpLayer.Set("stratum", uint8(0))
	ntpLayer.Set("poll", uint8(4))
	ntpLayer.Set("xtimestamp", timeToNTP(time.Now()))

	data, err := ntpLayer.SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	fmt.Printf("  NTP 包大小: %d bytes\n", len(data))
	fmt.Printf("  LI=%d VN=%d Mode=%d\n",
		ntp.LI(data[0]),
		ntp.VN(data[0]),
		ntp.Mode(data[0]))

	// 3. 解析 NTP 响应
	fmt.Println("--- 3. 模拟解析 NTP 服务器响应 ---")
	resp := make([]byte, 48)
	resp[0] = ntp.SetLVM(ntp.LINoWarning, 4, ntp.ModeServer)
	resp[1] = 2 // stratum 2
	resp[2] = 4 // poll
	resp[3] = 0xEC // precision = -20
	binary.BigEndian.PutUint32(resp[4:8], 0x00010000)   // root delay = 1s
	binary.BigEndian.PutUint32(resp[8:12], 0x00008000)  // root dispersion
	binary.BigEndian.PutUint32(resp[12:16], 0x475A4953) // refid "GZIS"
	now := timeToNTP(time.Now())
	binary.BigEndian.PutUint64(resp[16:24], now)         // ref timestamp
	binary.BigEndian.PutUint64(resp[24:32], now)         // orig timestamp
	binary.BigEndian.PutUint64(resp[32:40], now)         // recv timestamp
	binary.BigEndian.PutUint64(resp[40:48], now)         // xmit timestamp

	parsed := ntp.NewNTP()
	consumed, err := parsed.ParseFields(resp)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	fmt.Printf("  解析消耗: %d bytes\n", consumed)

	lvm, _ := parsed.Get("lvm")
	fmt.Printf("  LI=%d VN=%d Mode=%d\n",
		ntp.LI(lvm.(uint8)),
		ntp.VN(lvm.(uint8)),
		ntp.Mode(lvm.(uint8)))

	stratum, _ := parsed.Get("stratum")
	fmt.Printf("  Stratum: %d\n", stratum.(uint8))

	poll, _ := parsed.Get("poll")
	fmt.Printf("  Poll: %d\n", poll.(uint8))

	xts, _ := parsed.Get("xtimestamp")
	xmitTime := ntpToTime(xts.(uint64))
	fmt.Printf("  Xmit Timestamp: %s\n", xmitTime.Format("2006-01-02 15:04:05.000"))

	// 4. 构建 IP+UDP+NTP 并解剖
	fmt.Println("--- 4. 构建 IP+UDP+NTP 并解剖 ---")
	ip := layers.NewIP()
	ip.Set("src", mustParseIP("10.0.0.1"))
	ip.Set("dst", mustParseIP("10.0.0.2"))
	udp := layers.NewUDP()
	udp.Set("sport", uint16(12345))
	udp.Set("dport", uint16(123))

	fullPkt := ip.Over(udp)
	ntpL := ntp.NewNTP()
	ntpL.Set("lvm", ntp.SetLVM(ntp.LINoWarning, 4, ntp.ModeClient))
	fullPkt.Push(ntpL)

	raw, err = fullPkt.Build()
	if err != nil {
		fmt.Printf("Build 失败: %v\n", err)
		return
	}
	fmt.Printf("  完整 IP+UDP+NTP: %d bytes\n", len(raw))
}

func timeToNTP(t time.Time) uint64 {
	sec := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32(uint64(t.Nanosecond()) * (1 << 32) / 1e9)
	return uint64(sec)<<32 | uint64(frac)
}

func ntpToTime(ntpTs uint64) time.Time {
	sec := uint32(ntpTs >> 32)
	frac := uint32(ntpTs & 0xFFFFFFFF)
	if sec == 0 {
		return time.Time{}
	}
	nanos := uint64(frac) * 1e9 / (1 << 32)
	return time.Unix(int64(sec)-ntpEpochOffset, int64(nanos))
}

func mustParseIP(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid IP: " + s)
	}
	return ip.To4()
}
