// 示例 39: IP 分片重组
//
// 本示例演示 goscapy 的 IP 分片重组功能:
//   - 手动创建分片包并提交给 Reassembler
//   - 观察乱序分片的正确重组
//   - 演示超时清理和 DoS 保护 (MaxGroups)
//
// 本示例不需要网络权限，纯内存操作。
//
// 运行方式: go run main.go

package main

import (
	"fmt"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/reassembly"
)

func main() {
	fmt.Println("=== IP 分片重组示例 ===")
	fmt.Println()

	demoBasicReassembly()
	demoOutOfOrderReassembly()
	demoTimeout()
	demoDoSProtection()
}

func demoBasicReassembly() {
	fmt.Println("--- 1. 基本两片重组 ---")

	r := reassembly.New(reassembly.WithTimeout(5 * time.Second))
	defer r.Close()

	// 模拟一个 24 字节的 ICMP 报文被拆成两个分片:
	// 分片 1: offset=0, MF=1, 16 字节 payload
	// 分片 2: offset=2 (16/8=2), MF=0, 8 字节 payload
	payload1 := make([]byte, 16)
	for i := range payload1 {
		payload1[i] = byte(i)
	}
	payload2 := make([]byte, 8)
	for i := range payload2 {
		payload2[i] = byte(i + 16)
	}

	frag1 := buildFragment("10.0.0.1", "10.0.0.2", 0x1234, layers.IPProtoICMP, 0, true, payload1)
	frag2 := buildFragment("10.0.0.1", "10.0.0.2", 0x1234, layers.IPProtoICMP, 2, false, payload2)

	fmt.Printf("  提交分片 1 (offset=0, MF=1, len=%d)...\n", len(payload1))
	result := r.Submit(frag1)
	fmt.Printf("    结果: %v (等待更多分片)\n", result)

	fmt.Printf("  提交分片 2 (offset=2, MF=0, len=%d)...\n", len(payload2))
	result = r.Submit(frag2)
	if result != nil {
		fmt.Printf("    重组成功! 层数: %d\n", result.Len())
		ipLayer := result.GetLayer("IP")
		if ipLayer != nil {
			src, _ := ipLayer.Get("src")
			dst, _ := ipLayer.Get("dst")
			fmt.Printf("    IP: %v -> %v\n", src, dst)
		}
	}
	fmt.Println()
}

func demoOutOfOrderReassembly() {
	fmt.Println("--- 2. 乱序分片重组 ---")

	r := reassembly.New(reassembly.WithTimeout(5 * time.Second))
	defer r.Close()

	// 3 个分片，每个 8 字节，按 2, 0, 1 的顺序提交
	payloads := [3][]byte{
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		{0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
	}

	frag0 := buildFragment("192.168.1.1", "192.168.1.2", 0xABCD, layers.IPProtoUDP, 0, true, payloads[0])
	frag1 := buildFragment("192.168.1.1", "192.168.1.2", 0xABCD, layers.IPProtoUDP, 1, true, payloads[1])
	frag2 := buildFragment("192.168.1.1", "192.168.1.2", 0xABCD, layers.IPProtoUDP, 2, false, payloads[2])

	fmt.Println("  发送顺序: frag2, frag0, frag1 (乱序)")

	fmt.Printf("  提交 frag2 (offset=2, MF=0): ")
	if r.Submit(frag2) == nil {
		fmt.Println("等待中...")
	}

	fmt.Printf("  提交 frag0 (offset=0, MF=1): ")
	if r.Submit(frag0) == nil {
		fmt.Println("等待中...")
	}

	fmt.Printf("  提交 frag1 (offset=1, MF=1): ")
	result := r.Submit(frag1)
	if result != nil {
		fmt.Println("重组完成!")
		fmt.Printf("    重组后包含 %d 层\n", result.Len())
	}
	fmt.Printf("  活跃分片组: %d\n\n", r.Stats())
}

func demoTimeout() {
	fmt.Println("--- 3. 超时清理 ---")

	r := reassembly.New(reassembly.WithTimeout(100 * time.Millisecond))
	defer r.Close()

	// 只发送第一个分片，不发送后续分片
	payload := make([]byte, 8)
	frag := buildFragment("10.0.0.1", "10.0.0.2", 99, layers.IPProtoTCP, 0, true, payload)

	fmt.Println("  提交一个不完整的分片...")
	r.Submit(frag)
	fmt.Printf("  活跃分片组: %d\n", r.Stats())

	fmt.Println("  等待超时 (150ms)...")
	time.Sleep(150 * time.Millisecond)

	fmt.Printf("  超时后活跃分片组: %d (已被 GC 清理)\n\n", r.Stats())
}

func demoDoSProtection() {
	fmt.Println("--- 4. DoS 保护 (MaxGroups) ---")

	r := reassembly.New(
		reassembly.WithTimeout(5*time.Second),
		reassembly.WithMaxGroups(3),
	)
	defer r.Close()

	fmt.Println("  MaxGroups=3, 尝试创建 5 个分片组...")

	for i := range 5 {
		before := r.Stats()
		frag := buildFragment("10.0.0.1", "10.0.0.2", uint16(i), layers.IPProtoICMP, 0, true, make([]byte, 8))
		r.Submit(frag)
		after := r.Stats()
		if after > before {
			fmt.Printf("  分片组 %d: 已接受 (活跃: %d)\n", i, after)
		} else {
			fmt.Printf("  分片组 %d: 被丢弃 (已达上限, 活跃: %d)\n", i, after)
		}
	}
	fmt.Printf("  最终活跃分片组: %d (不超过 MaxGroups=3)\n\n", r.Stats())
}

// buildFragment 创建一个 IP 分片包。
// offset 是以 8 字节为单位的偏移量，moreFragments 设置 MF 标志位。
func buildFragment(src, dst string, id uint16, proto uint8, offset uint16, moreFragments bool, payload []byte) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", src)
	ip.Set("dst", dst)
	ip.Set("id", id)
	ip.Set("proto", proto)

	flags := uint16(0)
	if moreFragments {
		flags = 0x01 << 13 // MF flag
	}
	frag := flags | (offset & 0x1FFF)
	ip.Set("frag", frag)
	ip.Set("len", uint16(20+len(payload)))

	raw := layers.NewRawWith(payload)
	return packet.NewFrom(ip, raw)
}
