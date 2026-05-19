// 示例 08: VLAN (802.1Q) 标签包构建示例
//
// 本示例演示如何在 Ethernet 帧上添加 VLAN 标签。
// 你将学到:
//   - VLAN 在网络隔离中的作用
//   - 如何使用 Dot1Q Builder 添加 VLAN 标签
//   - VID (VLAN ID)、PCP (优先级)、DEI (丢弃指示) 的含义
//   - 如何构建带 VLAN 标签的完整数据包
//
// 运行方式: go run main.go
// 注意: 本示例仅构建数据包，不需要 root 权限。

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

func main() {
	fmt.Println("=== goscapy 示例 08: VLAN (802.1Q) 标签包构建 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// VLAN 简介
	// -----------------------------------------------------------------------
	// VLAN (Virtual Local Area Network) 在交换机上划分虚拟网络。
	// 802.1Q 标签插在 Ethernet 头和上层协议之间 (4 字节):
	//
	//   [Ethernet 头 (14B)] [802.1Q 标签 (4B)] [上层协议 (如 IP)]
	//
	// 802.1Q 标签结构 (TCI - Tag Control Information):
	//   - PCP  (3 bit): Priority Code Point, 优先级 (0-7)
	//   - DEI  (1 bit):  Drop Eligible Indicator, 可丢弃标志
	//   - VID (12 bit): VLAN ID, 虚拟网络编号 (1-4094)

	// -----------------------------------------------------------------------
	// 第一部分: 基本带 VLAN 标签的包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: Ethernet + VLAN + IP + TCP ---")
	fmt.Println()

	// Ethernet → Dot1Q → IP → TCP 的协议栈
	vlanPkt := goscapy.NewEthernet().
		DstMAC("00:aa:bb:cc:dd:ee").
		SrcMAC("00:11:22:33:44:55").
		Type(0x8100).                         // TPID: 802.1Q
		Over(goscapy.NewDot1Q().
			VID(100).                          // VLAN ID: 100
			PCP(5).                            // 优先级: 5 (高优先级)
			DEI(false).                        // 不可丢弃
			Type(layers.EtherTypeIPv4)).       // 内层 EtherType: IPv4
		Over(goscapy.NewIP().
			SrcIP("192.168.100.10").           // VLAN 100 内的 IP
			DstIP("192.168.100.20").
			TTL(64).
			Proto(layers.IPProtoTCP)).
		Over(goscapy.NewTCP().
			SrcPort(12345).
			DstPort(80).
			Flags(layers.TCPSyn))

	vlanBytes, err := vlanPkt.Build()
	if err != nil {
		log.Fatalf("构建 VLAN 包失败: %v", err)
	}

	fmt.Printf("VLAN 标签包构建成功!\n")
	fmt.Printf("  VLAN ID: 100\n")
	fmt.Printf("  优先级: 5 (高)\n")
	fmt.Printf("  总长度: %d 字节 (比普通包多 4 字节 VLAN 标签)\n", len(vlanBytes))
	fmt.Printf("  Hex dump:\n%s\n", hex.Dump(vlanBytes))

	// -----------------------------------------------------------------------
	// 第二部分: 不同 VLAN ID 的包
	// -----------------------------------------------------------------------
	fmt.Println("--- 第二部分: 不同 VLAN 的包对比 ---")
	fmt.Println()

	// 使用 Shortcut 函数快速创建带 VLAN 的包
	vlan1Bytes, err := goscapy.EtherDot1QIP(
		"00:11:22:33:44:55",   // 源 MAC
		"00:aa:bb:cc:dd:ee",   // 目标 MAC
		"192.168.10.1",         // 源 IP
		"192.168.10.2",         // 目标 IP
		10,                     // VLAN ID: 10
	)
	if err != nil {
		log.Fatalf("构建 VLAN 10 包失败: %v", err)
	}

	vlan2Bytes, err := goscapy.EtherDot1QIP(
		"00:11:22:33:44:55",
		"00:aa:bb:cc:dd:ee",
		"192.168.20.1",
		"192.168.20.2",
		20,                     // VLAN ID: 20
	)
	if err != nil {
		log.Fatalf("构建 VLAN 20 包失败: %v", err)
	}

	fmt.Printf("VLAN 10 的包: %d 字节\n", len(vlan1Bytes))
	fmt.Printf("VLAN 20 的包: %d 字节\n", len(vlan2Bytes))
	fmt.Println()
	fmt.Println("注意: 不同 VLAN 的包大小相同，只是 VLAN ID 字段不同。")
	fmt.Println("交换机根据 VLAN ID 将流量隔离到不同的虚拟网络中。")
	fmt.Println()

	// -----------------------------------------------------------------------
	// VLAN 字段参考
	// -----------------------------------------------------------------------
	fmt.Println("--- VLAN 字段参考 ---")
	fmt.Println()
	fmt.Println("  VID: VLAN ID (0-4095)")
	fmt.Println("       0 = 优先级标签 (空 VLAN)")
	fmt.Println("       1 = 默认 VLAN")
	fmt.Println("       2-4094 = 用户可用")
	fmt.Println("       4095 = 保留")
	fmt.Println()
	fmt.Println("  PCP: Priority Code Point (0-7)")
	fmt.Println("       0 = 尽力而为 (Best Effort)")
	fmt.Println("       1 = 背景 (Background)")
	fmt.Println("       2 = 备用 (Spare)")
	fmt.Println("       3 = 尽力而为 (Excellent Effort)")
	fmt.Println("       4 = 受控负载 (Controlled Load)")
	fmt.Println("       5 = 视频 (Video)")
	fmt.Println("       6 = 语音 (Voice)")
	fmt.Println("       7 = 网络控制 (Network Control)")
	fmt.Println()
	fmt.Println("  DEI: Drop Eligible Indicator")
	fmt.Println("       false = 正常 (不可丢弃)")
	fmt.Println("       true = 拥塞时可丢弃")
	fmt.Println()
	fmt.Println("下一步: 运行 09-gre-vxlan 示例，学习隧道封装")
}
