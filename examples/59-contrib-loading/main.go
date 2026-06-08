// 示例 59: Contrib 模块系统 — 按需加载协议
//
// 本示例演示如何使用 goscapy 的 contrib 模块系统按需加载协议，
// 而非一次性加载所有协议。
//
// 功能:
//   - contrib.Register() / contrib.Load() 注册和加载协议模块
//   - contrib.LoadAll() 一次性加载所有已注册模块
//   - contrib.List() / contrib.Loaded() 查看模块状态
//   - 精简构建模式: 只导入需要的 contrib 包
//
// 运行方式: go run main.go

package main

import (
	"fmt"

	// Option 1: Full build — import all protocols via the layers package.
	// This loads everything (backward compatible).
	// _ "github.com/smallnest/goscapy/pkg/layers"

	// Option 2: Lean build — import only what you need.
	// Core protocols (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, DHCP,
	// Dot1Q, GRE, VXLAN) are loaded automatically when you import
	// github.com/smallnest/goscapy/pkg/layers.
	// For non-core protocols, import specific contrib packages:

	"github.com/smallnest/goscapy/pkg/contrib"
	_ "github.com/smallnest/goscapy/pkg/contrib/ospf"
	_ "github.com/smallnest/goscapy/pkg/contrib/bgp"
	_ "github.com/smallnest/goscapy/pkg/contrib/ntp"

	"github.com/smallnest/goscapy/pkg/layers/ospf"
	"github.com/smallnest/goscapy/pkg/packet"
)

func main() {
	fmt.Println("=== goscapy 示例 59: Contrib 模块系统 ===")
	fmt.Println()

	// -----------------------------------------------------------------------
	// 第一部分: 查看已注册的 contrib 模块
	// -----------------------------------------------------------------------
	fmt.Println("--- 第一部分: 已注册的 contrib 模块 ---")
	fmt.Println()

	registered := contrib.List()
	fmt.Printf("已注册 %d 个 contrib 模块:\n", len(registered))
	for _, name := range registered {
		fmt.Printf("  - %s (loaded: %v)\n", name, contrib.IsLoaded(name))
	}

	// -----------------------------------------------------------------------
	// 第二部分: 按需加载模块
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第二部分: 按需加载 ---")
	fmt.Println()

	// Load specific modules on demand
	if err := contrib.Load("ospf"); err != nil {
		fmt.Printf("加载 OSPF 失败: %v\n", err)
	} else {
		fmt.Println("OSPF 模块已加载")
	}

	if err := contrib.Load("bgp"); err != nil {
		fmt.Printf("加载 BGP 失败: %v\n", err)
	} else {
		fmt.Println("BGP 模块已加载")
	}

	// NTP is registered but not yet loaded
	fmt.Printf("NTP loaded: %v\n", contrib.IsLoaded("ntp"))

	// -----------------------------------------------------------------------
	// 第三部分: 使用已加载的协议
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第三部分: 使用已加载的协议 ---")
	fmt.Println()

	// OSPF is now available
	ospfLayer := ospf.NewOSPF()
	pkt := packet.NewFrom(ospfLayer)
	fmt.Printf("OSPF packet: %s\n", pkt)

	// -----------------------------------------------------------------------
	// 第四部分: 加载所有已注册模块
	// -----------------------------------------------------------------------
	fmt.Println()
	fmt.Println("--- 第四部分: 加载所有模块 ---")
	fmt.Println()

	contrib.LoadAll()

	loaded := contrib.Loaded()
	fmt.Printf("已加载 %d 个模块:\n", len(loaded))
	for _, name := range loaded {
		fmt.Printf("  - %s\n", name)
	}

	// NTP is now loaded
	fmt.Printf("NTP loaded: %v\n", contrib.IsLoaded("ntp"))
}
