// 示例 43: 路由表查询
//
// 本示例演示如何使用 goscapy 的路由表 API。
// 你将学到:
//   - 如何读取系统 IPv4/IPv6 路由表
//   - 如何查询到指定 IP 的路由（网关 + 接口）
//   - 如何获取默认路由
//   - 如何列出所有网络接口
//
// 运行: go run main.go
package main

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/route"
)

func main() {
	fmt.Println("=== 路由表查询示例 ===")
	fmt.Println()

	// 1. 读取 IPv4 路由表
	fmt.Println("--- 1. IPv4 路由表 ---")
	routes, err := route.Table4()
	if err != nil {
		fmt.Printf("读取路由表失败: %v\n", err)
		return
	}
	fmt.Printf("共 %d 条路由:\n", len(routes))
	for _, r := range routes {
		dst := "default"
		if r.Destination != nil {
			dst = r.Destination.String()
		}
		gw := "-"
		if r.Gateway != nil {
			gw = r.Gateway.String()
		}
		fmt.Printf("  %-20s via %-15s dev %-8s metric %d\n", dst, gw, r.Interface, r.Metric)
	}
	fmt.Println()

	// 2. 默认路由
	fmt.Println("--- 2. 默认路由 ---")
	def, err := route.DefaultRoute4()
	if err != nil {
		fmt.Printf("查询失败: %v\n", err)
	} else {
		fmt.Printf("  网关: %s\n", def.Gateway)
		fmt.Printf("  接口: %s\n", def.Interface)
	}
	fmt.Println()

	// 3. 路由查询: 到 8.8.8.8 走哪条路?
	fmt.Println("--- 3. 路由查询 ---")
	targets := []string{"8.8.8.8", "192.168.1.1", "127.0.0.1", "1.1.1.1"}
	for _, t := range targets {
		r, err := route.Route4(net.ParseIP(t))
		if err != nil {
			fmt.Printf("  %s: 无路由 (%v)\n", t, err)
			continue
		}
		gw := "直连"
		if r.Gateway != nil {
			gw = r.Gateway.String()
		}
		fmt.Printf("  %s → 网关 %-15s 接口 %s\n", t, gw, r.Interface)
	}
	fmt.Println()

	// 4. 网络接口列表
	fmt.Println("--- 4. 网络接口 ---")
	ifaces, err := route.Interfaces()
	if err != nil {
		fmt.Printf("查询失败: %v\n", err)
		return
	}
	for _, i := range ifaces {
		fmt.Printf("  %-8s index=%-3d mtu=%-5d addrs=%v\n",
			i.Name, i.Index, i.MTU, i.Addresses)
	}
}
