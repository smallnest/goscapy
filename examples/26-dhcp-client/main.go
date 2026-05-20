// 示例 26: DHCP 客户端
//
// 本示例演示如何使用 goscapy 实现 DHCP DORA 交互流程，从 DHCP 服务器获取 IP。
// 你将学到:
//   - DHCP Discover/Offer/Request/ACK 四步交互
//   - 广播和单播 DHCP 消息的区别
//   - DHCP option 的解析
//
// 运行方式: sudo go run main.go [选项]
// 示例:     sudo go run main.go
//           sudo go run main.go -iface en0
//
// ⚠️  需要 root 权限 (sudo) 或 CAP_NET_RAW 能力。

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dhcp"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	iface := flag.String("iface", "", "网络接口 (默认自动选择)")
	flag.Parse()

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	mac := getMAC(ifaceVal)
	if mac == nil {
		fmt.Fprintf(os.Stderr, "无法获取接口 %s 的 MAC 地址\n", ifaceVal)
		os.Exit(1)
	}

	xid := rand.Uint32()

	fmt.Printf("=== DHCP 客户端 ===\n")
	fmt.Printf("接口: %s, MAC: %s\n\n", ifaceVal, formatMAC(mac))

	// Step 1: DHCP Discover (广播)
	fmt.Println("[1/4] 发送 DHCP Discover (广播)...")
	discoverPkt := buildDHCPDiscover(xid, mac)
	err := sendrecv.Sendp(discoverPkt, ifaceVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "发送 Discover 失败: %v\n", err)
		os.Exit(1)
	}

	// 等待 DHCP Offer
	offerPkt := waitForDHCP(ifaceVal, dhcp.DHCPOFFER, 3*time.Second)
	if offerPkt == nil {
		fmt.Println("  未收到 DHCP Offer (超时)")
		os.Exit(1)
	}

	dhcpLayer := offerPkt.GetLayer("DHCP")
	yiaddr, _ := dhcpLayer.Get("yiaddr")
	serverIP := getDHCPServerID(dhcpLayer)

	fmt.Printf("  收到 DHCP Offer!\n")
	fmt.Printf("  分配 IP: %s\n", yiaddr)
	fmt.Printf("  DHCP 服务器: %s\n\n", serverIP)

	// Step 2: DHCP Request (广播)
	fmt.Println("[2/4] 发送 DHCP Request (广播)...")
	requestPkt := buildDHCPRequest(xid, mac, yiaddr.(string), serverIP)
	err = sendrecv.Sendp(requestPkt, ifaceVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "发送 Request 失败: %v\n", err)
		os.Exit(1)
	}

	// 等待 DHCP ACK
	ackPkt := waitForDHCP(ifaceVal, dhcp.DHCPACK, 5*time.Second)
	if ackPkt == nil {
		fmt.Println("  未收到 DHCP ACK (超时)")
		os.Exit(1)
	}

	ackLayer := ackPkt.GetLayer("DHCP")
	assignedIP, _ := ackLayer.Get("yiaddr")

	fmt.Printf("  收到 DHCP ACK!\n")
	fmt.Printf("  分配 IP: %s\n", assignedIP)

	// 解析 DHCP Options
	parseDHCPOptions(ackLayer)

	fmt.Println("\n=== DHCP DORA 流程完成 ===")
}

func buildDHCPDiscover(xid uint32, chaddr []byte) *packet.Packet {
	return goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").
		SrcMAC(formatMAC(chaddr)).
		Type(layers.EtherTypeIPv4).
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP("255.255.255.255").
			TTL(64).
			Proto(layers.IPProtoUDP)).
		Over(goscapy.NewUDP().
			SrcPort(68).
			DstPort(67)).
		Over(goscapy.NewDHCP().
			Op(1). // BOOTREQUEST
			XID(xid).
			CHAddr(chaddr).
			MessageType(dhcp.DHCPDISCOVER)).
		Packet()
}

func buildDHCPRequest(xid uint32, chaddr []byte, requestedIP, serverID string) *packet.Packet {
	return goscapy.NewEthernet().
		DstMAC("ff:ff:ff:ff:ff:ff").
		SrcMAC(formatMAC(chaddr)).
		Type(layers.EtherTypeIPv4).
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP("255.255.255.255").
			TTL(64).
			Proto(layers.IPProtoUDP)).
		Over(goscapy.NewUDP().
			SrcPort(68).
			DstPort(67)).
		Over(goscapy.NewDHCP().
			Op(1).
			XID(xid).
			CHAddr(chaddr).
			MessageType(dhcp.DHCPREQUEST)).
		Packet()
}

func waitForDHCP(iface string, expectedType uint8, timeout time.Duration) *packet.Packet {
	rx, err := sendrecv.OpenReceiver(iface)
	if err != nil {
		return nil
	}
	defer rx.Close()

	pkt, err := rx.Recv(timeout)
	if err != nil {
		return nil
	}

	dhcpLayer := pkt.GetLayer("DHCP")
	if dhcpLayer == nil {
		return nil
	}

	msgType, _ := dhcpLayer.Get("msg_type")
	if msgType == nil {
		return nil
	}

	if msgType.(uint8) != expectedType {
		return nil
	}

	return pkt
}

func getDHCPServerID(layer *packet.Layer) string {
	if siaddr, err := layer.Get("siaddr"); err == nil && siaddr != nil {
		return siaddr.(string)
	}
	return "0.0.0.0"
}

func parseDHCPOptions(layer *packet.Layer) {
	fmt.Println("\n--- DHCP 配置信息 ---")

	if subnet, err := layer.Get("subnet_mask"); err == nil && subnet != nil {
		fmt.Printf("  子网掩码: %s\n", subnet)
	}
	if router, err := layer.Get("router"); err == nil && router != nil {
		fmt.Printf("  网关: %s\n", router)
	}
	if dns, err := layer.Get("dns"); err == nil && dns != nil {
		fmt.Printf("  DNS: %s\n", dns)
	}
	if leaseTime, err := layer.Get("lease_time"); err == nil && leaseTime != nil {
		lt := leaseTime.(uint32)
		fmt.Printf("  租约时间: %d 秒 (%d 小时)\n", lt, lt/3600)
	}
	if yiaddr, err := layer.Get("yiaddr"); err == nil && yiaddr != nil {
		fmt.Printf("  分配 IP: %s\n", yiaddr)
	}
}

func getMAC(iface string) []byte {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	return i.HardwareAddr
}

func formatMAC(b []byte) string {
	if len(b) < 6 {
		return "00:00:00:00:00:00"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
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