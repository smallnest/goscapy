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
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/fields"
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
	offerPkt := waitForDHCP(ifaceVal, xid, dhcp.DHCPOFFER, 3*time.Second)
	if offerPkt == nil {
		fmt.Println("  未收到 DHCP Offer (超时)")
		os.Exit(1)
	}

	dhcpLayer := offerPkt.GetLayer("DHCP")
	yiaddrVal, _ := dhcpLayer.Get("yiaddr")
	yiaddr := yiaddrVal.(net.IP).String()
	serverIP := getDHCPServerID(dhcpLayer)

	fmt.Printf("  收到 DHCP Offer!\n")
	fmt.Printf("  分配 IP: %s\n", yiaddr)
	fmt.Printf("  DHCP 服务器: %s\n\n", serverIP)

	// Step 2: DHCP Request (广播)
	fmt.Println("[2/4] 发送 DHCP Request (广播)...")
	requestPkt := buildDHCPRequest(xid, mac, yiaddr, serverIP)
	err = sendrecv.Sendp(requestPkt, ifaceVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "发送 Request 失败: %v\n", err)
		os.Exit(1)
	}

	// 等待 DHCP ACK
	ackPkt := waitForDHCP(ifaceVal, xid, dhcp.DHCPACK, 5*time.Second)
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
	opts := []fields.TLVOption{
		dhcp.NewMessageTypeOption(dhcp.DHCPREQUEST),
		dhcp.NewRequestedIPOption(requestedIP),
		dhcp.NewServerIDOption(serverID),
	}
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
			Options(dhcp.BuildDHCPOptions(opts))).
		Packet()
}

func waitForDHCP(iface string, xid uint32, expectedType uint8, timeout time.Duration) *packet.Packet {
	rx, err := sendrecv.OpenReceiver(iface)
	if err != nil {
		return nil
	}
	defer rx.Close()

	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}

		pkt, err := rx.Recv(remaining)
		if err != nil {
			return nil
		}

		dhcpLayer := pkt.GetLayer("DHCP")
		if dhcpLayer == nil {
			continue
		}

		// Verify transaction ID
		xidVal, err := dhcpLayer.Get("xid")
		if err != nil || xidVal.(uint32) != xid {
			continue
		}

		optionsVal, err := dhcpLayer.Get("options")
		if err != nil {
			continue
		}
		optionsBytes, ok := optionsVal.([]byte)
		if !ok {
			continue
		}

		opts, err := dhcp.ParseDHCPOptions(optionsBytes)
		if err != nil {
			continue
		}

		msgType := dhcp.GetMessageType(opts)
		if msgType != expectedType {
			continue
		}

		return pkt
	}
}

func parseIPOption(opt *fields.TLVOption) string {
	if opt == nil || len(opt.Value) < 4 {
		return ""
	}
	return net.IP(opt.Value[:4]).String()
}

func parseIPsOption(opt *fields.TLVOption) []string {
	if opt == nil || len(opt.Value)%4 != 0 {
		return nil
	}
	var ips []string
	for i := 0; i < len(opt.Value); i += 4 {
		ips = append(ips, net.IP(opt.Value[i:i+4]).String())
	}
	return ips
}

func parseUint32Option(opt *fields.TLVOption) uint32 {
	if opt == nil || len(opt.Value) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(opt.Value[:4])
}

func getDHCPServerID(layer *packet.Layer) string {
	// First check Option 54 (Server Identifier)
	if optVal, err := layer.Get("options"); err == nil {
		if optBytes, ok := optVal.([]byte); ok {
			if opts, err := dhcp.ParseDHCPOptions(optBytes); err == nil {
				if serverIDOpt := dhcp.GetDHCPOption(opts, dhcp.OptServerID); serverIDOpt != nil {
					return parseIPOption(serverIDOpt)
				}
			}
		}
	}
	// Fallback to siaddr field
	if siaddr, err := layer.Get("siaddr"); err == nil && siaddr != nil {
		if ip, ok := siaddr.(net.IP); ok {
			return ip.String()
		}
	}
	return "0.0.0.0"
}

func parseDHCPOptions(layer *packet.Layer) {
	fmt.Println("\n--- DHCP 配置信息 ---")

	optVal, err := layer.Get("options")
	if err != nil {
		return
	}
	optBytes, ok := optVal.([]byte)
	if !ok {
		return
	}
	opts, err := dhcp.ParseDHCPOptions(optBytes)
	if err != nil {
		return
	}

	if subnetOpt := dhcp.GetDHCPOption(opts, dhcp.OptSubnetMask); subnetOpt != nil {
		fmt.Printf("  子网掩码: %s\n", parseIPOption(subnetOpt))
	}
	if routerOpt := dhcp.GetDHCPOption(opts, dhcp.OptRouter); routerOpt != nil {
		fmt.Printf("  网关: %s\n", parseIPOption(routerOpt))
	}
	if dnsOpt := dhcp.GetDHCPOption(opts, dhcp.OptDNS); dnsOpt != nil {
		fmt.Printf("  DNS: %v\n", parseIPsOption(dnsOpt))
	}
	if leaseTimeOpt := dhcp.GetDHCPOption(opts, dhcp.OptLeaseTime); leaseTimeOpt != nil {
		lt := parseUint32Option(leaseTimeOpt)
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