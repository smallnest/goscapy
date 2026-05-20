package sendrecv

import (
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dhcp"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Helper: build an IP/ICMP packet with the given dst, id, and seq.
func buildICMPPacket(dst string, id, seq uint16) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("dst", net.ParseIP(dst))
	ip.Set("src", net.ParseIP("10.0.0.1"))
	icmp := layers.NewICMPEcho(id, seq)
	return ip.Over(icmp)
}

// Helper: build an IP/TCP packet with the given addresses, ports, seq, and flags.
func buildTCPPacket(src, dst string, sport, dport uint16, seq uint32, flags uint8) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", net.ParseIP(src))
	ip.Set("dst", net.ParseIP(dst))
	tcp := layers.NewTCPWith(sport, dport, flags)
	tcp.Set("seq", seq)
	return ip.Over(tcp)
}

// Helper: build an IP/UDP packet with the given addresses and ports.
func buildUDPPacket(src, dst string, sport, dport uint16) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", net.ParseIP(src))
	ip.Set("dst", net.ParseIP(dst))
	udp := layers.NewUDPWith(sport, dport)
	return ip.Over(udp)
}

// Helper: build an IP/UDP/DNS packet with the given transaction ID.
func buildDNSPacket(src, dst string, id uint16) *packet.Packet {
	ip := layers.NewIP()
	ip.Set("src", net.ParseIP(src))
	ip.Set("dst", net.ParseIP(dst))
	udp := layers.NewUDPWith(53, 53)
	dnsLayer := dns.NewDNS()
	dnsLayer.Set("id", id)
	return packet.NewFrom(ip, udp, dnsLayer)
}

func TestDefaultMatchICMPMatch(t *testing.T) {
	sent := buildICMPPacket("8.8.8.8", 0x1234, 1)
	// Build a matching reply: src == sent's dst, type=EchoReply, same id.
	replyIP := layers.NewIP()
	replyIP.Set("src", net.ParseIP("8.8.8.8"))
	replyIP.Set("dst", net.ParseIP("10.0.0.1"))
	replyICMP := layers.NewICMP()
	replyICMP.Set("type", uint8(0)) // Echo Reply
	replyICMP.Set("id", uint16(0x1234))
	replyICMP.Set("seq", uint16(1))
	reply := packet.NewFrom(replyIP, replyICMP)

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for correct ICMP Echo Reply")
	}
}

func TestDefaultMatchICMPWrongID(t *testing.T) {
	sent := buildICMPPacket("8.8.8.8", 0x1234, 1)
	replyIP := layers.NewIP()
	replyIP.Set("src", net.ParseIP("8.8.8.8"))
	replyICMP := layers.NewICMP()
	replyICMP.Set("type", uint8(0))
	replyICMP.Set("id", uint16(0x5678)) // different id
	reply := packet.NewFrom(replyIP, replyICMP)

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for ICMP reply with wrong id")
	}
}

func TestDefaultMatchICMPWrongSrc(t *testing.T) {
	sent := buildICMPPacket("8.8.8.8", 0x1234, 1)
	replyIP := layers.NewIP()
	replyIP.Set("src", net.ParseIP("1.1.1.1")) // not the sent dst
	replyICMP := layers.NewICMP()
	replyICMP.Set("type", uint8(0))
	replyICMP.Set("id", uint16(0x1234))
	reply := packet.NewFrom(replyIP, replyICMP)

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for ICMP reply from wrong source")
	}
}

func TestDefaultMatchICMPNotEchoReply(t *testing.T) {
	sent := buildICMPPacket("8.8.8.8", 0x1234, 1)
	replyIP := layers.NewIP()
	replyIP.Set("src", net.ParseIP("8.8.8.8"))
	replyICMP := layers.NewICMP()
	replyICMP.Set("type", uint8(13)) // Timestamp, neither Echo Reply nor error
	replyICMP.Set("id", uint16(0x1234))
	reply := packet.NewFrom(replyIP, replyICMP)

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for non-Echo-Reply, non-error ICMP type")
	}
}

func TestDefaultMatchTCPMatch(t *testing.T) {
	sent := buildTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, 0x02) // SYN
	reply := buildTCPPacket("10.0.0.2", "10.0.0.1", 80, 12345, 5000, 0x12) // SYN-ACK, ack=1001
	reply.GetLayer("TCP").Set("ack", uint32(1001))

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for correct TCP SYN-ACK")
	}
}

func TestDefaultMatchTCPWrongAck(t *testing.T) {
	sent := buildTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, 0x02)
	reply := buildTCPPacket("10.0.0.2", "10.0.0.1", 80, 12345, 5000, 0x12)
	reply.GetLayer("TCP").Set("ack", uint32(999)) // wrong ack

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for TCP SYN-ACK with wrong ack")
	}
}

func TestDefaultMatchTCPNoSynAck(t *testing.T) {
	sent := buildTCPPacket("10.0.0.1", "10.0.0.2", 12345, 80, 1000, 0x02)
	reply := buildTCPPacket("10.0.0.2", "10.0.0.1", 80, 12345, 5000, 0x04) // RST, not SYN-ACK
	reply.GetLayer("TCP").Set("ack", uint32(1001))

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for non-SYN-ACK TCP response")
	}
}

func TestDefaultMatchUDPMatch(t *testing.T) {
	sent := buildUDPPacket("10.0.0.1", "10.0.0.2", 12345, 53)
	reply := buildUDPPacket("10.0.0.2", "10.0.0.1", 53, 12345)

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for correct UDP reply with swapped ports")
	}
}

func TestDefaultMatchUDPWrongPorts(t *testing.T) {
	sent := buildUDPPacket("10.0.0.1", "10.0.0.2", 12345, 53)
	reply := buildUDPPacket("10.0.0.2", "10.0.0.1", 9999, 12345)

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for UDP reply with wrong source port")
	}
}

func TestDefaultMatchDNSMatch(t *testing.T) {
	sent := buildDNSPacket("10.0.0.1", "8.8.8.8", 0xABCD)
	reply := buildDNSPacket("8.8.8.8", "10.0.0.1", 0xABCD)

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for DNS reply with same transaction ID")
	}
}

func TestDefaultMatchDNSWrongID(t *testing.T) {
	sent := buildDNSPacket("10.0.0.1", "8.8.8.8", 0xABCD)
	reply := buildDNSPacket("8.8.8.8", "10.0.0.1", 0x1234)

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for DNS reply with different transaction ID")
	}
}

// ---- ARP tests ----

func buildARPPacket(op uint16, psrc, pdst string) *packet.Packet {
	arp := layers.NewARP()
	arp.Set("op", op)
	arp.Set("psrc", net.ParseIP(psrc))
	arp.Set("pdst", net.ParseIP(pdst))
	return packet.NewFrom(arp)
}

func TestDefaultMatchARPMatch(t *testing.T) {
	sent := buildARPPacket(1, "10.0.0.1", "10.0.0.2") // who-has 10.0.0.2
	reply := buildARPPacket(2, "10.0.0.2", "10.0.0.1") // is-at, psrc=10.0.0.2, pdst=10.0.0.1

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for correct ARP reply")
	}
}

func TestDefaultMatchARPWrongOp(t *testing.T) {
	sent := buildARPPacket(1, "10.0.0.1", "10.0.0.2")
	reply := buildARPPacket(1, "10.0.0.2", "10.0.0.1") // also who-has, not is-at

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for ARP request as reply to ARP request")
	}
}

func TestDefaultMatchARPWrongIP(t *testing.T) {
	sent := buildARPPacket(1, "10.0.0.1", "10.0.0.2") // asking for 10.0.0.2
	reply := buildARPPacket(2, "10.0.0.3", "10.0.0.1") // replying from 10.0.0.3

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for ARP reply from wrong IP")
	}
}

// ---- DHCP tests ----

func buildDHCPPacket(op uint8, xid uint32) *packet.Packet {
	dhcpLayer := dhcp.NewDHCP()
	dhcpLayer.Set("op", op)
	dhcpLayer.Set("xid", xid)
	return packet.NewFrom(dhcpLayer)
}

func TestDefaultMatchDHCPMatch(t *testing.T) {
	sent := buildDHCPPacket(1, 0xDEADBEEF)   // BOOTREQUEST
	reply := buildDHCPPacket(2, 0xDEADBEEF)  // BOOTREPLY, same xid

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for DHCP reply with same xid")
	}
}

func TestDefaultMatchDHCPWrongXid(t *testing.T) {
	sent := buildDHCPPacket(1, 0xDEADBEEF)
	reply := buildDHCPPacket(2, 0xCAFEBABE) // different xid

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for DHCP reply with different xid")
	}
}

func TestDefaultMatchDHCPWrongOp(t *testing.T) {
	sent := buildDHCPPacket(1, 0xDEADBEEF)
	reply := buildDHCPPacket(1, 0xDEADBEEF) // also BOOTREQUEST

	match := DefaultMatch(sent)
	if match(sent, reply) {
		t.Fatal("expected no match for BOOTREQUEST as reply to BOOTREQUEST")
	}
}

// ---- ICMP error tests ----

func TestDefaultMatchICMPDestUnreach(t *testing.T) {
	// ICMP Dest Unreachable (type=3) is a valid response to an Echo Request.
	sent := buildICMPPacket("8.8.8.8", 0x1234, 1)
	replyIP := layers.NewIP()
	replyIP.Set("src", net.ParseIP("8.8.8.8"))
	replyICMP := layers.NewICMP()
	replyICMP.Set("type", uint8(3)) // Dest Unreachable
	reply := packet.NewFrom(replyIP, replyICMP)

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for ICMP Dest Unreachable as response to Echo Request")
	}
}

func TestDefaultMatchICMPTimeExceeded(t *testing.T) {
	// ICMP Time Exceeded (type=11) is a valid response to an Echo Request.
	sent := buildICMPPacket("8.8.8.8", 0x1234, 1)
	replyIP := layers.NewIP()
	replyIP.Set("src", net.ParseIP("8.8.8.8")) // from target or router on path
	replyICMP := layers.NewICMP()
	replyICMP.Set("type", uint8(11)) // Time Exceeded
	reply := packet.NewFrom(replyIP, replyICMP)

	match := DefaultMatch(sent)
	if !match(sent, reply) {
		t.Fatal("expected match for ICMP Time Exceeded as response to Echo Request")
	}
}