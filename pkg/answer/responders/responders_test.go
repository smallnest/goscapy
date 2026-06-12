package responders

import (
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/packet"
)

func TestICMPEchoResponder(t *testing.T) {
	am := ICMPEchoResponder("lo")
	f := am.Funcs()

	// Build an echo request.
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.5")
	_ = ip.Set("dst", "192.168.1.1")
	_ = ip.Set("proto", layers.IPProtoICMP)
	icmp := layers.NewICMPEcho(0xABCD, 7)
	req := packet.NewFrom(ip, icmp, layers.NewRawWith([]byte("ping-payload")))

	if !f.IsRequest(req) {
		t.Fatal("IsRequest should accept echo request")
	}
	reply, ok := f.MakeReply(req)
	if !ok || reply == nil {
		t.Fatal("MakeReply failed")
	}

	rIP := reply.GetLayer("IP")
	rICMP := reply.GetLayer("ICMP")
	if rIP == nil || rICMP == nil {
		t.Fatal("reply missing layers")
	}
	// src/dst swapped.
	src, _ := rIP.Get("src")
	dst, _ := rIP.Get("dst")
	if ipString(src) != "192.168.1.1" || ipString(dst) != "192.168.1.5" {
		t.Errorf("addresses not swapped: src=%v dst=%v", src, dst)
	}
	// type = echo reply, id/seq preserved.
	typ, _ := rICMP.Get("type")
	if typ.(uint8) != layers.ICMPEchoReply {
		t.Errorf("reply type = %v, want EchoReply", typ)
	}
	id, _ := rICMP.Get("id")
	if id.(uint16) != 0xABCD {
		t.Errorf("id = %#x, want 0xABCD", id)
	}
	// payload preserved.
	if reply.GetLayer("Raw") == nil {
		t.Error("reply missing echo payload")
	}

	// Non-echo (e.g. dest-unreach) should be rejected.
	ip2 := layers.NewIP()
	_ = ip2.Set("proto", layers.IPProtoICMP)
	other := layers.NewICMP()
	_ = other.Set("type", layers.ICMPDestUnreach)
	if f.IsRequest(packet.NewFrom(ip2, other)) {
		t.Error("IsRequest should reject non-echo ICMP")
	}
}

func TestARPResponder(t *testing.T) {
	am := ARPResponder("lo", "192.168.1.1", "aa:bb:cc:dd:ee:ff")
	f := am.Funcs()
	if !am.Config().SendL2 {
		t.Error("ARP responder should send at L2")
	}

	// who-has 192.168.1.1
	eth := layers.NewEthernetWith("ff:ff:ff:ff:ff:ff", "11:22:33:44:55:66", layers.EtherTypeARP)
	arp := layers.NewARP()
	_ = arp.Set("op", layers.ARPWhoHas)
	_ = arp.Set("hwsrc", "11:22:33:44:55:66")
	_ = arp.Set("psrc", "192.168.1.50")
	_ = arp.Set("pdst", "192.168.1.1")
	req := packet.NewFrom(eth, arp)

	if !f.IsRequest(req) {
		t.Fatal("IsRequest should accept who-has for our IP")
	}
	reply, ok := f.MakeReply(req)
	if !ok {
		t.Fatal("MakeReply failed")
	}
	rArp := reply.GetLayer("ARP")
	op, _ := rArp.Get("op")
	if op.(uint16) != layers.ARPIsAt {
		t.Errorf("reply op = %v, want is-at", op)
	}
	psrc, _ := rArp.Get("psrc")
	if ipString(psrc) != "192.168.1.1" {
		t.Errorf("reply psrc = %v, want 192.168.1.1", psrc)
	}
	hwsrc, _ := rArp.Get("hwsrc")
	if hwString(hwsrc) != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("reply hwsrc = %v", hwsrc)
	}

	// who-has for a different IP should be rejected.
	arp2 := layers.NewARP()
	_ = arp2.Set("op", layers.ARPWhoHas)
	_ = arp2.Set("pdst", "10.0.0.99")
	if f.IsRequest(packet.NewFrom(eth, arp2)) {
		t.Error("IsRequest should reject who-has for other IPs")
	}
}

func TestDNSResponder(t *testing.T) {
	resolver := StaticDNSResolver(map[string]string{
		"example.com": "93.184.216.34",
		"Foo.Local":   "10.0.0.9",
	}, 300)
	am := DNSResponder("lo", resolver)
	f := am.Funcs()

	// Build a DNS query for example.com A.
	ip := layers.NewIP()
	_ = ip.Set("src", "192.168.1.5")
	_ = ip.Set("dst", "192.168.1.1")
	_ = ip.Set("proto", layers.IPProtoUDP)
	udp := layers.NewUDP()
	_ = udp.Set("sport", uint16(40000))
	_ = udp.Set("dport", uint16(53))
	dnsq := dns.NewDNS()
	_ = dnsq.Set("id", uint16(0x1234))
	_ = dnsq.Set("flags", uint16(0x0100)) // RD=1, QR=0
	_ = dnsq.Set("qdcount", uint16(1))
	_ = dnsq.Set("data", dns.BuildDNSMessage([]dns.DNSQuestion{
		{Name: "example.com", Type: dns.QtypeA, Class: dns.QclassIN},
	}, nil, nil, nil))
	req := packet.NewFrom(ip, udp, dnsq)

	if !f.IsRequest(req) {
		t.Fatal("IsRequest should accept DNS query")
	}
	reply, ok := f.MakeReply(req)
	if !ok || reply == nil {
		t.Fatal("MakeReply failed")
	}

	rDNS := reply.GetLayer("DNS")
	if rDNS == nil {
		t.Fatal("reply missing DNS")
	}
	id, _ := rDNS.Get("id")
	if id.(uint16) != 0x1234 {
		t.Errorf("reply id = %#x, want 0x1234", id)
	}
	flags, _ := rDNS.Get("flags")
	if flags.(uint16)&0x8000 == 0 {
		t.Error("reply QR bit not set")
	}
	an, _ := rDNS.Get("ancount")
	if an.(uint16) != 1 {
		t.Errorf("ancount = %d, want 1", an)
	}
	// Verify the answer RR resolves to the expected IP.
	answers, err := dns.GetAnswers(rDNS)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("got %d answers, want 1", len(answers))
	}
	gotIP := net.IP(answers[0].RData).String()
	if gotIP != "93.184.216.34" {
		t.Errorf("answer IP = %s, want 93.184.216.34", gotIP)
	}

	// Reply UDP ports must be swapped (sport=53).
	rUDP := reply.GetLayer("UDP")
	sp, _ := rUDP.Get("sport")
	dp, _ := rUDP.Get("dport")
	if sp.(uint16) != 53 || dp.(uint16) != 40000 {
		t.Errorf("ports not swapped: sport=%v dport=%v", sp, dp)
	}

	// Unknown name → no reply.
	dnsq2 := dns.NewDNS()
	_ = dnsq2.Set("qdcount", uint16(1))
	_ = dnsq2.Set("data", dns.BuildDNSMessage([]dns.DNSQuestion{
		{Name: "unknown.test", Type: dns.QtypeA, Class: dns.QclassIN},
	}, nil, nil, nil))
	if _, ok := f.MakeReply(packet.NewFrom(ip, udp, dnsq2)); ok {
		t.Error("MakeReply should skip unknown names")
	}
}

func TestStaticDNSResolverCaseInsensitive(t *testing.T) {
	r := StaticDNSResolver(map[string]string{"Example.COM": "1.2.3.4"}, 60)
	if _, _, ok := r("example.com.", dns.QtypeA); !ok {
		t.Error("resolver should match case-insensitively with trailing dot")
	}
	if _, _, ok := r("example.com", dns.QtypeAAAA); ok {
		t.Error("resolver should only answer A queries")
	}
}
