package bpf_test

import (
	"errors"
	"testing"

	"github.com/smallnest/goscapy/pkg/bpf"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// build returns the wire bytes of an Ethernet-framed packet.
func build(t *testing.T, p *packet.Packet) []byte {
	t.Helper()
	b, err := p.Build()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ethIPTCP(t *testing.T, src, dst string, sport, dport uint16) []byte {
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", src)
	_ = ip.Set("dst", dst)
	_ = ip.Set("proto", layers.IPProtoTCP)
	tcp := layers.NewTCP()
	_ = tcp.Set("sport", sport)
	_ = tcp.Set("dport", dport)
	return build(t, packet.NewFrom(eth, ip, tcp))
}

func ethIPUDP(t *testing.T, src, dst string, sport, dport uint16) []byte {
	eth := layers.NewEthernetWith("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", layers.EtherTypeIPv4)
	ip := layers.NewIP()
	_ = ip.Set("src", src)
	_ = ip.Set("dst", dst)
	_ = ip.Set("proto", layers.IPProtoUDP)
	udp := layers.NewUDP()
	_ = udp.Set("sport", sport)
	_ = udp.Set("dport", dport)
	return build(t, packet.NewFrom(eth, ip, udp))
}

func ethARP(t *testing.T) []byte {
	eth := layers.NewEthernetWith("ff:ff:ff:ff:ff:ff", "11:22:33:44:55:66", layers.EtherTypeARP)
	arp := layers.NewARP()
	_ = arp.Set("hwsrc", "11:22:33:44:55:66")
	_ = arp.Set("psrc", "192.168.1.1")
	_ = arp.Set("hwdst", "00:00:00:00:00:00")
	_ = arp.Set("pdst", "192.168.1.2")
	return build(t, packet.NewFrom(eth, arp))
}

func mustMatch(t *testing.T, filter string, pkt []byte, want bool) {
	t.Helper()
	prog, err := bpf.Compile(filter)
	if err != nil {
		t.Fatalf("Compile(%q): %v", filter, err)
	}
	got := bpf.Match(prog, pkt)
	if got != want {
		t.Errorf("filter %q match = %v, want %v", filter, got, want)
	}
}

func TestEtherTypeFilters(t *testing.T) {
	tcp := ethIPTCP(t, "192.168.1.1", "192.168.1.2", 1000, 80)
	arp := ethARP(t)

	mustMatch(t, "ip", tcp, true)
	mustMatch(t, "ip", arp, false)
	mustMatch(t, "arp", arp, true)
	mustMatch(t, "arp", tcp, false)
}

func TestProtoFilters(t *testing.T) {
	tcp := ethIPTCP(t, "192.168.1.1", "192.168.1.2", 1000, 80)
	udp := ethIPUDP(t, "192.168.1.1", "192.168.1.2", 1000, 53)

	mustMatch(t, "tcp", tcp, true)
	mustMatch(t, "tcp", udp, false)
	mustMatch(t, "udp", udp, true)
	mustMatch(t, "udp", tcp, false)
}

func TestHostFilters(t *testing.T) {
	pkt := ethIPTCP(t, "10.0.0.1", "10.0.0.2", 1000, 80)

	mustMatch(t, "host 10.0.0.1", pkt, true)
	mustMatch(t, "host 10.0.0.2", pkt, true)
	mustMatch(t, "host 10.0.0.3", pkt, false)
	mustMatch(t, "src host 10.0.0.1", pkt, true)
	mustMatch(t, "src host 10.0.0.2", pkt, false)
	mustMatch(t, "dst host 10.0.0.2", pkt, true)
	mustMatch(t, "dst host 10.0.0.1", pkt, false)
}

func TestPortFilters(t *testing.T) {
	pkt := ethIPTCP(t, "10.0.0.1", "10.0.0.2", 12345, 80)

	mustMatch(t, "port 80", pkt, true)
	mustMatch(t, "port 12345", pkt, true)
	mustMatch(t, "port 443", pkt, false)
	mustMatch(t, "src port 12345", pkt, true)
	mustMatch(t, "src port 80", pkt, false)
	mustMatch(t, "dst port 80", pkt, true)
	mustMatch(t, "tcp port 80", pkt, true)

	udp := ethIPUDP(t, "10.0.0.1", "10.0.0.2", 12345, 80)
	mustMatch(t, "udp port 80", udp, true)
	mustMatch(t, "tcp port 80", udp, false) // proto-restricted: UDP rejected
}

func TestBooleanFilters(t *testing.T) {
	web := ethIPTCP(t, "10.0.0.1", "10.0.0.2", 12345, 80)
	ssh := ethIPTCP(t, "10.0.0.1", "10.0.0.2", 12345, 22)
	dns := ethIPUDP(t, "10.0.0.1", "10.0.0.2", 12345, 53)

	mustMatch(t, "tcp and port 80", web, true)
	mustMatch(t, "tcp and port 80", ssh, false)
	mustMatch(t, "tcp port 80 or udp port 53", web, true)
	mustMatch(t, "tcp port 80 or udp port 53", dns, true)
	mustMatch(t, "tcp port 80 or udp port 53", ssh, false)
	mustMatch(t, "not tcp", dns, true)
	mustMatch(t, "not tcp", web, false)
	mustMatch(t, "tcp and (port 80 or port 22)", ssh, true)
	mustMatch(t, "tcp and (port 80 or port 22)", web, true)
	mustMatch(t, "ip and not port 80", web, false)
	mustMatch(t, "ip and not port 80", ssh, true)
}

func TestImplicitAnd(t *testing.T) {
	web := ethIPTCP(t, "10.0.0.1", "10.0.0.2", 12345, 80)
	// "tcp dst port 80" is implicit-and of two primitives.
	mustMatch(t, "tcp dst port 80", web, true)
	mustMatch(t, "tcp dst port 22", web, false)
}

func TestEmptyFilter(t *testing.T) {
	prog, err := bpf.Compile("")
	if err != nil {
		t.Fatal(err)
	}
	if prog != nil {
		t.Errorf("empty filter should compile to nil program, got %d insns", len(prog))
	}
}

func TestUnsupported(t *testing.T) {
	cases := []string{
		"vlan",
		"ether host aa:bb:cc:dd:ee:ff",
		"port 80 xyzzy",
		"net 10.0.0.0/8",
	}
	for _, c := range cases {
		if _, err := bpf.Compile(c); !errors.Is(err, bpf.ErrUnsupported) {
			t.Errorf("Compile(%q) err = %v, want ErrUnsupported", c, err)
		}
	}
}

func TestMatchFunc(t *testing.T) {
	pred, err := bpf.MatchFunc("tcp port 80")
	if err != nil {
		t.Fatal(err)
	}
	web := ethIPTCP(t, "10.0.0.1", "10.0.0.2", 12345, 80)
	ssh := ethIPTCP(t, "10.0.0.1", "10.0.0.2", 12345, 22)
	if !pred(web) {
		t.Error("expected web to match")
	}
	if pred(ssh) {
		t.Error("expected ssh to not match")
	}

	// Empty filter matches everything.
	all, err := bpf.MatchFunc("")
	if err != nil {
		t.Fatal(err)
	}
	if !all(ssh) {
		t.Error("empty filter should match all")
	}
}

func TestJumpOffsetsInRange(t *testing.T) {
	// A larger filter should still resolve to valid <=255 offsets.
	_, err := bpf.Compile("tcp port 80 or tcp port 443 or udp port 53 or udp port 67 or arp")
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
}
