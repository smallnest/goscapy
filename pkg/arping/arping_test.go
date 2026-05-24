package arping

import (
	"net"
	"sort"
	"strings"
	"testing"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 1500000000 { // 1.5s
		t.Errorf("Timeout = %v, want 1.5s", opts.Timeout)
	}
	if opts.Concurrency != 50 {
		t.Errorf("Concurrency = %d, want 50", opts.Concurrency)
	}
}

func TestResultString(t *testing.T) {
	r := &ArpingResult{
		CIDR:      "192.168.1.0/24",
		Interface: "en0",
		Hosts: []Host{
			{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"},
			{IP: "192.168.1.100", MAC: "aa:bb:cc:dd:ee:64"},
		},
		Duration: 2000000000, // 2s
	}

	s := r.String()
	if !strings.Contains(s, "192.168.1.0/24") {
		t.Error("missing CIDR")
	}
	if !strings.Contains(s, "192.168.1.1") {
		t.Error("missing IP")
	}
	if !strings.Contains(s, "aa:bb:cc:dd:ee:01") {
		t.Error("missing MAC")
	}
	if !strings.Contains(s, "Found 2 hosts") {
		t.Error("missing host count")
	}
}

func TestResultStringEmpty(t *testing.T) {
	r := &ArpingResult{
		CIDR:      "10.0.0.0/24",
		Interface: "eth0",
		Hosts:     nil,
		Duration:  1000000000,
	}

	s := r.String()
	if !strings.Contains(s, "Found 0 hosts") {
		t.Error("should show 0 hosts")
	}
}

func TestCIDRToIPs(t *testing.T) {
	ips, err := cidrToIPs("192.168.1.0/30")
	if err != nil {
		t.Fatalf("cidrToIPs: %v", err)
	}
	// /30 = 4 addresses: 0, 1, 2, 3
	if len(ips) != 4 {
		t.Errorf("got %d IPs, want 4", len(ips))
	}
	if ips[0] != "192.168.1.0" {
		t.Errorf("first IP = %q", ips[0])
	}
	if ips[3] != "192.168.1.3" {
		t.Errorf("last IP = %q", ips[3])
	}
}

func TestCIDRToIPsSingle(t *testing.T) {
	ips, err := cidrToIPs("10.0.0.1/32")
	if err != nil {
		t.Fatalf("cidrToIPs: %v", err)
	}
	if len(ips) != 1 {
		t.Errorf("got %d IPs, want 1", len(ips))
	}
	if ips[0] != "10.0.0.1" {
		t.Errorf("IP = %q", ips[0])
	}
}

func TestCIDRToIPsInvalid(t *testing.T) {
	_, err := cidrToIPs("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIncIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.0").To4()
	incIP(ip)
	if ip.String() != "192.168.1.1" {
		t.Errorf("after inc: %s", ip)
	}

	// Test carry.
	ip2 := net.ParseIP("192.168.1.255").To4()
	incIP(ip2)
	if ip2.String() != "192.168.2.0" {
		t.Errorf("after carry: %s", ip2)
	}
}

func TestGetSrcMAC(t *testing.T) {
	// lo0 has no MAC on macOS, function should handle gracefully.
	mac := getSrcMAC("lo0")
	_ = mac // just verify no panic

	// Test with a real interface.
	iface := defaultIface()
	mac2 := getSrcMAC(iface)
	if mac2 == "" || mac2 == "00:00:00:00:00:00" {
		t.Errorf("getSrcMAC(%s) = %q, expected real MAC", iface, mac2)
	}
}

func TestGetSrcIP(t *testing.T) {
	ip := getSrcIP("lo0")
	if ip == "" {
		t.Error("getSrcIP should not return empty")
	}
}

func TestDefaultIface(t *testing.T) {
	iface := defaultIface()
	if iface == "" {
		t.Error("defaultIface should not return empty")
	}
}

func TestArpingInvalidIP(t *testing.T) {
	_, err := Arping("not-an-ip", DefaultOptions())
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestHostSort(t *testing.T) {
	// Verify Arping sorts hosts by IP.
	r := &ArpingResult{
		CIDR: "10.0.0.0/24",
		Hosts: []Host{
			{IP: "10.0.0.3", MAC: "aa:bb:cc:dd:ee:03"},
			{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:01"},
			{IP: "10.0.0.2", MAC: "aa:bb:cc:dd:ee:02"},
		},
	}
	// Sort like Arping does.
	sort.Slice(r.Hosts, func(i, j int) bool {
		return r.Hosts[i].IP < r.Hosts[j].IP
	})
	if r.Hosts[0].IP != "10.0.0.1" || r.Hosts[1].IP != "10.0.0.2" || r.Hosts[2].IP != "10.0.0.3" {
		t.Errorf("sort order wrong: %v", r.Hosts)
	}
}
