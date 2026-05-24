package route

import (
	"net"
	"testing"
)

func TestTable4(t *testing.T) {
	routes, err := Table4()
	if err != nil {
		t.Fatalf("Table4() error: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("Table4() returned no routes")
	}

	found := false
	for _, r := range routes {
		if r.Destination == nil {
			found = true
			t.Logf("Default route: gateway=%s iface=%s metric=%d", r.Gateway, r.Interface, r.Metric)
			if r.Interface == "" {
				t.Error("Default route has empty interface")
			}
		}
	}
	if !found {
		t.Log("Warning: no default route found (unusual but not fatal)")
	}
}

func TestTable6(t *testing.T) {
	routes, err := Table6()
	if err != nil {
		t.Logf("Table6() error: %v (may be expected if no IPv6 routes)", err)
		return
	}
	t.Logf("IPv6 routes: %d", len(routes))
}

func TestDefaultRoute4(t *testing.T) {
	r, err := DefaultRoute4()
	if err != nil {
		t.Fatalf("DefaultRoute4() error: %v", err)
	}
	t.Logf("Default route: gateway=%s iface=%s", r.Gateway, r.Interface)
	if r.Interface == "" {
		t.Error("Default route has empty interface")
	}
}

func TestRoute4(t *testing.T) {
	// Route to 8.8.8.8 should resolve via the default route.
	r, err := Route4(net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("Route4(8.8.8.8) error: %v", err)
	}
	t.Logf("Route to 8.8.8.8: gateway=%s iface=%s", r.Gateway, r.Interface)
	if r.Interface == "" {
		t.Error("Route has empty interface")
	}
}

func TestRoute4Localhost(t *testing.T) {
	r, err := Route4(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Route4(127.0.0.1) error: %v", err)
	}
	t.Logf("Route to 127.0.0.1: gateway=%s iface=%s", r.Gateway, r.Interface)
}

func TestInterfaces(t *testing.T) {
	ifaces, err := Interfaces()
	if err != nil {
		t.Fatalf("Interfaces() error: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("Interfaces() returned nothing")
	}
	for _, i := range ifaces {
		t.Logf("  %s (index=%d mtu=%d addrs=%v)", i.Name, i.Index, i.MTU, i.Addresses)
	}
}

func TestBestMatch(t *testing.T) {
	routes := []Route{
		{Destination: mustParseCIDR("192.168.1.0/24"), Interface: "eth0"},
		{Destination: mustParseCIDR("10.0.0.0/8"), Interface: "eth1"},
		{Destination: nil, Interface: "eth2", Gateway: net.ParseIP("192.168.1.1")},
	}

	// Specific match
	r, err := bestMatch(net.ParseIP("192.168.1.100"), routes)
	if err != nil {
		t.Fatal(err)
	}
	if r.Interface != "eth0" {
		t.Errorf("192.168.1.100 matched %s, want eth0", r.Interface)
	}

	// Broader match
	r, err = bestMatch(net.ParseIP("10.1.2.3"), routes)
	if err != nil {
		t.Fatal(err)
	}
	if r.Interface != "eth1" {
		t.Errorf("10.1.2.3 matched %s, want eth1", r.Interface)
	}

	// Default route
	r, err = bestMatch(net.ParseIP("8.8.8.8"), routes)
	if err != nil {
		t.Fatal(err)
	}
	if r.Interface != "eth2" {
		t.Errorf("8.8.8.8 matched %s, want eth2", r.Interface)
	}

	// Prefer longer prefix
	routes2 := []Route{
		{Destination: mustParseCIDR("10.0.0.0/8"), Interface: "eth0"},
		{Destination: mustParseCIDR("10.1.0.0/16"), Interface: "eth1"},
	}
	r, err = bestMatch(net.ParseIP("10.1.1.1"), routes2)
	if err != nil {
		t.Fatal(err)
	}
	if r.Interface != "eth1" {
		t.Errorf("10.1.1.1 matched %s, want eth1 (longer prefix)", r.Interface)
	}
}

func TestParseHexIP(t *testing.T) {
	tests := []struct {
		hex string
		want string
	}{
		{"00000000", "0.0.0.0"},
		{"0102A8C0", "192.168.2.1"},
		{"FFFFFFFF", "255.255.255.255"},
		{"08080808", "8.8.8.8"},
	}
	for _, tt := range tests {
		ip, err := parseHexIP(tt.hex)
		if err != nil {
			t.Errorf("parseHexIP(%s) error: %v", tt.hex, err)
			continue
		}
		if got := ip.String(); got != tt.want {
			t.Errorf("parseHexIP(%s) = %s, want %s", tt.hex, got, tt.want)
		}
	}
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}
