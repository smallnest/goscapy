// RADIUS authentication packet building and parsing example.
package main

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/layers/radius"
)

func main() {
	// Build RADIUS Access-Request with AVPs.
	avps := []fields.TLVOption{
		radius.NewUserNameAVP("testuser"),
		radius.NewNASIPAVP("192.168.1.1"),
		radius.NewNASPortAVP(0),
		radius.NewServiceTypeAVP(2), // Framed
		radius.NewFramedIPAVP("10.0.0.100"),
	}

	wire := radius.BuildRADIUSAVPs(avps)
	fmt.Printf("RADIUS AVPs wire format (%d bytes):\n  %x\n\n", len(wire), wire)

	// Parse AVPs from wire.
	parsed, err := radius.ParseRADIUSAVPs(wire)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	fmt.Println("Parsed RADIUS AVPs:")
	for i, a := range parsed {
		fmt.Printf("  [%d] Type=%d Value=%v\n", i, a.Type, a.Value)
	}

	// Look up specific AVP.
	userName := radius.GetRADIUSAVP(parsed, radius.AVPUserName)
	if userName != nil {
		fmt.Printf("\nUser-Name: %s\n", string(userName.Value))
	}

	nasIP := radius.GetRADIUSAVP(parsed, radius.AVPNASIP)
	if nasIP != nil {
		fmt.Printf("NAS-IP-Address: %s\n", net.IP(nasIP.Value))
	}

	// Code names.
	fmt.Printf("\nRADIUS codes:\n")
	for _, code := range []uint8{1, 2, 3, 4, 5, 11} {
		fmt.Printf("  %d = %s\n", code, radius.CodeName(code))
	}
}
