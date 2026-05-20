package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

const ntpEpochOffset = 2208988800

func main() {
	server := flag.String("server", "pool.ntp.org", "NTP server address")
	iface := flag.String("I", "", "Network interface (auto-detect if empty)")
	flag.Parse()

	ifaceVal := *iface
	if ifaceVal == "" {
		ifaceVal = defaultIface()
	}

	serverIP, err := resolveHost(*server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve %s: %v\n", *server, err)
		os.Exit(1)
	}

	fmt.Printf("NTP query: %s (%s)\n\n", *server, serverIP)

	ntpData := buildNTPRequest()
	start := time.Now()

	pkt := goscapy.NewEthernet().
		Over(goscapy.NewIP().
			SrcIP("0.0.0.0").
			DstIP(serverIP).
			TTL(64).
			Proto(layers.IPProtoUDP)).
		Over(goscapy.NewUDP().
			SrcPort(12345).
			DstPort(123)).
		Over(&rawBuilder{layers.NewRawWith(ntpData)}).
		Packet()

	_, reply, err := sendrecv.SendRecv1(pkt, ifaceVal, 3*time.Second)
	rtt := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
		os.Exit(1)
	}
	if reply == nil {
		fmt.Println("Query timeout: no response")
		os.Exit(1)
	}

	rawLayer := reply.GetLayer("Raw")
	if rawLayer == nil {
		fmt.Println("No Raw layer in response")
		return
	}
	load, err := rawLayer.Get("load")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read payload: %v\n", err)
		os.Exit(1)
	}
	respData := load.([]byte)
	if len(respData) < 48 {
		fmt.Fprintf(os.Stderr, "NTP response too short: %d bytes\n", len(respData))
		os.Exit(1)
	}

	li := (respData[0] >> 6) & 0x03
	vn := (respData[0] >> 3) & 0x07
	stratum := respData[1]
	refTS := ntpToTime(respData[16:24])
	origTS := ntpToTime(respData[24:32])
	recvTS := ntpToTime(respData[32:40])
	xmitTS := ntpToTime(respData[40:48])

	offset := float64(recvTS.UnixNano()-origTS.UnixNano()) / 1e9

	fmt.Printf("LI: %d  VN: %d  Stratum: %d\n", li, vn, stratum)
	fmt.Printf("Ref Timestamp:     %s\n", refTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Orig Timestamp:    %s\n", origTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Recv Timestamp:    %s\n", recvTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Xmit Timestamp:    %s\n", xmitTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("\nLocal time:        %s\n", time.Now().Format("2006-01-02 15:04:05.000"))
	fmt.Printf("Server ref time:   %s\n", xmitTS.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("RTT:               %.3f ms\n", rtt.Seconds()*1000)
	fmt.Printf("Clock offset:      %.3f ms\n", offset*1000)
	fmt.Printf("      (local clock is %s)\n", offsetStr(offset))
}

func buildNTPRequest() []byte {
	buf := make([]byte, 48)
	buf[0] = (4 << 3) | 3 // VN=4, Mode=3 (client)
	putNTPTimestamp(buf[40:48], time.Now())
	return buf
}

func putNTPTimestamp(b []byte, t time.Time) {
	sec := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32(uint64(t.UnixNano()%1e9) * (1 << 32) / 1e9)
	binary.BigEndian.PutUint32(b[0:4], sec)
	binary.BigEndian.PutUint32(b[4:8], frac)
}

func ntpToTime(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	if sec == 0 {
		return time.Time{}
	}
	nanos := uint64(frac) * 1e9 / (1 << 32)
	return time.Unix(int64(sec)-ntpEpochOffset, int64(nanos))
}

func offsetStr(offset float64) string {
	if math.Abs(offset) < 0.001 {
		return "synced"
	}
	if offset > 0 {
		return fmt.Sprintf("%.1f ms fast", offset*1000)
	}
	return fmt.Sprintf("%.1f ms slow", -offset*1000)
}

type rawBuilder struct {
	layer *packet.Layer
}

func (rb *rawBuilder) Layer() *packet.Layer { return rb.layer }

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

func resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}