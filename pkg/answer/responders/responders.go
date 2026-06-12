// Package responders provides ready-to-use AnsweringMachine instances built on
// pkg/answer: an ICMP echo responder, an ARP responder, and a minimal DNS
// responder. They serve as both turnkey tools (test stubs, honeypots) and as
// worked examples of the answer.Funcs contract.
//
// Each constructor returns an *answer.AnsweringMachine; call Run(ctx) to start
// the sniff→match→reply loop. All responders require raw-socket privileges.
package responders

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/answer"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ICMPEchoResponder builds an AnsweringMachine that replies to ICMP Echo
// Requests with matching Echo Replies, swapping src/dst at the IP layer and
// preserving the id/seq/payload. It mirrors a host responding to ping.
//
// Replies are sent at L3 (the OS adds the link-layer header). Only IPv4 ICMP
// is handled.
func ICMPEchoResponder(iface string) *answer.AnsweringMachine {
	return answer.New(answer.Config{Iface: iface}, answer.Funcs{
		IsRequest: func(pkt *packet.Packet) bool {
			ic := pkt.GetLayer("ICMP")
			if ic == nil {
				return false
			}
			t, _ := ic.Get("type")
			tv, _ := t.(uint8)
			return tv == layers.ICMPEchoRequest
		},
		MakeReply: func(pkt *packet.Packet) (*packet.Packet, bool) {
			reqIP := pkt.GetLayer("IP")
			reqICMP := pkt.GetLayer("ICMP")
			if reqIP == nil || reqICMP == nil {
				return nil, false
			}
			src, _ := reqIP.Get("src")
			dst, _ := reqIP.Get("dst")

			ip := layers.NewIP()
			_ = ip.Set("src", dst) // reply src = request dst
			_ = ip.Set("dst", src) // reply dst = request src
			_ = ip.Set("proto", layers.IPProtoICMP)

			icmp := layers.NewICMP()
			_ = icmp.Set("type", layers.ICMPEchoReply)
			_ = icmp.Set("code", uint8(0))
			copyField(reqICMP, icmp, "id")
			copyField(reqICMP, icmp, "seq")

			reply := packet.NewFrom(ip, icmp)
			// Preserve the echo payload, if any, as a Raw layer.
			if raw := pkt.GetLayer("Raw"); raw != nil {
				if load, err := raw.Get("load"); err == nil {
					if b, ok := load.([]byte); ok && len(b) > 0 {
						reply.Push(layers.NewRawWith(b))
					}
				}
			}
			return reply, true
		},
	})
}

// ARPResponder builds an AnsweringMachine that answers ARP who-has requests for
// myIP with an is-at reply advertising myMAC. Replies are sent at L2.
//
// An ARP responder rewrites neighbors' ARP caches; use it only on networks you
// are authorized to test.
func ARPResponder(iface, myIP, myMAC string) *answer.AnsweringMachine {
	return answer.New(answer.Config{Iface: iface, SendL2: true}, answer.Funcs{
		IsRequest: func(pkt *packet.Packet) bool {
			arp := pkt.GetLayer("ARP")
			if arp == nil {
				return false
			}
			op, _ := arp.Get("op")
			if opv, _ := op.(uint16); opv != layers.ARPWhoHas {
				return false
			}
			pdst, _ := arp.Get("pdst")
			return ipString(pdst) == myIP
		},
		MakeReply: func(pkt *packet.Packet) (*packet.Packet, bool) {
			req := pkt.GetLayer("ARP")
			if req == nil {
				return nil, false
			}
			reqHwsrc, _ := req.Get("hwsrc")
			reqPsrc, _ := req.Get("psrc")

			eth := layers.NewEthernetWith(hwString(reqHwsrc), myMAC, layers.EtherTypeARP)
			arp := layers.NewARP()
			_ = arp.Set("op", layers.ARPIsAt)
			_ = arp.Set("hwsrc", myMAC)
			_ = arp.Set("psrc", myIP)
			_ = arp.Set("hwdst", hwString(reqHwsrc))
			_ = arp.Set("pdst", ipString(reqPsrc))
			return packet.NewFrom(eth, arp), true
		},
	})
}

// DNSResolver maps a query name (lowercase, trailing dot optional) and qtype to
// an answer. Return ok=false to ignore a query.
type DNSResolver func(name string, qtype uint16) (rdata []byte, ttl uint32, ok bool)

// StaticDNSResolver returns a DNSResolver backed by a name→IPv4 map. It answers
// A queries (QtypeA) from the map and ignores everything else. Names are
// matched case-insensitively with an optional trailing dot.
func StaticDNSResolver(zone map[string]string, ttl uint32) DNSResolver {
	norm := make(map[string]string, len(zone))
	for k, v := range zone {
		norm[normalizeName(k)] = v
	}
	return func(name string, qtype uint16) ([]byte, uint32, bool) {
		if qtype != dns.QtypeA {
			return nil, 0, false
		}
		ip, ok := norm[normalizeName(name)]
		if !ok {
			return nil, 0, false
		}
		return dns.BuildARData(ip), ttl, true
	}
}

// DNSResponder builds an AnsweringMachine that answers UDP DNS queries using
// the supplied resolver. It echoes the transaction ID, copies the question
// section, and appends one answer RR per resolved question. Replies are sent
// at L3 with ports swapped.
//
// This is a minimal authoritative-style responder for testing and emulation,
// not a full recursive resolver.
func DNSResponder(iface string, resolve DNSResolver) *answer.AnsweringMachine {
	return answer.New(answer.Config{Iface: iface}, answer.Funcs{
		IsRequest: func(pkt *packet.Packet) bool {
			dnsLayer := pkt.GetLayer("DNS")
			if dnsLayer == nil {
				return false
			}
			// Only answer queries (QR=0).
			flags, _ := dnsLayer.Get("flags")
			fv, _ := flags.(uint16)
			return fv&0x8000 == 0
		},
		MakeReply: func(pkt *packet.Packet) (*packet.Packet, bool) {
			reqIP := pkt.GetLayer("IP")
			reqUDP := pkt.GetLayer("UDP")
			reqDNS := pkt.GetLayer("DNS")
			if reqIP == nil || reqUDP == nil || reqDNS == nil {
				return nil, false
			}

			questions, answers, ok := buildDNSAnswers(reqDNS, resolve)
			if !ok {
				return nil, false
			}

			src, _ := reqIP.Get("src")
			dst, _ := reqIP.Get("dst")
			sp, _ := reqUDP.Get("sport")
			dp, _ := reqUDP.Get("dport")
			id, _ := reqDNS.Get("id")

			ip := layers.NewIP()
			_ = ip.Set("src", dst)
			_ = ip.Set("dst", src)
			_ = ip.Set("proto", layers.IPProtoUDP)

			udp := layers.NewUDP()
			_ = udp.Set("sport", dp) // reply src port = request dst port (53)
			_ = udp.Set("dport", sp)

			dnsLayer := dns.NewDNS()
			_ = dnsLayer.Set("id", id)
			_ = dnsLayer.Set("flags", uint16(0x8180)) // QR=1, RD=1, RA=1
			_ = dnsLayer.Set("qdcount", uint16(len(questions)))
			_ = dnsLayer.Set("ancount", uint16(len(answers)))
			_ = dnsLayer.Set("data", dns.BuildDNSMessage(questions, answers, nil, nil))

			return packet.NewFrom(ip, udp, dnsLayer), true
		},
	})
}

// buildDNSAnswers parses the request's questions and resolves each one,
// returning the questions to echo and the answer RRs. ok is false when there
// are no questions or none resolve.
func buildDNSAnswers(reqDNS *packet.Layer, resolve DNSResolver) (questions []dns.DNSQuestion, answers []dns.DNSRR, ok bool) {
	qs, err := dns.GetQuestions(reqDNS)
	if err != nil || len(qs) == 0 {
		return nil, nil, false
	}
	for _, q := range qs {
		rdata, ttl, found := resolve(q.Name, q.Type)
		if !found {
			continue
		}
		answers = append(answers, dns.DNSRR{
			Name:     q.Name,
			Type:     q.Type,
			Class:    q.Class,
			TTL:      ttl,
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		})
	}
	if len(answers) == 0 {
		return nil, nil, false
	}
	return qs, answers, true
}

// --- helpers ---

func copyField(from, to *packet.Layer, name string) {
	if v, err := from.Get(name); err == nil {
		_ = to.Set(name, v)
	}
}

func ipString(v any) string {
	switch t := v.(type) {
	case net.IP:
		return t.String()
	case string:
		return t
	case []byte:
		return net.IP(t).String()
	}
	return fmt.Sprintf("%v", v)
}

func hwString(v any) string {
	switch t := v.(type) {
	case net.HardwareAddr:
		return t.String()
	case string:
		return t
	}
	return fmt.Sprintf("%v", v)
}

func normalizeName(name string) string {
	n := name
	if len(n) > 0 && n[len(n)-1] == '.' {
		n = n[:len(n)-1]
	}
	// ASCII lowercase.
	b := []byte(n)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
