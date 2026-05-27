package sendrecv

import (
	"net"

	"github.com/smallnest/goscapy/pkg/packet"
)

// MatchFunc is a predicate that returns true if a received packet is a valid
// response to the sent packet. It implements Scapy's automatic response-matching
// logic across multiple protocols (ICMP, TCP, UDP, DNS).
type MatchFunc func(sent, received *packet.Packet) bool

// ICMP type constants (IANA-assigned).
const (
	icmpEchoReply    uint8 = 0
	icmpDestUnreach  uint8 = 3
	icmpEchoRequest  uint8 = 8
	icmpTimeExceeded uint8 = 11
)

// ARP operation constants.
const (
	arpWhoHas uint16 = 1
	arpIsAt   uint16 = 2
)

// BOOTP operation constants.
const (
	bootRequest uint8 = 1
	bootReply   uint8 = 2
)

// DefaultMatch returns a MatchFunc that uses protocol-specific heuristics to
// match a received packet against the sent packet. The matching logic is:
//
//	ICMP Echo: received.IP.src == sent.IP.dst &&
//	           received.ICMP.type == EchoReply (if sent.type == EchoRequest) &&
//	           received.ICMP.id == sent.ICMP.id
//	ICMP Error: received.IP.src == sent.IP.dst (no id/seq check; error types
//	            repurpose those fields as "unused" or gateway address)
//	TCP:  received.IP.src == sent.IP.dst &&
//	      received.TCP.sport == sent.TCP.dport &&
//	      received.TCP.dport == sent.TCP.sport
//	      If sent.flags has SYN: received.flags must have SYN|ACK &&
//	      received.TCP.ack == sent.TCP.seq + 1
//	UDP:  received.IP.src == sent.IP.dst &&
//	      received.UDP.sport == sent.UDP.dport &&
//	      received.UDP.dport == sent.UDP.sport
//	DNS:  received.DNS.id == sent.DNS.id (transaction ID match)
//	ARP:  received.ARP.op == is-at &&
//	      received.ARP.psrc == sent.ARP.pdst &&
//	      received.ARP.pdst == sent.ARP.psrc (IP swap)
//	DHCP: received.DHCP.xid == sent.DHCP.xid (transaction ID match)
//
// When the sent packet has no IP layer (e.g. ARP at L2), the IP-level check
// is skipped.
func DefaultMatch(sent *packet.Packet) MatchFunc {
	sentIP := sent.GetLayer("IP")
	sentICMP := sent.GetLayer("ICMP")
	sentTCP := sent.GetLayer("TCP")
	sentUDP := sent.GetLayer("UDP")
	sentDNS := sent.GetLayer("DNS")
	sentARP := sent.GetLayer("ARP")
	sentDHCP := sent.GetLayer("DHCP")

	// Pre-extract fields from the sent packet to avoid repeated lookups.
	var sentDstIP net.IP
	if sentIP != nil {
		if v, err := sentIP.Get("dst"); err == nil {
			sentDstIP, _ = v.(net.IP)
		}
	}

	var (
		hasICMP      bool
		sentICMPType uint8
		sentICMPID   uint16
	)
	if sentICMP != nil {
		hasICMP = true
		if v, err := sentICMP.Get("type"); err == nil {
			sentICMPType, _ = v.(uint8)
		}
		if v, err := sentICMP.Get("id"); err == nil {
			sentICMPID, _ = v.(uint16)
		}
	}

	var (
		hasTCP       bool
		sentTCPSport uint16
		sentTCPDport uint16
		sentTCPSeq   uint32
		sentTCPFlags uint8
	)
	if sentTCP != nil {
		hasTCP = true
		if v, err := sentTCP.Get("sport"); err == nil {
			sentTCPSport, _ = v.(uint16)
		}
		if v, err := sentTCP.Get("dport"); err == nil {
			sentTCPDport, _ = v.(uint16)
		}
		if v, err := sentTCP.Get("seq"); err == nil {
			sentTCPSeq, _ = v.(uint32)
		}
		if v, err := sentTCP.Get("flags"); err == nil {
			sentTCPFlags, _ = v.(uint8)
		}
	}

	var (
		hasUDP       bool
		sentUDPSport uint16
		sentUDPDport uint16
	)
	if sentUDP != nil {
		hasUDP = true
		if v, err := sentUDP.Get("sport"); err == nil {
			sentUDPSport, _ = v.(uint16)
		}
		if v, err := sentUDP.Get("dport"); err == nil {
			sentUDPDport, _ = v.(uint16)
		}
	}

	var (
		hasDNS    bool
		sentDNSID uint16
	)
	if sentDNS != nil {
		hasDNS = true
		if v, err := sentDNS.Get("id"); err == nil {
			sentDNSID, _ = v.(uint16)
		}
	}

	var (
		hasARP     bool
		sentARPOp  uint16
		sentARPPsrc net.IP
		sentARPPdst net.IP
	)
	if sentARP != nil {
		hasARP = true
		if v, err := sentARP.Get("op"); err == nil {
			sentARPOp, _ = v.(uint16)
		}
		if v, err := sentARP.Get("psrc"); err == nil {
			sentARPPsrc, _ = v.(net.IP)
		}
		if v, err := sentARP.Get("pdst"); err == nil {
			sentARPPdst, _ = v.(net.IP)
		}
	}

	var (
		hasDHCP    bool
		sentDHCPOp  uint8
		sentDHCPXid uint32
	)
	if sentDHCP != nil {
		hasDHCP = true
		if v, err := sentDHCP.Get("op"); err == nil {
			sentDHCPOp, _ = v.(uint8)
		}
		if v, err := sentDHCP.Get("xid"); err == nil {
			sentDHCPXid, _ = v.(uint32)
		}
	}

	return func(_, received *packet.Packet) bool {
		// ARP matching: operates at L2, no IP layer involved.
		if hasARP {
			recvARP := received.GetLayer("ARP")
			if recvARP == nil {
				return false
			}

			// ARP request (who-has) must be answered with is-at.
			if sentARPOp == arpWhoHas {
				recvOp, err := recvARP.Get("op")
				if err != nil {
					return false
				}
				recvOpVal, ok := recvOp.(uint16)
				if !ok || recvOpVal != arpIsAt {
					return false
				}
			}

			// Reply psrc == request pdst (IP the request was looking for).
			if sentARPPdst != nil {
				recvPsrc, err := recvARP.Get("psrc")
				if err != nil {
					return false
				}
				recvPsrcIP, ok := recvPsrc.(net.IP)
				if !ok || !recvPsrcIP.Equal(sentARPPdst) {
					return false
				}
			}

			// Reply pdst == request psrc (reply is directed back to requester).
			if sentARPPsrc != nil {
				recvPdst, err := recvARP.Get("pdst")
				if err != nil {
					return false
				}
				recvPdstIP, ok := recvPdst.(net.IP)
				if !ok || !recvPdstIP.Equal(sentARPPsrc) {
					return false
				}
			}

			return true
		}

		// IP-level check: received src must equal sent dst.
		// Skipped for ARP (L2 protocol) and when the sent packet has no IP layer.
		if sentDstIP != nil {
			recvIP := received.GetLayer("IP")
			if recvIP == nil {
				return false
			}
			recvSrc, err := recvIP.Get("src")
			if err != nil {
				return false
			}
			recvSrcIP, ok := recvSrc.(net.IP)
			if !ok || !recvSrcIP.Equal(sentDstIP) {
				return false
			}
		}

		// ICMP-level check.
		if hasICMP {
			recvICMP := received.GetLayer("ICMP")
			if recvICMP == nil {
				return false
			}

			// Echo Request must be answered with Echo Reply.
			if sentICMPType == icmpEchoRequest {
				recvType, err := recvICMP.Get("type")
				if err != nil {
					return false
				}
				recvTypeVal, ok := recvType.(uint8)
				if !ok {
					return false
				}

				switch recvTypeVal {
				case icmpEchoReply:
					// Echo Reply: id must match.
					recvID, err := recvICMP.Get("id")
					if err != nil {
						return false
					}
					recvIDVal, ok := recvID.(uint16)
					if !ok || recvIDVal != sentICMPID {
						return false
					}
				case icmpDestUnreach, icmpTimeExceeded:
					// Error responses: no id/seq field; the error payload
					// contains the original packet. For now, IP-level
					// match (checked above) is sufficient as a best-effort
					// filter.
				default:
					// Unknown ICMP type — reject.
					return false
				}
			}
		}

		// TCP-level check: ports must be swapped.
		// If the sent packet has SYN, the response must be SYN-ACK
		// with ack == sent.seq + 1.
		if hasTCP {
			recvTCP := received.GetLayer("TCP")
			if recvTCP == nil {
				return false
			}
			recvSport, err := recvTCP.Get("sport")
			if err != nil {
				return false
			}
			recvDport, err := recvTCP.Get("dport")
			if err != nil {
				return false
			}
			recvSportVal, _ := recvSport.(uint16)
			recvDportVal, _ := recvDport.(uint16)
			if recvSportVal != sentTCPDport || recvDportVal != sentTCPSport {
				return false
			}

			// SYN-ACK check.
			const tcpSyn = uint8(0x02)
			const tcpAck = uint8(0x10)
			if sentTCPFlags&tcpSyn != 0 {
				recvFlags, err := recvTCP.Get("flags")
				if err != nil {
					return false
				}
				recvFlagsVal, _ := recvFlags.(uint8)
				if recvFlagsVal&tcpSyn == 0 || recvFlagsVal&tcpAck == 0 {
					return false
				}

				recvAck, err := recvTCP.Get("ack")
				if err != nil {
					return false
				}
				recvAckVal, _ := recvAck.(uint32)
				if recvAckVal != sentTCPSeq+1 {
					return false
				}
			}
		}

		// UDP-level check: ports must be swapped.
		if hasUDP {
			recvUDP := received.GetLayer("UDP")
			if recvUDP == nil {
				return false
			}
			recvSport, err := recvUDP.Get("sport")
			if err != nil {
				return false
			}
			recvDport, err := recvUDP.Get("dport")
			if err != nil {
				return false
			}
			recvSportVal, _ := recvSport.(uint16)
			recvDportVal, _ := recvDport.(uint16)
			if recvSportVal != sentUDPDport || recvDportVal != sentUDPSport {
				return false
			}
		}

		// DNS-level check: transaction ID must match.
		if hasDNS {
			recvDNS := received.GetLayer("DNS")
			if recvDNS == nil {
				return false
			}
			recvID, err := recvDNS.Get("id")
			if err != nil {
				return false
			}
			recvIDVal, ok := recvID.(uint16)
			if !ok || recvIDVal != sentDNSID {
				return false
			}
		}

		// DHCP-level check: transaction ID (xid) must match.
		if hasDHCP {
			recvDHCP := received.GetLayer("DHCP")
			if recvDHCP == nil {
				return false
			}

			// BOOTREPLY op check if request was BOOTREQUEST.
			if sentDHCPOp == bootRequest {
				recvOp, err := recvDHCP.Get("op")
				if err != nil {
					return false
				}
				recvOpVal, ok := recvOp.(uint8)
				if !ok || recvOpVal != bootReply {
					return false
				}
			}

			recvXid, err := recvDHCP.Get("xid")
			if err != nil {
				return false
			}
			recvXidVal, ok := recvXid.(uint32)
			if !ok || recvXidVal != sentDHCPXid {
				return false
			}
		}

		return true
	}
}