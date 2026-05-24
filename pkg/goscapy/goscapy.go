// Package goscapy provides an idiomatic Go API for building and serializing
// network packets. It offers two complementary interfaces:
//
//  1. Builder API — fluent method chaining for type-safe, explicit packet construction.
//  2. Shortcut functions — one-liners for common protocol stacks with sensible defaults.
//
// # Builder API
//
//	pkt, _ := goscapy.NewEthernet().
//	    DstMAC("ff:ff:ff:ff:ff:ff").
//	    Over(goscapy.NewIP().DstIP("8.8.8.8")).
//	    Over(goscapy.NewICMP().Type(8)).
//	    Build()
//
// # Shortcut functions
//
//	pkt, _ := goscapy.EtherIPICMP("ff:ff:ff:ff:ff:ff", "8.8.8.8", 8, 0)
package goscapy

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/layers/bgp"
	"github.com/smallnest/goscapy/pkg/layers/dhcp"
	"github.com/smallnest/goscapy/pkg/layers/dot11"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	"github.com/smallnest/goscapy/pkg/layers/dot1q"
	"github.com/smallnest/goscapy/pkg/layers/erspan"
	"github.com/smallnest/goscapy/pkg/layers/gre"
	layershttp "github.com/smallnest/goscapy/pkg/layers/http"
	"github.com/smallnest/goscapy/pkg/layers/lldp"
	"github.com/smallnest/goscapy/pkg/layers/ntp"
	"github.com/smallnest/goscapy/pkg/layers/ospf"
	"github.com/smallnest/goscapy/pkg/layers/quic"
	layerstls "github.com/smallnest/goscapy/pkg/layers/tls"
	"github.com/smallnest/goscapy/pkg/layers/vxlan"
	"github.com/smallnest/goscapy/pkg/packet"
)

// LayerBuilder is implemented by all protocol builders.
// It exposes the underlying packet layer for stacking.
type LayerBuilder interface {
	Layer() *packet.Layer
}

// PacketBuilder wraps a Packet and provides chaining methods (Over, Build).
type PacketBuilder struct {
	pkt *packet.Packet
}

// Over stacks another layer on top and returns the PacketBuilder for chaining.
func (pb *PacketBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pb.pkt.Push(upper.Layer())
	return pb
}

// Build serializes the full packet into wire-format bytes.
func (pb *PacketBuilder) Build() ([]byte, error) {
	return pb.pkt.Build()
}

// Packet returns the underlying Packet for advanced use.
func (pb *PacketBuilder) Packet() *packet.Packet {
	return pb.pkt
}

// ---- EthernetBuilder ----

// EthernetBuilder builds Ethernet frame layers.
type EthernetBuilder struct {
	layer *packet.Layer
}

// NewEthernet creates an Ethernet frame builder with default values.
func NewEthernet() *EthernetBuilder {
	return &EthernetBuilder{layer: layers.NewEthernet()}
}

func (b *EthernetBuilder) Layer() *packet.Layer { return b.layer }

// DstMAC sets the destination MAC address (e.g. "ff:ff:ff:ff:ff:ff").
func (b *EthernetBuilder) DstMAC(mac string) *EthernetBuilder {
	b.layer.Set("dst", mac)
	return b
}

// SrcMAC sets the source MAC address.
func (b *EthernetBuilder) SrcMAC(mac string) *EthernetBuilder {
	b.layer.Set("src", mac)
	return b
}

// Type sets the EtherType field (e.g. layers.EtherTypeIPv4).
func (b *EthernetBuilder) Type(t uint16) *EthernetBuilder {
	b.layer.Set("type", t)
	return b
}

// Over stacks an upper layer on top of this Ethernet layer and returns a PacketBuilder.
func (b *EthernetBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- IPBuilder ----

// IPBuilder builds IPv4 header layers.
type IPBuilder struct {
	layer *packet.Layer
}

// NewIP creates an IPv4 header builder with sensible defaults (v4, ttl=64).
func NewIP() *IPBuilder {
	return &IPBuilder{layer: layers.NewIP()}
}

func (b *IPBuilder) Layer() *packet.Layer { return b.layer }

// SrcIP sets the source IP address (e.g. "192.168.1.1").
func (b *IPBuilder) SrcIP(ip string) *IPBuilder {
	b.layer.Set("src", ip)
	return b
}

// DstIP sets the destination IP address.
func (b *IPBuilder) DstIP(ip string) *IPBuilder {
	b.layer.Set("dst", ip)
	return b
}

// TTL sets the time-to-live field.
func (b *IPBuilder) TTL(ttl uint8) *IPBuilder {
	b.layer.Set("ttl", ttl)
	return b
}

// Proto sets the protocol field (e.g. layers.IPProtoTCP).
func (b *IPBuilder) Proto(p uint8) *IPBuilder {
	b.layer.Set("proto", p)
	return b
}

// ID sets the identification field.
func (b *IPBuilder) ID(id uint16) *IPBuilder {
	b.layer.Set("id", id)
	return b
}

// Over stacks an upper layer on top of this IP layer and returns a PacketBuilder.
func (b *IPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- ICMPBuilder ----

// ICMPBuilder builds ICMP message layers.
type ICMPBuilder struct {
	layer *packet.Layer
}

// NewICMP creates an ICMP message builder (default: Echo Request, type=8).
func NewICMP() *ICMPBuilder {
	return &ICMPBuilder{layer: layers.NewICMP()}
}

func (b *ICMPBuilder) Layer() *packet.Layer { return b.layer }

// Type sets the ICMP type field.
func (b *ICMPBuilder) Type(t uint8) *ICMPBuilder {
	b.layer.Set("type", t)
	return b
}

// Code sets the ICMP code field.
func (b *ICMPBuilder) Code(c uint8) *ICMPBuilder {
	b.layer.Set("code", c)
	return b
}

// ID sets the ICMP identifier field.
func (b *ICMPBuilder) ID(id uint16) *ICMPBuilder {
	b.layer.Set("id", id)
	return b
}

// Seq sets the ICMP sequence number field.
func (b *ICMPBuilder) Seq(seq uint16) *ICMPBuilder {
	b.layer.Set("seq", seq)
	return b
}

// ---- TCPBuilder ----

// TCPBuilder builds TCP header layers.
type TCPBuilder struct {
	layer *packet.Layer
}

// NewTCP creates a TCP header builder with sensible defaults.
func NewTCP() *TCPBuilder {
	return &TCPBuilder{layer: layers.NewTCP()}
}

func (b *TCPBuilder) Layer() *packet.Layer { return b.layer }

// SrcPort sets the source port.
func (b *TCPBuilder) SrcPort(p uint16) *TCPBuilder {
	b.layer.Set("sport", p)
	return b
}

// DstPort sets the destination port.
func (b *TCPBuilder) DstPort(p uint16) *TCPBuilder {
	b.layer.Set("dport", p)
	return b
}

// Flags sets the TCP flags byte (e.g. layers.TCPSyn | layers.TCPAck).
func (b *TCPBuilder) Flags(f uint8) *TCPBuilder {
	b.layer.Set("flags", f)
	return b
}

// Seq sets the sequence number.
func (b *TCPBuilder) Seq(s uint32) *TCPBuilder {
	b.layer.Set("seq", s)
	return b
}

// Ack sets the acknowledgment number.
func (b *TCPBuilder) Ack(a uint32) *TCPBuilder {
	b.layer.Set("ack", a)
	return b
}

// Window sets the window size.
func (b *TCPBuilder) Window(w uint16) *TCPBuilder {
	b.layer.Set("window", w)
	return b
}

// Over stacks an upper layer on top of this TCP layer and returns a PacketBuilder.
func (b *TCPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- UDPBuilder ----

// UDPBuilder builds UDP header layers.
type UDPBuilder struct {
	layer *packet.Layer
}

// NewUDP creates a UDP header builder with sensible defaults.
func NewUDP() *UDPBuilder {
	return &UDPBuilder{layer: layers.NewUDP()}
}

func (b *UDPBuilder) Layer() *packet.Layer { return b.layer }

// SrcPort sets the source port.
func (b *UDPBuilder) SrcPort(p uint16) *UDPBuilder {
	b.layer.Set("sport", p)
	return b
}

// DstPort sets the destination port.
func (b *UDPBuilder) DstPort(p uint16) *UDPBuilder {
	b.layer.Set("dport", p)
	return b
}

// Over stacks an upper layer on top of this UDP layer and returns a PacketBuilder.
func (b *UDPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- ARPBuilder ----

// ARPBuilder builds ARP message layers.
type ARPBuilder struct {
	layer *packet.Layer
}

// NewARP creates an ARP message builder with sensible defaults for Ethernet+IPv4.
func NewARP() *ARPBuilder {
	return &ARPBuilder{layer: layers.NewARP()}
}

func (b *ARPBuilder) Layer() *packet.Layer { return b.layer }

// Op sets the ARP operation (layers.ARPWhoHas or layers.ARPIsAt).
func (b *ARPBuilder) Op(op uint16) *ARPBuilder {
	b.layer.Set("op", op)
	return b
}

// SrcMAC sets the sender hardware address.
func (b *ARPBuilder) SrcMAC(mac string) *ARPBuilder {
	b.layer.Set("hwsrc", mac)
	return b
}

// SrcIP sets the sender protocol address.
func (b *ARPBuilder) SrcIP(ip string) *ARPBuilder {
	b.layer.Set("psrc", ip)
	return b
}

// DstMAC sets the target hardware address.
func (b *ARPBuilder) DstMAC(mac string) *ARPBuilder {
	b.layer.Set("hwdst", mac)
	return b
}

// DstIP sets the target protocol address.
func (b *ARPBuilder) DstIP(ip string) *ARPBuilder {
	b.layer.Set("pdst", ip)
	return b
}

// Over stacks an upper layer on top of this ARP layer and returns a PacketBuilder.
func (b *ARPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- DNSBuilder ----

// DNSBuilder builds DNS message layers.
type DNSBuilder struct {
	layer *packet.Layer
}

// NewDNS creates a DNS message builder with default query header (RD=1).
func NewDNS() *DNSBuilder {
	return &DNSBuilder{layer: dns.NewDNS()}
}

func (b *DNSBuilder) Layer() *packet.Layer { return b.layer }

// ID sets the DNS transaction ID.
func (b *DNSBuilder) ID(id uint16) *DNSBuilder {
	b.layer.Set("id", id)
	return b
}

// Flags sets the DNS flags field.
func (b *DNSBuilder) Flags(flags uint16) *DNSBuilder {
	b.layer.Set("flags", flags)
	return b
}

// QDCount sets the question count.
func (b *DNSBuilder) QDCount(n uint16) *DNSBuilder {
	b.layer.Set("qdcount", n)
	return b
}

// ANCount sets the answer count.
func (b *DNSBuilder) ANCount(n uint16) *DNSBuilder {
	b.layer.Set("ancount", n)
	return b
}

// NSCount sets the authority count.
func (b *DNSBuilder) NSCount(n uint16) *DNSBuilder {
	b.layer.Set("nscount", n)
	return b
}

// ARCount sets the additional count.
func (b *DNSBuilder) ARCount(n uint16) *DNSBuilder {
	b.layer.Set("arcount", n)
	return b
}

// Data sets the raw DNS data (questions + RRs) directly.
func (b *DNSBuilder) Data(data []byte) *DNSBuilder {
	b.layer.Set("data", data)
	return b
}

// Questions sets the question section and updates QDCount.
func (b *DNSBuilder) Questions(qs []dns.DNSQuestion) *DNSBuilder {
	b.layer.Set("qdcount", uint16(len(qs)))
	b.layer.Set("data", dns.BuildDNSMessage(qs, nil, nil, nil))
	return b
}

// Over stacks an upper layer on top of this DNS layer and returns a PacketBuilder.
func (b *DNSBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- DHCPBuilder ----

// DHCPBuilder builds DHCP message layers.
type DHCPBuilder struct {
	layer *packet.Layer
}

// NewDHCP creates a DHCP message builder with default BOOTREQUEST header.
func NewDHCP() *DHCPBuilder {
	return &DHCPBuilder{layer: dhcp.NewDHCP()}
}

func (b *DHCPBuilder) Layer() *packet.Layer { return b.layer }

// Op sets the BOOTP operation (BOOTREQUEST=1, BOOTREPLY=2).
func (b *DHCPBuilder) Op(op uint8) *DHCPBuilder {
	b.layer.Set("op", op)
	return b
}

// XID sets the transaction ID.
func (b *DHCPBuilder) XID(xid uint32) *DHCPBuilder {
	b.layer.Set("xid", xid)
	return b
}

// CIAddr sets the client IP address.
func (b *DHCPBuilder) CIAddr(ip string) *DHCPBuilder {
	b.layer.Set("ciaddr", ip)
	return b
}

// YIAddr sets the your (assigned) IP address.
func (b *DHCPBuilder) YIAddr(ip string) *DHCPBuilder {
	b.layer.Set("yiaddr", ip)
	return b
}

// SIAddr sets the server IP address.
func (b *DHCPBuilder) SIAddr(ip string) *DHCPBuilder {
	b.layer.Set("siaddr", ip)
	return b
}

// GIAddr sets the gateway IP address.
func (b *DHCPBuilder) GIAddr(ip string) *DHCPBuilder {
	b.layer.Set("giaddr", ip)
	return b
}

// CHAddr sets the client hardware address (max 16 bytes).
func (b *DHCPBuilder) CHAddr(addr []byte) *DHCPBuilder {
	b.layer.Set("chaddr", addr)
	return b
}

// Options sets the raw DHCP options bytes.
func (b *DHCPBuilder) Options(data []byte) *DHCPBuilder {
	b.layer.Set("options", data)
	return b
}

// MessageType sets the DHCP Message Type option (53) and updates the options field.
func (b *DHCPBuilder) MessageType(mt uint8) *DHCPBuilder {
	opts := []fields.TLVOption{dhcp.NewMessageTypeOption(mt)}
	b.layer.Set("options", dhcp.BuildDHCPOptions(opts))
	return b
}

// Over stacks an upper layer on top of this DHCP layer and returns a PacketBuilder.
func (b *DHCPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- IPv6Builder ----

// IPv6Builder builds IPv6 header layers.
type IPv6Builder struct {
	layer *packet.Layer
}

// NewIPv6 creates an IPv6 header builder with defaults (v6, hop limit=64).
func NewIPv6() *IPv6Builder {
	return &IPv6Builder{layer: layers.NewIPv6()}
}

func (b *IPv6Builder) Layer() *packet.Layer { return b.layer }

// SrcIP sets the source IPv6 address.
func (b *IPv6Builder) SrcIP(ip string) *IPv6Builder {
	b.layer.Set("src", ip)
	return b
}

// DstIP sets the destination IPv6 address.
func (b *IPv6Builder) DstIP(ip string) *IPv6Builder {
	b.layer.Set("dst", ip)
	return b
}

// NH sets the next header field.
func (b *IPv6Builder) NH(nh uint8) *IPv6Builder {
	b.layer.Set("nh", nh)
	return b
}

// HLim sets the hop limit field.
func (b *IPv6Builder) HLim(hlim uint8) *IPv6Builder {
	b.layer.Set("hlim", hlim)
	return b
}

// TC sets the traffic class field (updates the combined ver_tc_fl field).
func (b *IPv6Builder) TC(tc uint8) *IPv6Builder {
	v, _ := b.layer.Get("ver_tc_fl")
	fl := layers.IPv6FlowLabel(v.(uint32))
	b.layer.Set("ver_tc_fl", layers.MakeIPv6VerTCFL(tc, fl))
	return b
}

// FL sets the flow label field (updates the combined ver_tc_fl field).
func (b *IPv6Builder) FL(fl uint32) *IPv6Builder {
	v, _ := b.layer.Get("ver_tc_fl")
	tc := layers.IPv6TrafficClass(v.(uint32))
	b.layer.Set("ver_tc_fl", layers.MakeIPv6VerTCFL(tc, fl))
	return b
}

// Over stacks an upper layer on top of this IPv6 layer and returns a PacketBuilder.
func (b *IPv6Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- ICMPv6Builder ----

// ICMPv6Builder builds ICMPv6 base header layers.
type ICMPv6Builder struct {
	layer *packet.Layer
}

// NewICMPv6 creates an ICMPv6 base header builder (default: Echo Request, type=128).
func NewICMPv6() *ICMPv6Builder {
	return &ICMPv6Builder{layer: layers.NewICMPv6()}
}

func (b *ICMPv6Builder) Layer() *packet.Layer { return b.layer }

// Type sets the ICMPv6 type field.
func (b *ICMPv6Builder) Type(t uint8) *ICMPv6Builder {
	b.layer.Set("type", t)
	return b
}

// Code sets the ICMPv6 code field.
func (b *ICMPv6Builder) Code(c uint8) *ICMPv6Builder {
	b.layer.Set("code", c)
	return b
}

// Over stacks an upper layer on top of this ICMPv6 layer and returns a PacketBuilder.
func (b *ICMPv6Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- Dot1QBuilder ----

// Dot1QBuilder builds 802.1Q VLAN tag layers.
type Dot1QBuilder struct {
	layer *packet.Layer
}

// NewDot1Q creates a Dot1Q VLAN tag builder with default 802.1Q TPID.
func NewDot1Q() *Dot1QBuilder {
	return &Dot1QBuilder{layer: dot1q.NewDot1QLayer()}
}

func (b *Dot1QBuilder) Layer() *packet.Layer { return b.layer }

// VID sets the VLAN ID (12 bits, 0-4095).
func (b *Dot1QBuilder) VID(vid uint16) *Dot1QBuilder {
	tci, _ := b.layer.Get("tci")
	val := (tci.(uint16) & 0xF000) | (vid & 0x0FFF)
	b.layer.Set("tci", val)
	return b
}

// PCP sets the Priority Code Point (3 bits, 0-7).
func (b *Dot1QBuilder) PCP(pcp uint8) *Dot1QBuilder {
	tci, _ := b.layer.Get("tci")
	val := (tci.(uint16) & 0x1FFF) | (uint16(pcp&0x7) << 13)
	b.layer.Set("tci", val)
	return b
}

// DEI sets the Drop Eligible Indicator.
func (b *Dot1QBuilder) DEI(dei bool) *Dot1QBuilder {
	tci, _ := b.layer.Get("tci")
	val := tci.(uint16)
	if dei {
		val |= 0x1000
	} else {
		val &^= 0x1000
	}
	b.layer.Set("tci", val)
	return b
}

// Type sets the inner EtherType.
func (b *Dot1QBuilder) Type(etype uint16) *Dot1QBuilder {
	b.layer.Set("type", etype)
	return b
}

// TPID sets the Tag Protocol Identifier (default 0x8100, or 0x88A8 for QinQ).
func (b *Dot1QBuilder) TPID(tpid uint16) *Dot1QBuilder {
	b.layer.Set("tpid", tpid)
	return b
}

// Over stacks an upper layer on top of this Dot1Q layer and returns a PacketBuilder.
func (b *Dot1QBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- VXLANBuilder ----

// VXLANBuilder builds VXLAN encapsulation layers.
type VXLANBuilder struct {
	layer *packet.Layer
}

// NewVXLAN creates a VXLAN builder with default I flag set.
func NewVXLAN() *VXLANBuilder {
	return &VXLANBuilder{layer: vxlan.NewVXLANLayer()}
}

func (b *VXLANBuilder) Layer() *packet.Layer { return b.layer }

// VNI sets the VXLAN Network Identifier (24 bits, 0-16777215).
func (b *VXLANBuilder) VNI(vni uint32) *VXLANBuilder {
	b.layer.Set("vni", vni&0xFFFFFF)
	return b
}

// Flags sets the VXLAN flags byte.
func (b *VXLANBuilder) Flags(flags uint8) *VXLANBuilder {
	b.layer.Set("flags", flags)
	return b
}

// Over stacks an upper layer on top of this VXLAN layer and returns a PacketBuilder.
func (b *VXLANBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- GREBuilder ----

// GREBuilder builds GRE tunnel encapsulation layers.
type GREBuilder struct {
	layer *packet.Layer
}

// NewGRE creates a GRE builder with default ProtocolType=0x0800 (IP).
func NewGRE() *GREBuilder {
	return &GREBuilder{layer: gre.NewGRELayer()}
}

func (b *GREBuilder) Layer() *packet.Layer { return b.layer }

// ProtocolType sets the GRE Protocol Type (e.g. 0x0800 for IP, 0x6558 for Ethernet).
func (b *GREBuilder) ProtocolType(pt uint16) *GREBuilder {
	b.layer.Set("proto", pt)
	return b
}

// Key sets the GRE Key field and enables the K flag.
func (b *GREBuilder) Key(k uint32) *GREBuilder {
	b.layer.Set("key", k)
	flags, _ := b.layer.Get("flagsver")
	b.layer.Set("flagsver", flags.(uint16)|gre.FlagK)
	return b
}

// Seq sets the GRE Sequence Number and enables the S flag.
func (b *GREBuilder) Seq(s uint32) *GREBuilder {
	b.layer.Set("seq", s)
	flags, _ := b.layer.Get("flagsver")
	b.layer.Set("flagsver", flags.(uint16)|gre.FlagS)
	return b
}

// SetChecksum sets the GRE Checksum and enables the C flag.
func (b *GREBuilder) SetChecksum(csum uint16) *GREBuilder {
	b.layer.Set("chksum", csum)
	b.layer.Set("reserved1", uint16(0))
	flags, _ := b.layer.Get("flagsver")
	b.layer.Set("flagsver", flags.(uint16)|gre.FlagC)
	return b
}

// Over stacks an upper layer on top of this GRE layer and returns a PacketBuilder.
func (b *GREBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- LLDPBuilder ----

// LLDPBuilder builds LLDP frame layers.
type LLDPBuilder struct {
	layer *packet.Layer
}

// NewLLDPLayer creates an LLDP builder with default TLV data.
func NewLLDPLayer() *LLDPBuilder {
	return &LLDPBuilder{layer: lldp.NewLLDP()}
}

func (b *LLDPBuilder) Layer() *packet.Layer { return b.layer }

// TLVData sets the raw TLV data bytes.
func (b *LLDPBuilder) TLVData(data []byte) *LLDPBuilder {
	b.layer.Set("tlv_data", data)
	return b
}

// LLDPDU sets the TLV data from a structured LLDPDU.
func (b *LLDPBuilder) LLDPDU(du *lldp.LLDPDU) *LLDPBuilder {
	data, err := du.Serialize()
	if err != nil {
		return b
	}
	b.layer.Set("tlv_data", data)
	return b
}

// ---- ERSPANBuilder ----

// ERSPANBuilder builds ERSPAN v3 encapsulation layers.
type ERSPANBuilder struct {
	layer *packet.Layer
}

// NewERSPANLayer creates an ERSPAN v3 builder with default values.
func NewERSPANLayer() *ERSPANBuilder {
	return &ERSPANBuilder{layer: erspan.NewERSPAN()}
}

func (b *ERSPANBuilder) Layer() *packet.Layer { return b.layer }

// FromERSPAN sets the layer fields from an ERSPAN struct.
func (b *ERSPANBuilder) FromERSPAN(e *erspan.ERSPAN) *ERSPANBuilder {
	data, err := e.Serialize()
	if err != nil {
		return b
	}
	// Set individual fields from serialized data
	b.layer.Set("ver_vlan_hi", data[0])
	b.layer.Set("vlan_lo_cos_bso_en", uint16(data[1])<<8|uint16(data[2]))
	b.layer.Set("session_id_flags", data[3])
	b.layer.Set("reserved", data[4])
	ts := uint32(data[5])<<24 | uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	b.layer.Set("timestamp", ts)
	b.layer.Set("sgt_p_ft", uint16(data[9])<<8|uint16(data[10]))
	b.layer.Set("offset_hw", uint16(data[11])<<8)
	return b
}

// ---- OSPFBuilder ----

// OSPFBuilder builds OSPFv2 header layers.
type OSPFBuilder struct {
	layer *packet.Layer
}

// NewOSPFLayer creates an OSPFv2 header builder with default values.
func NewOSPFLayer() *OSPFBuilder {
	return &OSPFBuilder{layer: ospf.NewOSPF()}
}

func (b *OSPFBuilder) Layer() *packet.Layer { return b.layer }

// RouterID sets the OSPF Router ID.
func (b *OSPFBuilder) RouterID(ip string) *OSPFBuilder {
	b.layer.Set("router_id", ip)
	return b
}

// AreaID sets the OSPF Area ID.
func (b *OSPFBuilder) AreaID(ip string) *OSPFBuilder {
	b.layer.Set("area_id", ip)
	return b
}

// Type sets the OSPF message type (Hello, DBD, LSR, LSU, LSAck).
func (b *OSPFBuilder) Type(t uint8) *OSPFBuilder {
	b.layer.Set("type", t)
	return b
}

// Over stacks an upper layer on top of this OSPF layer and returns a PacketBuilder.
func (b *OSPFBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- BGPBuilder ----

// BGPBuilder builds BGP common header layers.
type BGPBuilder struct {
	layer *packet.Layer
}

// NewBGPLayer creates a BGP common header builder with default values.
func NewBGPLayer() *BGPBuilder {
	return &BGPBuilder{layer: bgp.NewBGP()}
}

func (b *BGPBuilder) Layer() *packet.Layer { return b.layer }

// Type sets the BGP message type (OPEN, UPDATE, NOTIFICATION, KEEPALIVE).
func (b *BGPBuilder) Type(t uint8) *BGPBuilder {
	b.layer.Set("type", t)
	return b
}

// Over stacks an upper layer on top of this BGP layer and returns a PacketBuilder.
func (b *BGPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- QUICBuilder ----

// QUICBuilder builds QUIC packet layers.
type QUICBuilder struct {
	layer *packet.Layer
}

// NewQUICLayer creates a QUIC Long Header builder with default values.
func NewQUICLayer() *QUICBuilder {
	return &QUICBuilder{layer: quic.NewQUICLongHeader()}
}

func (b *QUICBuilder) Layer() *packet.Layer { return b.layer }

// Version sets the QUIC version.
func (b *QUICBuilder) Version(v uint32) *QUICBuilder {
	b.layer.Set("version", v)
	return b
}

// DCID sets the Destination Connection ID.
func (b *QUICBuilder) DCID(cid []byte) *QUICBuilder {
	b.layer.Set("dcid", cid)
	return b
}

// SCID sets the Source Connection ID.
func (b *QUICBuilder) SCID(cid []byte) *QUICBuilder {
	b.layer.Set("scid", cid)
	return b
}

// Over stacks an upper layer on top of this QUIC layer and returns a PacketBuilder.
func (b *QUICBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- HTTPBuilder ----

// HTTPBuilder builds HTTP message layers.
type HTTPBuilder struct {
	layer *packet.Layer
}

// NewHTTP creates an HTTP message builder.
func NewHTTP() *HTTPBuilder {
	return &HTTPBuilder{layer: layershttp.NewHTTP()}
}

func (b *HTTPBuilder) Layer() *packet.Layer { return b.layer }

// Request builds a raw HTTP request and sets it as the layer data.
func (b *HTTPBuilder) Request(method, path string, headers map[string]string, body []byte) *HTTPBuilder {
	raw := layershttp.BuildHTTPRequest(layershttp.HTTPRequest{
		Method:  method,
		Path:    path,
		Version: "HTTP/1.1",
		Headers: headers,
		Body:    body,
	})
	b.layer.Set("raw", raw)
	return b
}

// Response builds a raw HTTP response and sets it as the layer data.
func (b *HTTPBuilder) Response(statusCode int, headers map[string]string, body []byte) *HTTPBuilder {
	raw := layershttp.BuildHTTPResponse(layershttp.HTTPResponse{
		Version:    "HTTP/1.1",
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	})
	b.layer.Set("raw", raw)
	return b
}

// Raw sets the raw HTTP bytes directly.
func (b *HTTPBuilder) Raw(data []byte) *HTTPBuilder {
	b.layer.Set("raw", data)
	return b
}

// Over stacks an upper layer on top of this HTTP layer and returns a PacketBuilder.
func (b *HTTPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- NTPBuilder ----

// NTPBuilder builds NTP protocol layers.
type NTPBuilder struct {
	layer *packet.Layer
}

// NewNTP creates an NTP layer builder.
func NewNTP() *NTPBuilder {
	return &NTPBuilder{layer: ntp.NewNTP()}
}

func (b *NTPBuilder) Layer() *packet.Layer { return b.layer }

// LVM sets the LI/VN/Mode byte directly.
func (b *NTPBuilder) LVM(val uint8) *NTPBuilder {
	b.layer.Set("lvm", val)
	return b
}

// Mode sets the NTP mode using LI, VN, and mode values.
func (b *NTPBuilder) Mode(li, vn, mode uint8) *NTPBuilder {
	b.layer.Set("lvm", ntp.SetLVM(li, vn, mode))
	return b
}

// Stratum sets the stratum field.
func (b *NTPBuilder) Stratum(s uint8) *NTPBuilder {
	b.layer.Set("stratum", s)
	return b
}

// Poll sets the poll interval (log2 seconds).
func (b *NTPBuilder) Poll(p uint8) *NTPBuilder {
	b.layer.Set("poll", p)
	return b
}

// Precision sets the precision field (log2 seconds, stored as uint8).
func (b *NTPBuilder) Precision(p uint8) *NTPBuilder {
	b.layer.Set("precision", p)
	return b
}

// RootDelay sets the root delay (16.16 fixed-point).
func (b *NTPBuilder) RootDelay(d uint32) *NTPBuilder {
	b.layer.Set("rootdelay", d)
	return b
}

// RootDispersion sets the root dispersion (16.16 fixed-point).
func (b *NTPBuilder) RootDispersion(d uint32) *NTPBuilder {
	b.layer.Set("rootdispersion", d)
	return b
}

// RefID sets the reference identifier.
func (b *NTPBuilder) RefID(id uint32) *NTPBuilder {
	b.layer.Set("refid", id)
	return b
}

// RefTimestamp sets the reference timestamp.
func (b *NTPBuilder) RefTimestamp(ts uint64) *NTPBuilder {
	b.layer.Set("reftimestamp", ts)
	return b
}

// OrigTimestamp sets the originate timestamp.
func (b *NTPBuilder) OrigTimestamp(ts uint64) *NTPBuilder {
	b.layer.Set("origtimestamp", ts)
	return b
}

// RecvTimestamp sets the receive timestamp.
func (b *NTPBuilder) RecvTimestamp(ts uint64) *NTPBuilder {
	b.layer.Set("recvtimestamp", ts)
	return b
}

// XmitTimestamp sets the transmit timestamp.
func (b *NTPBuilder) XmitTimestamp(ts uint64) *NTPBuilder {
	b.layer.Set("xtimestamp", ts)
	return b
}

// Over stacks an upper layer on top of this NTP layer and returns a PacketBuilder.
func (b *NTPBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- Dot11Builder ----

// Dot11Builder builds IEEE 802.11 WiFi frame layers.
type Dot11Builder struct {
	layer *packet.Layer
}

// NewDot11 creates an 802.11 frame builder.
func NewDot11() *Dot11Builder {
	return &Dot11Builder{layer: dot11.NewDot11()}
}

func (b *Dot11Builder) Layer() *packet.Layer { return b.layer }

// FC sets the Frame Control bytes directly.
func (b *Dot11Builder) FC(fc0, fc1 uint8) *Dot11Builder {
	b.layer.Set("fc0", fc0)
	b.layer.Set("fc1", fc1)
	return b
}

// TypeSubtype sets frame type and subtype via helper.
func (b *Dot11Builder) TypeSubtype(ftype, subtype, flags uint8) *Dot11Builder {
	fc := dot11.SetFC(ftype, subtype, flags)
	b.layer.Set("fc0", fc[0])
	b.layer.Set("fc1", fc[1])
	return b
}

// Addr1 sets the receiver address (addr1).
func (b *Dot11Builder) Addr1(mac string) *Dot11Builder {
	b.layer.Set("addr1", mac)
	return b
}

// Addr2 sets the transmitter address (addr2).
func (b *Dot11Builder) Addr2(mac string) *Dot11Builder {
	b.layer.Set("addr2", mac)
	return b
}

// Addr3 sets the BSSID/filter address (addr3).
func (b *Dot11Builder) Addr3(mac string) *Dot11Builder {
	b.layer.Set("addr3", mac)
	return b
}

// SC sets the sequence control field.
func (b *Dot11Builder) SC(sc uint16) *Dot11Builder {
	b.layer.Set("sc", sc)
	return b
}

// Duration sets the duration/ID field.
func (b *Dot11Builder) Duration(d uint16) *Dot11Builder {
	b.layer.Set("duration", d)
	return b
}

// Over stacks an upper layer on top of this Dot11 layer.
func (b *Dot11Builder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- RadioTapBuilder ----

// RadioTapBuilder builds RadioTap header layers.
type RadioTapBuilder struct {
	layer *packet.Layer
}

// NewRadioTap creates a RadioTap header builder.
func NewRadioTap() *RadioTapBuilder {
	return &RadioTapBuilder{layer: dot11.NewRadioTap()}
}

func (b *RadioTapBuilder) Layer() *packet.Layer { return b.layer }

// Present sets the presence bitmap.
func (b *RadioTapBuilder) Present(flags uint32) *RadioTapBuilder {
	b.layer.Set("present", flags)
	return b
}

// Data sets the variable-length field data.
func (b *RadioTapBuilder) Data(data []byte) *RadioTapBuilder {
	b.layer.Set("data", data)
	return b
}

// Over stacks an upper layer on top of this RadioTap layer.
func (b *RadioTapBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}

// ---- TLSBuilder ----

// TLSBuilder builds TLS record layers.
type TLSBuilder struct {
	layer *packet.Layer
}

// NewTLS creates a TLS record builder.
func NewTLS() *TLSBuilder {
	return &TLSBuilder{layer: layerstls.NewTLS()}
}

func (b *TLSBuilder) Layer() *packet.Layer { return b.layer }

// ContentType sets the content type (20=CCS, 21=Alert, 22=Handshake, 23=App).
func (b *TLSBuilder) ContentType(ct uint8) *TLSBuilder {
	b.layer.Set("content_type", ct)
	return b
}

// Version sets the TLS version.
func (b *TLSBuilder) Version(v uint16) *TLSBuilder {
	b.layer.Set("version", v)
	return b
}

// Fragment sets the raw fragment data.
func (b *TLSBuilder) Fragment(data []byte) *TLSBuilder {
	b.layer.Set("fragment", data)
	return b
}

// Handshake sets the fragment to a handshake message with proper framing.
func (b *TLSBuilder) Handshake(hsType uint8, body []byte) *TLSBuilder {
	b.layer.Set("content_type", uint8(layerstls.ContentTypeHandshake))
	frag := make([]byte, 4+len(body))
	frag[0] = hsType
	frag[1] = byte(len(body) >> 16)
	frag[2] = byte(len(body) >> 8)
	frag[3] = byte(len(body))
	copy(frag[4:], body)
	b.layer.Set("fragment", frag)
	return b
}

// Alert sets the fragment to a TLS alert message.
func (b *TLSBuilder) Alert(level, desc uint8) *TLSBuilder {
	b.layer.Set("content_type", uint8(layerstls.ContentTypeAlert))
	b.layer.Set("fragment", []byte{level, desc})
	return b
}

// Over stacks an upper layer on top of this TLS layer.
func (b *TLSBuilder) Over(upper LayerBuilder) *PacketBuilder {
	pkt := b.layer.Over(upper.Layer())
	return &PacketBuilder{pkt: pkt}
}
