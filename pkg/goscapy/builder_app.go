package goscapy

import (
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/layers/dhcp"
	"github.com/smallnest/goscapy/pkg/layers/dns"
	layershttp "github.com/smallnest/goscapy/pkg/layers/http"
	"github.com/smallnest/goscapy/pkg/layers/ntp"
	layerstls "github.com/smallnest/goscapy/pkg/layers/tls"
	"github.com/smallnest/goscapy/pkg/packet"
)

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
