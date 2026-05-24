package tls

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// TLS ContentType constants.
const (
	ContentTypeChangeCipherSpec uint8 = 20
	ContentTypeAlert            uint8 = 21
	ContentTypeHandshake        uint8 = 22
	ContentTypeApplication      uint8 = 23
)

// TLS HandshakeType constants.
const (
	HandshakeTypeClientHello        uint8 = 1
	HandshakeTypeServerHello        uint8 = 2
	HandshakeTypeCertificate        uint8 = 11
	HandshakeTypeServerKeyExchange  uint8 = 12
	HandshakeTypeCertificateRequest uint8 = 13
	HandshakeTypeServerHelloDone    uint8 = 14
	HandshakeTypeCertificateVerify  uint8 = 15
	HandshakeTypeClientKeyExchange  uint8 = 16
	HandshakeTypeFinished           uint8 = 20
)

// TLS Version constants.
const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// TLS Alert level constants.
const (
	AlertLevelWarning uint8 = 1
	AlertLevelFatal   uint8 = 2
)

// TLS Alert description constants.
const (
	AlertCloseNotify          uint8 = 0
	AlertUnexpectedMessage    uint8 = 10
	AlertBadRecordMAC         uint8 = 20
	AlertHandshakeFailure     uint8 = 40
	AlertBadCertificate       uint8 = 42
	AlertCertificateRevoked   uint8 = 44
	AlertCertificateExpired   uint8 = 45
	AlertIllegalParameter     uint8 = 47
	AlertDecodeError          uint8 = 50
	AlertProtocolVersion      uint8 = 70
	AlertInternalError        uint8 = 80
	AlertInappropriateFallback uint8 = 86
	AlertNoApplicationProtocol uint8 = 120
)

// TLS Extension type constants.
const (
	ExtTypeServerName         uint16 = 0
	ExtTypeSupportedGroups    uint16 = 10
	ExtTypeSignatureAlgorithms uint16 = 13
	ExtTypeALPN               uint16 = 16
	ExtTypeKeyShare           uint16 = 51
	ExtTypeSupportedVersions  uint16 = 43
)

// ---- TLS Record Layer ----

// NewTLS creates a TLS record layer.
func NewTLS() *packet.Layer {
	return packet.NewLayer("TLS", []fields.Field{
		fields.NewByteField("content_type", ContentTypeHandshake),
		fields.NewShortField("version", VersionTLS12),
		fields.NewShortField("length", 0), // auto-set during build
		fields.NewStrField("fragment", ""),
	})
}

// ---- TLS Handshake Layer ----

// NewTLSHandshake creates a TLS handshake layer.
func NewTLSHandshake() *packet.Layer {
	return packet.NewLayer("TLSHandshake", []fields.Field{
		fields.NewByteField("handshake_type", HandshakeTypeClientHello),
		fields.NewThreeBytesField("length", 0),
		fields.NewStrField("body", ""),
	})
}

// ---- TLS ClientHello ----

// ClientHello represents a parsed TLS ClientHello message.
type ClientHello struct {
	Version         uint16
	Random         []byte // 32 bytes
	SessionID      []byte
	CipherSuites   []uint16
	Compression    []uint8
	Extensions     []Extension
}

// ServerHello represents a parsed TLS ServerHello message.
type ServerHello struct {
	Version       uint16
	Random       []byte // 32 bytes
	SessionID    []byte
	CipherSuite  uint16
	Compression  uint8
	Extensions   []Extension
}

// Extension represents a TLS extension.
type Extension struct {
	Type   uint16
	Data   []byte
}

// CertificateEntry represents a single certificate in the chain.
type CertificateEntry struct {
	Data []byte // DER-encoded certificate
}

// Alert represents a TLS alert message.
type Alert struct {
	Level       uint8
	Description uint8
}

// ---- Parse helpers ----

// ParseHandshake parses a TLS handshake message from raw bytes.
// Returns the handshake type, length, and body.
func ParseHandshake(data []byte) (hsType uint8, length int, body []byte, err error) {
	if len(data) < 4 {
		return 0, 0, nil, fmt.Errorf("tls: handshake header too short: %d bytes", len(data))
	}
	hsType = data[0]
	length = int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+length {
		return hsType, length, data[4:], fmt.Errorf("tls: handshake body truncated: need %d, have %d", length, len(data)-4)
	}
	return hsType, length, data[4 : 4+length], nil
}

// ParseClientHello parses a ClientHello from the handshake body.
func ParseClientHello(body []byte) (*ClientHello, error) {
	if len(body) < 34 {
		return nil, fmt.Errorf("tls: ClientHello too short: %d bytes", len(body))
	}
	pos := 0
	ch := &ClientHello{}

	ch.Version = binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2

	ch.Random = make([]byte, 32)
	copy(ch.Random, body[pos:pos+32])
	pos += 32

	// Session ID
	if pos >= len(body) {
		return nil, fmt.Errorf("tls: ClientHello truncated at session ID")
	}
	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return nil, fmt.Errorf("tls: ClientHello session ID overflows")
	}
	ch.SessionID = make([]byte, sidLen)
	copy(ch.SessionID, body[pos:pos+sidLen])
	pos += sidLen

	// Cipher suites
	if pos+2 > len(body) {
		return nil, fmt.Errorf("tls: ClientHello truncated at cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+csLen > len(body) {
		return nil, fmt.Errorf("tls: ClientHello cipher suites overflows")
	}
	numSuites := csLen / 2
	ch.CipherSuites = make([]uint16, numSuites)
	for i := 0; i < numSuites; i++ {
		ch.CipherSuites[i] = binary.BigEndian.Uint16(body[pos+i*2 : pos+i*2+2])
	}
	pos += csLen

	// Compression methods
	if pos >= len(body) {
		return nil, fmt.Errorf("tls: ClientHello truncated at compression")
	}
	compLen := int(body[pos])
	pos++
	if pos+compLen > len(body) {
		return nil, fmt.Errorf("tls: ClientHello compression overflows")
	}
	ch.Compression = make([]uint8, compLen)
	copy(ch.Compression, body[pos:pos+compLen])
	pos += compLen

	// Extensions (optional)
	if pos+2 <= len(body) {
		extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		pos += 2
		extEnd := pos + extLen
		if extEnd > len(body) {
			extEnd = len(body)
		}
		for pos+4 <= extEnd {
			extType := binary.BigEndian.Uint16(body[pos : pos+2])
			extDataLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
			pos += 4
			if pos+extDataLen > extEnd {
				break
			}
			extData := make([]byte, extDataLen)
			copy(extData, body[pos:pos+extDataLen])
			ch.Extensions = append(ch.Extensions, Extension{Type: extType, Data: extData})
			pos += extDataLen
		}
	}

	return ch, nil
}

// ParseServerHello parses a ServerHello from the handshake body.
func ParseServerHello(body []byte) (*ServerHello, error) {
	if len(body) < 34 {
		return nil, fmt.Errorf("tls: ServerHello too short: %d bytes", len(body))
	}
	pos := 0
	sh := &ServerHello{}

	sh.Version = binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2

	sh.Random = make([]byte, 32)
	copy(sh.Random, body[pos:pos+32])
	pos += 32

	// Session ID
	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return nil, fmt.Errorf("tls: ServerHello session ID overflows")
	}
	sh.SessionID = make([]byte, sidLen)
	copy(sh.SessionID, body[pos:pos+sidLen])
	pos += sidLen

	// Cipher suite
	if pos+2 > len(body) {
		return nil, fmt.Errorf("tls: ServerHello truncated at cipher suite")
	}
	sh.CipherSuite = binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2

	// Compression
	if pos >= len(body) {
		return nil, fmt.Errorf("tls: ServerHello truncated at compression")
	}
	sh.Compression = body[pos]
	pos++

	// Extensions (optional)
	if pos+2 <= len(body) {
		extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		pos += 2
		extEnd := pos + extLen
		if extEnd > len(body) {
			extEnd = len(body)
		}
		for pos+4 <= extEnd {
			extType := binary.BigEndian.Uint16(body[pos : pos+2])
			extDataLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
			pos += 4
			if pos+extDataLen > extEnd {
				break
			}
			extData := make([]byte, extDataLen)
			copy(extData, body[pos:pos+extDataLen])
			sh.Extensions = append(sh.Extensions, Extension{Type: extType, Data: extData})
			pos += extDataLen
		}
	}

	return sh, nil
}

// ParseCertificate parses a Certificate handshake message.
func ParseCertificate(body []byte) ([]CertificateEntry, error) {
	if len(body) < 3 {
		return nil, fmt.Errorf("tls: Certificate too short")
	}
	totalLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	pos := 3
	end := pos + totalLen
	if end > len(body) {
		end = len(body)
	}

	var certs []CertificateEntry
	for pos+3 <= end {
		certLen := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
		pos += 3
		if pos+certLen > end {
			break
		}
		certData := make([]byte, certLen)
		copy(certData, body[pos:pos+certLen])
		certs = append(certs, CertificateEntry{Data: certData})
		pos += certLen
	}
	return certs, nil
}

// ParseAlert parses a TLS alert from the fragment data.
func ParseAlert(data []byte) (*Alert, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("tls: alert too short: %d bytes", len(data))
	}
	return &Alert{Level: data[0], Description: data[1]}, nil
}

// ---- Extension helpers ----

// FindExtension finds the first extension with the given type.
func FindExtension(exts []Extension, extType uint16) *Extension {
	for i := range exts {
		if exts[i].Type == extType {
			return &exts[i]
		}
	}
	return nil
}

// ParseSNI extracts the Server Name Indication from extensions.
// Returns the hostname or empty string.
func ParseSNI(exts []Extension) string {
	ext := FindExtension(exts, ExtTypeServerName)
	if ext == nil || len(ext.Data) < 5 {
		return ""
	}
	// ServerNameList length (2 bytes), then ServerNameType (1), NameLength (2), Name
	listLen := int(binary.BigEndian.Uint16(ext.Data[0:2]))
	if listLen < 4 || len(ext.Data) < 5+int(ext.Data[4]) {
		_ = listLen
	}
	nameType := ext.Data[2] // 0 = hostname
	if nameType != 0 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(ext.Data[3:5]))
	if 5+nameLen > len(ext.Data) {
		return ""
	}
	return string(ext.Data[5 : 5+nameLen])
}

// ParseALPN extracts ALPN protocols from extensions.
func ParseALPN(exts []Extension) []string {
	ext := FindExtension(exts, ExtTypeALPN)
	if ext == nil || len(ext.Data) < 2 {
		return nil
	}
	pos := 0
	listLen := int(binary.BigEndian.Uint16(ext.Data[pos : pos+2]))
	pos += 2
	end := pos + listLen
	if end > len(ext.Data) {
		end = len(ext.Data)
	}
	var protos []string
	for pos+1 <= end {
		protoLen := int(ext.Data[pos])
		pos++
		if pos+protoLen > end {
			break
		}
		protos = append(protos, string(ext.Data[pos:pos+protoLen]))
		pos += protoLen
	}
	return protos
}

// ParseSupportedGroups extracts supported groups from extensions.
func ParseSupportedGroups(exts []Extension) []uint16 {
	ext := FindExtension(exts, ExtTypeSupportedGroups)
	if ext == nil || len(ext.Data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(ext.Data[0:2]))
	numGroups := listLen / 2
	if 2+listLen > len(ext.Data) {
		return nil
	}
	groups := make([]uint16, numGroups)
	for i := 0; i < numGroups; i++ {
		groups[i] = binary.BigEndian.Uint16(ext.Data[2+i*2 : 4+i*2])
	}
	return groups
}

// ---- Build helpers ----

// BuildClientHello constructs a raw ClientHello handshake body.
func BuildClientHello(ch *ClientHello) []byte {
	if ch.Random == nil {
		ch.Random = make([]byte, 32)
	}
	if ch.Version == 0 {
		ch.Version = VersionTLS12
	}

	var buf []byte
	buf = append(buf, byte(ch.Version>>8), byte(ch.Version))
	buf = append(buf, ch.Random...)
	buf = append(buf, byte(len(ch.SessionID)))
	buf = append(buf, ch.SessionID...)

	// Cipher suites
	csData := make([]byte, len(ch.CipherSuites)*2)
	for i, cs := range ch.CipherSuites {
		binary.BigEndian.PutUint16(csData[i*2:], cs)
	}
	buf = append(buf, byte(len(csData)>>8), byte(len(csData)))
	buf = append(buf, csData...)

	// Compression
	buf = append(buf, byte(len(ch.Compression)))
	buf = append(buf, ch.Compression...)

	// Extensions
	if len(ch.Extensions) > 0 {
		extData := BuildExtensions(ch.Extensions)
		buf = append(buf, byte(len(extData)>>8), byte(len(extData)))
		buf = append(buf, extData...)
	}

	return buf
}

// BuildExtensions serializes a list of TLS extensions.
func BuildExtensions(exts []Extension) []byte {
	var buf []byte
	for _, ext := range exts {
		buf = append(buf, byte(ext.Type>>8), byte(ext.Type))
		buf = append(buf, byte(len(ext.Data)>>8), byte(len(ext.Data)))
		buf = append(buf, ext.Data...)
	}
	return buf
}

// BuildSNIExtension creates an SNI extension with the given hostname.
func BuildSNIExtension(hostname string) Extension {
	name := []byte(hostname)
	data := make([]byte, 5+len(name))
	// ServerNameList length
	binary.BigEndian.PutUint16(data[0:2], uint16(3+len(name)))
	data[2] = 0 // host_name type
	binary.BigEndian.PutUint16(data[3:5], uint16(len(name)))
	copy(data[5:], name)
	return Extension{Type: ExtTypeServerName, Data: data}
}

// ContentTypeString returns a human-readable name for a content type.
func ContentTypeString(ct uint8) string {
	switch ct {
	case ContentTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case ContentTypeAlert:
		return "Alert"
	case ContentTypeHandshake:
		return "Handshake"
	case ContentTypeApplication:
		return "Application"
	default:
		return fmt.Sprintf("Unknown(%d)", ct)
	}
}

// HandshakeTypeString returns a human-readable name for a handshake type.
func HandshakeTypeString(ht uint8) string {
	switch ht {
	case HandshakeTypeClientHello:
		return "ClientHello"
	case HandshakeTypeServerHello:
		return "ServerHello"
	case HandshakeTypeCertificate:
		return "Certificate"
	case HandshakeTypeServerKeyExchange:
		return "ServerKeyExchange"
	case HandshakeTypeCertificateRequest:
		return "CertificateRequest"
	case HandshakeTypeServerHelloDone:
		return "ServerHelloDone"
	case HandshakeTypeCertificateVerify:
		return "CertificateVerify"
	case HandshakeTypeClientKeyExchange:
		return "ClientKeyExchange"
	case HandshakeTypeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("Unknown(%d)", ht)
	}
}

func init() {
	packet.RegisterLayer("TLS", NewTLS)
}
