// 示例 47: TLS 层构建与解析
//
// 运行: go run main.go
package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers/tls"
)

func main() {
	fmt.Println("=== TLS 层示例 ===")
	fmt.Println()

	// 1. 构建一个 TLS ClientHello
	fmt.Println("--- 1. 构建 TLS ClientHello ---")
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}

	ch := &tls.ClientHello{
		Version:      tls.VersionTLS12,
		Random:       random,
		CipherSuites: []uint16{0xC02F, 0xC030, 0xC02B, 0x009E, 0x009C},
		Compression:  []uint8{0},
		Extensions: []tls.Extension{
			tls.BuildSNIExtension("example.com"),
			{Type: tls.ExtTypeSupportedGroups, Data: []byte{0x00, 0x04, 0x00, 0x17, 0x00, 0x18}},
		},
	}

	chBody := tls.BuildClientHello(ch)
	fmt.Printf("  ClientHello body: %d bytes\n", len(chBody))

	// 2. 使用 Builder API 构建 TLS 记录
	fmt.Println("--- 2. 构建 TLS 记录 ---")
	tlsPkt := goscapy.NewTLS().
		Handshake(tls.HandshakeTypeClientHello, chBody)

	pkt := goscapy.NewIP().
		SrcIP("192.168.1.100").
		DstIP("93.184.216.34").
		Over(goscapy.NewTCP().SrcPort(54321).DstPort(443)).
		Over(tlsPkt)

	raw, err := pkt.Build()
	if err != nil {
		fmt.Printf("Build 失败: %v\n", err)
		return
	}
	fmt.Printf("  IP+TCP+TLS 数据包: %d bytes\n", len(raw))

	// 3. 解析 TLS 记录
	fmt.Println("--- 3. 解析 TLS 记录 ---")
	record := tls.NewTLS()
	// Manually build TLS record bytes
	record.Set("content_type", uint8(tls.ContentTypeHandshake))
	record.Set("version", uint16(tls.VersionTLS12))
	record.Set("fragment", append([]byte{0x01, 0x00, 0x00, byte(len(chBody))}, chBody...))

	recData, _ := record.SerializeFields()
	fmt.Printf("  TLS record: %d bytes\n", len(recData))
	fmt.Printf("  ContentType: %s\n", tls.ContentTypeString(recData[0]))

	// 4. 解析 ClientHello
	fmt.Println("--- 4. 解析 ClientHello ---")
	parsed, err := tls.ParseClientHello(chBody)
	if err != nil {
		fmt.Printf("ParseClientHello: %v\n", err)
		return
	}
	fmt.Printf("  Version: %#x\n", parsed.Version)
	fmt.Printf("  CipherSuites (%d):", len(parsed.CipherSuites))
	for _, cs := range parsed.CipherSuites {
		fmt.Printf(" %#x", cs)
	}
	fmt.Println()

	sni := tls.ParseSNI(parsed.Extensions)
	fmt.Printf("  SNI: %q\n", sni)

	groups := tls.ParseSupportedGroups(parsed.Extensions)
	fmt.Printf("  Supported Groups: %v\n", groups)

	// 5. 构建和解析 Alert
	fmt.Println("--- 5. TLS Alert ---")
	alertPkt := goscapy.NewTLS().
		ContentType(tls.ContentTypeAlert).
		Alert(tls.AlertLevelFatal, tls.AlertHandshakeFailure)

	alertData, err := alertPkt.Layer().SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	parsedAlert, err := tls.ParseAlert(alertData[5:]) // skip 5-byte record header
	if err != nil {
		fmt.Printf("ParseAlert: %v\n", err)
		return
	}
	fmt.Printf("  Alert: level=%d desc=%d\n", parsedAlert.Level, parsedAlert.Description)

	// 6. 解析 ServerHello
	fmt.Println("--- 6. 模拟 ServerHello ---")
	sh := &tls.ServerHello{
		Version:      tls.VersionTLS12,
		Random:       make([]byte, 32),
		CipherSuite:  0xC02F,
		Compression:  0,
	}
	shBody := buildServerHello(sh)
	parsedSH, err := tls.ParseServerHello(shBody)
	if err != nil {
		fmt.Printf("ParseServerHello: %v\n", err)
		return
	}
	fmt.Printf("  Version: %#x  CipherSuite: %#x\n", parsedSH.Version, parsedSH.CipherSuite)

	// 7. 解析 Certificate
	fmt.Println("--- 7. 解析 Certificate ---")
	dummyCert := []byte("dummy-cert-der-data")
	var certMsg []byte
	totalLen := 3 + len(dummyCert)
	certMsg = append(certMsg, byte(totalLen>>16), byte(totalLen>>8), byte(totalLen))
	certMsg = append(certMsg, byte(len(dummyCert)>>16), byte(len(dummyCert)>>8), byte(len(dummyCert)))
	certMsg = append(certMsg, dummyCert...)

	certs, err := tls.ParseCertificate(certMsg)
	if err != nil {
		fmt.Printf("ParseCertificate: %v\n", err)
		return
	}
	fmt.Printf("  Certificates: %d entries\n", len(certs))
	fmt.Printf("  Cert[0] size: %d bytes\n", len(certs[0].Data))
}

func buildServerHello(sh *tls.ServerHello) []byte {
	if sh.Random == nil {
		sh.Random = make([]byte, 32)
	}
	var buf []byte
	buf = append(buf, byte(sh.Version>>8), byte(sh.Version))
	buf = append(buf, sh.Random...)
	buf = append(buf, byte(len(sh.SessionID)))
	buf = append(buf, sh.SessionID...)
	buf = append(buf, byte(sh.CipherSuite>>8), byte(sh.CipherSuite))
	buf = append(buf, sh.Compression)
	return buf
}
