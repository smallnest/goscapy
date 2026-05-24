// 示例 44: HTTP 层构建与解析
//
// 运行: go run main.go
package main

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	layershttp "github.com/smallnest/goscapy/pkg/layers/http"
)

func main() {
	fmt.Println("=== HTTP 层示例 ===")
	fmt.Println()

	// 1. 构建 HTTP GET 请求
	fmt.Println("--- 1. 构建 HTTP GET 请求 ---")
	reqRaw := layershttp.BuildHTTPRequest(layershttp.HTTPRequest{
		Method: layershttp.MethodGet,
		Path:   "/api/data?key=value",
		Headers: map[string]string{
			"Host":            "example.com",
			"Accept":          "application/json",
			"User-Agent":      "goscapy/1.0",
			"Accept-Encoding": "gzip",
		},
	})
	fmt.Printf("%s\n", reqRaw)

	// 2. 构建 HTTP POST 请求 (带 Body)
	fmt.Println("--- 2. 构建 HTTP POST 请求 ---")
	postRaw := layershttp.BuildHTTPRequest(layershttp.HTTPRequest{
		Method: layershttp.MethodPost,
		Path:   "/api/submit",
		Headers: map[string]string{
			"Host":         "example.com",
			"Content-Type": "application/json",
		},
		Body: []byte(`{"name":"goscapy","version":"1.0"}`),
	})
	fmt.Printf("%s\n", postRaw)

	// 3. 构建 HTTP 响应
	fmt.Println("--- 3. 构建 HTTP 响应 ---")
	respRaw := layershttp.BuildHTTPResponse(layershttp.HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Server":       "goscapy/1.0",
		},
		Body: []byte(`{"status":"ok"}`),
	})
	fmt.Printf("%s\n", respRaw)

	// 4. 解析 HTTP 请求
	fmt.Println("--- 4. 解析 HTTP 请求 ---")
	req, _, err := layershttp.ParseHTTP(reqRaw)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	fmt.Printf("  Method: %s\n", req.Method)
	fmt.Printf("  Path:   %s\n", req.Path)
	fmt.Printf("  Version: %s\n", req.Version)
	for k, v := range req.Headers {
		fmt.Printf("  Header: %s = %s\n", k, v)
	}

	// 5. 解析 HTTP 响应
	fmt.Println("--- 5. 解析 HTTP 响应 ---")
	_, resp, err := layershttp.ParseHTTP(respRaw)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	fmt.Printf("  Status: %d %s\n", resp.StatusCode, resp.ReasonPhrase)
	fmt.Printf("  Body:   %s\n", string(resp.Body))
	fmt.Println()

	// 6. 使用 Builder API 构建完整数据包
	fmt.Println("--- 6. 构建 IP+TCP+HTTP 数据包 ---")
	h := goscapy.NewHTTP().Request(
		layershttp.MethodGet,
		"/index.html",
		map[string]string{"Host": "example.com"},
		nil,
	)
	pkt := goscapy.NewIP().
		SrcIP("192.168.1.100").
		DstIP("93.184.216.34").
		Over(goscapy.NewTCP().SrcPort(54321).DstPort(80)).
		Over(h)

	raw, err := pkt.Build()
	if err != nil {
		fmt.Printf("Build 失败: %v\n", err)
		return
	}
	fmt.Printf("  数据包大小: %d bytes\n", len(raw))

	// 7. 手动构建 TCP+HTTP 并解析
	fmt.Println("--- 7. 手动解析 HTTP over TCP ---")
	ip := layers.NewIP()
	ip.Set("src", net.ParseIP("10.0.0.1"))
	ip.Set("dst", net.ParseIP("10.0.0.2"))
	tcp := layers.NewTCP()
	tcp.Set("sport", uint16(12345))
	tcp.Set("dport", uint16(80))
	tcp.Set("flags", uint8(layers.TCPSyn|layers.TCPAck))

	httpPkt := ip.Over(tcp)
	httpLayer := layershttp.NewHTTP()
	httpLayer.Set("raw", respRaw)
	httpPkt.Push(httpLayer)

	raw, err = httpPkt.Build()
	if err != nil {
		fmt.Printf("Build 失败: %v\n", err)
		return
	}
	fmt.Printf("  完整 IP+TCP+HTTP: %d bytes\n", len(raw))
}
