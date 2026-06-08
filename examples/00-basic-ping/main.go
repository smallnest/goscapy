package main

import (
	"fmt"
	"time"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

func main() {
	// 构建 + 发送 + 接收第一个回复
	pkt := goscapy.NewIP().
		DstIP("8.8.8.8").
		Over(goscapy.NewICMP().
			Type(8).Code(0)).
		Packet()

	_, resp, err := sendrecv.SendRecv1(
		pkt, "en0", 3*time.Second)
	fmt.Println(resp.Summary())
}
