// 示例 56: Zigbee / IoT 无线协议层构建与解析
//
// 运行: go run main.go
package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers/lorawan"
	"github.com/smallnest/goscapy/pkg/layers/zigbee"
)

func main() {
	fmt.Println("=== Zigbee / IoT 无线协议层示例 ===")
	fmt.Println()

	// ---- Zigbee ----

	// 1. 构建 ZigbeeNWK + ZigbeeAPS + ZigbeeCluster 链
	fmt.Println("--- 1. 构建 Zigbee 数据帧 ---")
	zclPayload := zigbee.BuildZCLReadAttr([]uint16{0x0000, 0x0001})

	cluster := goscapy.NewZigbeeCluster().
		FrameControl(0x00).
		Command(zigbee.ZCLCmdReadAttributes).
		Payload(zclPayload)

	clusterData, err := cluster.Layer().SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	fmt.Printf("  ZCL ReadAttributes: %d bytes\n", len(clusterData))

	aps := goscapy.NewZigbeeAPS().
		FrameControl(0x00).
		DstEndpoint(1).
		Cluster(zigbee.ClusterOnOff).
		Profile(zigbee.ProfileHA).
		SrcEndpoint(1)

	apsData, _ := aps.Layer().SerializeFields()
	fmt.Printf("  APS: %d bytes, cluster=%s\n", len(apsData), zigbee.ClusterName(zigbee.ClusterOnOff))

	nwk := goscapy.NewZigbeeNWK().
		FrameControl(0x0020). // version=2, data frame
		SeqNum(1).
		Dst(0x0001).
		Src(0x0002).
		Radius(5)

	nwkData, _ := nwk.Layer().SerializeFields()
	fmt.Printf("  NWK: %d bytes\n", len(nwkData))

	// 2. 解析 Zigbee 帧
	fmt.Println("--- 2. 解析 Zigbee NWK 帧 ---")
	parsedNWK := zigbee.NewZigbeeNWK()
	n, err := parsedNWK.ParseFields(nwkData)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	fmt.Printf("  消耗 %d 字节\n", n)

	fc, _ := parsedNWK.Get("frame_control")
	fmt.Printf("  帧类型: %s\n", zigbee.NWKFrameTypeString(zigbee.NWKFrameType(fc.(uint16))))
	fmt.Printf("  协议版本: %d\n", zigbee.NWKProtocolVersionFC(fc.(uint16)))
	fmt.Printf("  安全标志: %v\n", zigbee.NWKSecurity(fc.(uint16)))

	dst, _ := parsedNWK.Get("dst")
	src, _ := parsedNWK.Get("src")
	fmt.Printf("  目的地址: 0x%04x  源地址: 0x%04x\n", dst.(uint16), src.(uint16))

	// 3. ZCL 属性解析
	fmt.Println("--- 3. ZCL 属性读取响应解析 ---")
	respPayload := []byte{
		0x00, 0x00, // attribute ID = 0x0000
		0x00,       // status = success
		0x20,       // data type = uint8
		0x01,       // value = 1 (OnOff = ON)
		0x01, 0x00, // attribute ID = 0x0001
		0x00,       // status = success
		0x30,       // data type = enum8
		0x02,       // value = 2
	}
	attrs, err := zigbee.ParseZCLReadAttrResp(respPayload)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	for _, a := range attrs {
		fmt.Printf("  属性 0x%04x: 类型=0x%02x 值=%v\n", a.AttributeID, a.DataType, a.Value)
	}

	// ---- LoRaWAN ----

	fmt.Println()
	fmt.Println("--- 4. 构建 LoRaWAN 数据帧 ---")
	lwData := lorawan.BuildLoRaWANData(&lorawan.LoRaWANData{
		FOpts:    []byte{},
		FPort:    1,
		Payload:  []byte{0xCA, 0xFE},
		MIC:      []byte{0x01, 0x02, 0x03, 0x04},
	})

	lorawanFrame := goscapy.NewLoRaWAN().
		MHDR(uint8(lorawan.MTypeUnconfirmedUp)<<5 | lorawan.Major).
		DevAddr(0x01020304).
		FCtrl(0).
		FCnt(1).
		Data(lwData)

	frameData, err := lorawanFrame.Layer().SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	fmt.Printf("  LoRaWAN 帧: %d 字节\n", len(frameData))

	// 5. 解析 LoRaWAN 帧
	fmt.Println("--- 5. 解析 LoRaWAN 帧 ---")
	parsedLW := lorawan.NewLoRaWAN()
	_, err = parsedLW.ParseFields(frameData)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}

	mhdr, _ := parsedLW.Get("mhdr")
	fmt.Printf("  MType: %s\n", lorawan.MTypeString(lorawan.MTypeFromMHDR(mhdr.(uint8))))
	fmt.Printf("  Major: %d\n", lorawan.MajorFromMHDR(mhdr.(uint8)))

	devAddr, _ := parsedLW.Get("dev_addr")
	fmt.Printf("  DevAddr: 0x%08x\n", devAddr.(uint32))

	fctrl, _ := parsedLW.Get("fctrl")
	foptsLen := int(lorawan.FCtrlFOptsLen(fctrl.(uint8)))
	fmt.Printf("  FCtrl: 0x%02x (FOptsLen=%d, ADR=%v, ACK=%v)\n",
		fctrl.(uint8), foptsLen,
		lorawan.IsFCtrlADR(fctrl.(uint8)),
		lorawan.IsFCtrlAck(fctrl.(uint8)))

	dataField, _ := parsedLW.Get("data")
	lwParsed, err := lorawan.ParseLoRaWANData(dataField.([]byte), foptsLen)
	if err != nil {
		fmt.Printf("ParseLoRaWANData: %v\n", err)
		return
	}
	fmt.Printf("  FPort: %d  Payload: %x  MIC: %x\n", lwParsed.FPort, lwParsed.Payload, lwParsed.MIC)

	// 6. LoRaWAN Join Request
	fmt.Println("--- 6. 构建 LoRaWAN Join Request ---")
	joinReq := lorawan.NewLoRaWANJoinReq()
	_ = joinReq.Set("app_eui", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	_ = joinReq.Set("dev_eui", []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18})
	_ = joinReq.Set("dev_nonce", uint16(0xABCD))
	_ = joinReq.Set("mic", []byte{0xAA, 0xBB, 0xCC, 0xDD})

	joinData, _ := joinReq.SerializeFields()
	fmt.Printf("  Join Request: %d 字节 (预期 %d)\n", len(joinData), lorawan.JoinRequestSize)

	// 7. MAC 命令解析
	fmt.Println("--- 7. MAC 命令解析 ---")
	macCmds := []lorawan.MACCommand{
		{CID: lorawan.MACCmdLinkCheckAns, Value: []byte{0x05, 0x0A}},
		{CID: lorawan.MACCmdDevStatusReq},
	}
	foptsWire := lorawan.BuildMACCommands(macCmds)
	parsedCmds, err := lorawan.ParseMACCommands(foptsWire)
	if err != nil {
		fmt.Printf("ParseMACCommands: %v\n", err)
		return
	}
	for i, c := range parsedCmds {
		fmt.Printf("  MAC[%d]: CID=0x%02x Value=%v\n", i, c.CID, c.Value)
	}
}
