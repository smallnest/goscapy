// 示例 46: 802.11 WiFi 层构建与解析
//
// 运行: go run main.go
package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers/dot11"
)

func main() {
	fmt.Println("=== 802.11 WiFi 层示例 ===")
	fmt.Println()

	// 1. 构建 Beacon 帧
	fmt.Println("--- 1. 构建 Beacon 帧 ---")
	dot11Frame := dot11.NewDot11()
	fc := dot11.SetFC(dot11.TypeManagement, dot11.SubtypeBeacon, 0)
	dot11Frame.Set("fc0", fc[0])
	dot11Frame.Set("fc1", fc[1])
	dot11Frame.Set("addr1", "ff:ff:ff:ff:ff:ff")               // broadcast
	dot11Frame.Set("addr2", "00:11:22:33:44:55")                // AP MAC
	dot11Frame.Set("addr3", "00:11:22:33:44:55")                // BSSID
	dot11Frame.Set("sc", uint16(0x0100))                        // seq=16

	frameData, err := dot11Frame.SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	fmt.Printf("  Dot11 头部: %d bytes\n", len(frameData))
	fmt.Printf("  Type=%d Subtype=%d\n",
		dot11.FCType(frameData[0]),
		dot11.FCSubtype(frameData[0]))

	// 2. 构建 Beacon Body
	fmt.Println("--- 2. 构建 Beacon Body ---")
	beacon := dot11.NewDot11Beacon()
	beacon.Set("timestamp", uint64(12345678))
	beacon.Set("beacon_interval", uint16(100))
	beacon.Set("cap", uint16(0x0411)) // ESS + privacy + short-slot

	beaconData, err := beacon.SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	fmt.Printf("  Beacon body: %d bytes\n", len(beaconData))

	// 3. 构建 Information Elements
	fmt.Println("--- 3. 构建 Information Elements ---")
	elts := []dot11.IE{
		{ID: dot11.EltIDSSID, Info: []byte("MyNetwork")},
		{ID: dot11.EltIDSupportedRates, Info: []byte{0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24}},
		{ID: dot11.EltIDDSSS, Info: []byte{6}},  // channel 6
	}
	ieData := dot11.BuildDot11Elts(elts)
	fmt.Printf("  IEs: %d bytes (SSID=%q)\n", len(ieData), "MyNetwork")

	// 4. 组装完整 Beacon 帧
	fmt.Println("--- 4. 完整 Beacon 帧 ---")
	fullFrame := append(frameData, beaconData...)
	fullFrame = append(fullFrame, ieData...)
	fmt.Printf("  总大小: %d bytes\n", len(fullFrame))

	// 5. 解析 Dot11 头部
	fmt.Println("--- 5. 解析 Dot11 帧 ---")
	parsed := dot11.NewDot11()
	n, err := parsed.ParseFields(fullFrame)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	fc0, _ := parsed.Get("fc0")
	fmt.Printf("  消耗: %d bytes\n", n)
	fmt.Printf("  Type=%d Subtype=%d\n",
		dot11.FCType(fc0.(uint8)),
		dot11.FCSubtype(fc0.(uint8)))

	// 6. 构建 Deauth 帧
	fmt.Println("--- 6. 构建 Deauth 帧 ---")
	deauthFrame := dot11.NewDot11()
	fcDeauth := dot11.SetFC(dot11.TypeManagement, dot11.SubtypeDeauth, 0)
	deauthFrame.Set("fc0", fcDeauth[0])
	deauthFrame.Set("fc1", fcDeauth[1])
	deauthFrame.Set("addr1", "aa:bb:cc:dd:ee:ff")
	deauthFrame.Set("addr2", "00:11:22:33:44:55")
	deauthFrame.Set("addr3", "00:11:22:33:44:55")

	deauthBody := dot11.NewDot11Deauth()
	deauthBody.Set("reason", uint16(dot11.ReasonDeauthLeaving))

	headerData, _ := deauthFrame.SerializeFields()
	bodyData, _ := deauthBody.SerializeFields()
	fmt.Printf("  Deauth: %d + %d = %d bytes\n",
		len(headerData), len(bodyData), len(headerData)+len(bodyData))

	// 7. 构建 RadioTap + Dot11
	fmt.Println("--- 7. 构建 RadioTap + Dot11 ---")
	rt := dot11.NewRadioTap()
	rt.Set("present", uint32(1<<dot11.RTFlagRate|1<<dot11.RTFlagDBmAntSignal))
	rt.Set("data", []byte{0x12, 0xC5}) // rate=18, signal=-59 dBm

	rtData, err := rt.SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	fmt.Printf("  RadioTap: %d bytes\n", len(rtData))

	// Parse RadioTap to extract fields
	parsedRT := dot11.NewRadioTap()
	_, err = parsedRT.ParseFields(rtData)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	p, _ := parsedRT.Get("present")
	d, _ := parsedRT.Get("data")
	fields := dot11.ParseRadioTapData(d.([]byte), p.(uint32))
	if rate, ok := fields["rate"]; ok {
		fmt.Printf("  Rate: %d (0.5 Mbps units)\n", rate)
	}
	if sig, ok := fields["dbm_antsignal"]; ok {
		fmt.Printf("  Signal: %d dBm\n", sig)
	}

	// 8. 解析 IE 列表
	fmt.Println("--- 8. 解析 Information Elements ---")
	parsedIEs, err := dot11.ParseDot11Elts(ieData)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	for i, ie := range parsedIEs {
		fmt.Printf("  IE[%d]: ID=%d Len=%d\n", i, ie.ID, len(ie.Info))
	}
	fmt.Printf("  SSID: %q\n", dot11.SSIDFromIE(parsedIEs))
}
