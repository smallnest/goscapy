// 示例 48: Bluetooth / BLE 层构建与解析
//
// 运行: go run main.go
package main

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers/bt"
)

func main() {
	fmt.Println("=== Bluetooth / BLE 层示例 ===")
	fmt.Println()

	// 1. 构建 HCI Command
	fmt.Println("--- 1. 构建 HCI Command ---")
	hci := goscapy.NewHCI().
		Type(bt.HCICommand).
		Opcode(0x0406). // HCI_Reset
		Params(nil)

	hciData, err := hci.Layer().SerializeFields()
	if err != nil {
		fmt.Printf("序列化失败: %v\n", err)
		return
	}
	fmt.Printf("  HCI Command: %d bytes, type=%s\n", len(hciData), bt.HCITypeString(hciData[0]))

	// 2. 构建 L2CAP + ATT Read Request
	fmt.Println("--- 2. 构建 L2CAP + ATT ---")
	attParams := []byte{0x01, 0x00} // handle = 0x0001
	attLayer := goscapy.NewATT().
		Opcode(bt.ATTOpcodeReadReq).
		Params(attParams)

	attData, _ := attLayer.Layer().SerializeFields()
	fmt.Printf("  ATT ReadReq: %d bytes, opcode=%s\n", len(attData), bt.ATTOpcodeString(attData[0]))

	l2cap := goscapy.NewL2CAP().
		CID(bt.L2CAPCIDATT).
		Data(attData)

	l2capData, _ := l2cap.Layer().SerializeFields()
	fmt.Printf("  L2CAP: %d bytes, CID=0x%04x\n", len(l2capData), bt.L2CAPCIDATT)

	// 3. 构建完整 HCI ACL + L2CAP + ATT 链
	fmt.Println("--- 3. 构建 HCI ACL + L2CAP + ATT ---")
	aclPkt := goscapy.NewHCI().
		Type(bt.HCIACLData).
		Opcode(0x0041). // handle=1, PB flag=2
		Params(l2capData)

	aclData, _ := aclPkt.Layer().SerializeFields()
	fmt.Printf("  ACL packet: %d bytes\n", len(aclData))

	// 4. 解析 EIR (Extended Inquiry Response)
	fmt.Println("--- 4. 解析 BLE 广播 EIR ---")
	eirEntries := []bt.EIR{
		{Type: bt.EIRTypeFlags, Data: []byte{0x06}},           // LE General Discoverable, BR/EDR Not Supported
		{Type: bt.EIRTypeCompleteName, Data: []byte("MyBLE")},
		{Type: bt.EIRTypeTxPowerLevel, Data: []byte{0x04}},    // +4 dBm
		{Type: bt.EIRTypeAppearance, Data: []byte{0x80, 0x07}},// Generic Heart Rate Sensor
	}
	eirRaw := bt.BuildEIR(eirEntries)

	parsed, err := bt.ParseEIR(eirRaw)
	if err != nil {
		fmt.Printf("ParseEIR: %v\n", err)
		return
	}
	fmt.Printf("  EIR entries: %d\n", len(parsed))
	fmt.Printf("  Device Name: %q\n", bt.DeviceName(parsed))
	fmt.Printf("  Flags: %#x\n", bt.FindEIR(parsed, bt.EIRTypeFlags).Data)

	// 5. 解析 ATT Notification
	fmt.Println("--- 5. 解析 ATT Notification ---")
	notifyParams := []byte{0x0F, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F}
	notify, err := bt.ParseATTNotify(notifyParams)
	if err != nil {
		fmt.Printf("ParseATTNotify: %v\n", err)
		return
	}
	fmt.Printf("  Handle: 0x%04x\n", notify.Handle)
	fmt.Printf("  Value: %q\n", string(notify.Value))

	// 6. 解析 SM Pairing Request
	fmt.Println("--- 6. 解析 SM Pairing Request ---")
	smData := []byte{0x03, 0x00, 0x01, 0x10, 0x07, 0x07}
	pairReq, err := bt.ParseSMPairingReq(smData)
	if err != nil {
		fmt.Printf("ParseSMPairingReq: %v\n", err)
		return
	}
	fmt.Printf("  IOCap: %d  AuthReq: %#x  MaxEncSize: %d\n",
		pairReq.IOCapability, pairReq.AuthReq, pairReq.MaxEncSize)

	// 7. 解析 ATT Error Response
	fmt.Println("--- 7. 解析 ATT Error Response ---")
	errParams := []byte{bt.ATTOpcodeReadReq, 0x0A, 0x00, bt.ATTErrorReadNotPermitted}
	attErr, err := bt.ParseATTError(errParams)
	if err != nil {
		fmt.Printf("ParseATTError: %v\n", err)
		return
	}
	fmt.Printf("  Request: %s  Handle: 0x%04x  Error: 0x%02x\n",
		bt.ATTOpcodeString(attErr.RequestOpcode), attErr.Handle, attErr.ErrorCode)
}
