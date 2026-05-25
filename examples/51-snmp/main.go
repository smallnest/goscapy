// 示例 51: SNMP 协议层
//
// 运行: go run main.go
package main

import (
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/layers/snmp"
)

func main() {
	fmt.Println("=== SNMP 协议层示例 ===")
	fmt.Println()

	// 1. 构建 SNMPv2c GetRequest
	fmt.Println("--- 1. 构建 SNMPv2c GetRequest ---")
	getReq := &snmp.SNMPMessage{
		Version:   snmp.Version2c,
		Community: "public",
		PDUType:   snmp.PDUGetRequest,
		RequestID: 1,
		VarBinds: []snmp.VarBind{
			snmp.NewVarBind(".1.3.6.1.2.1.1.1.0"), // sysDescr
			snmp.NewVarBind(".1.3.6.1.2.1.1.5.0"), // sysName
		},
	}
	raw := snmp.BuildSNMP(getReq)
	fmt.Printf("  GetRequest: %d bytes\n", len(raw))

	// 2. 解析 GetRequest
	parsed, err := snmp.ParseSNMP(raw)
	if err != nil {
		fmt.Printf("解析失败: %v\n", err)
		return
	}
	fmt.Printf("  Version: %d, Community: %q\n", parsed.Version, parsed.Community)
	fmt.Printf("  PDU: %s, RequestID: %d\n", snmp.PDUTypeName(parsed.PDUType), parsed.RequestID)
	for i, vb := range parsed.VarBinds {
		fmt.Printf("  VarBind[%d]: OID=%s\n", i, vb.OID)
	}

	// 3. 构建 GetResponse
	fmt.Println("--- 2. 构建 GetResponse ---")
	resp := &snmp.SNMPMessage{
		Version:     snmp.Version2c,
		Community:   "public",
		PDUType:     snmp.PDUGetResponse,
		RequestID:   1,
		ErrorStatus: 0,
		ErrorIndex:  0,
		VarBinds: []snmp.VarBind{
			snmp.NewVarBindString(".1.3.6.1.2.1.1.1.0", "Linux test 5.4.0"),
			snmp.NewVarBindString(".1.3.6.1.2.1.1.5.0", "my-server"),
		},
	}
	respRaw := snmp.BuildSNMP(resp)
	parsedResp, _ := snmp.ParseSNMP(respRaw)
	fmt.Printf("  %s:\n", snmp.PDUTypeName(parsedResp.PDUType))
	for i, vb := range parsedResp.VarBinds {
		if s, ok := snmp.VarBindValueAsString(vb); ok {
			fmt.Printf("  VarBind[%d]: OID=%s Value=%q\n", i, vb.OID, s)
		}
	}

	// 4. 构建 SNMPv1 Trap
	fmt.Println("--- 3. 构建 SNMPv1 Trap ---")
	trap := &snmp.SNMPMessage{
		Version:      snmp.Version1,
		Community:    "public",
		PDUType:      snmp.PDUTrap,
		Enterprise:   ".1.3.6.1.4.1.311",
		AgentAddr:    net.ParseIP("192.168.1.1"),
		GenericTrap:  6, // enterpriseSpecific
		SpecificTrap: 1,
		Timestamp:    5000,
		VarBinds: []snmp.VarBind{
			snmp.NewVarBindString(".1.3.6.1.4.1.311.1.1", "linkDown"),
		},
	}
	trapRaw := snmp.BuildSNMP(trap)
	parsedTrap, _ := snmp.ParseSNMP(trapRaw)
	fmt.Printf("  PDU: %s\n", snmp.PDUTypeName(parsedTrap.PDUType))
	fmt.Printf("  Enterprise: %s\n", parsedTrap.Enterprise)
	fmt.Printf("  AgentAddr: %s\n", parsedTrap.AgentAddr)
	fmt.Printf("  GenericTrap: %d, SpecificTrap: %d\n", parsedTrap.GenericTrap, parsedTrap.SpecificTrap)

	// 5. 构建 GetBulk
	fmt.Println("--- 4. 构建 GetBulk ---")
	bulk := &snmp.SNMPMessage{
		Version:     snmp.Version2c,
		Community:   "public",
		PDUType:     snmp.PDUGetBulk,
		RequestID:   10,
		ErrorStatus: 0,   // non-repeaters
		ErrorIndex:  10,  // max-repetitions
		VarBinds: []snmp.VarBind{
			snmp.NewVarBind(".1.3.6.1.2.1.2.2.1.2"), // ifDescr
		},
	}
	bulkRaw := snmp.BuildSNMP(bulk)
	fmt.Printf("  GetBulk: %d bytes\n", len(bulkRaw))

	// 6. BER 编码演示
	fmt.Println("--- 5. BER 编码演示 ---")
	oid := ".1.3.6.1.2.1.1.1.0"
	encoded := snmp.BEREncodeOID(oid)
	fmt.Printf("  OID %s → %d bytes BER\n", oid, len(encoded))

	intVal := snmp.BEREncodeInteger(42)
	fmt.Printf("  Integer 42 → %d bytes BER\n", len(intVal))

	ip := snmp.BEREncodeIP(net.ParseIP("10.0.0.1"))
	fmt.Printf("  IP 10.0.0.1 → %d bytes BER\n", len(ip))
}
