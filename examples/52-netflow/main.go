// 示例 52: Netflow/IPFIX 协议层
//
// 运行: go run main.go
package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/smallnest/goscapy/pkg/layers/netflow"
)

func main() {
	fmt.Println("=== Netflow/IPFIX 协议层示例 ===")
	fmt.Println()

	// 1. Netflow V5
	fmt.Println("--- 1. Netflow V5 ---")
	rec := netflow.NetflowV5Record{
		SrcAddr: net.ParseIP("10.0.0.1").To4(),
		DstAddr: net.ParseIP("10.0.0.2").To4(),
		NextHop: net.ParseIP("0.0.0.0").To4(),
		Input:   1,
		Output:  2,
		Packets: 1500,
		Bytes:   75000,
		First:   100,
		Last:    500,
		SrcPort: 12345,
		DstPort: 80,
		Proto:   6,
		Tos:     0,
		Flags:   0x18,
		SrcAS:   65001,
		DstAS:   65002,
	}
	b := netflow.PackNetflowV5Record(rec)
	fmt.Printf("  Packed record: %d bytes\n", len(b))
	parsed, err := netflow.UnpackNetflowV5Record(b)
	if err != nil {
		fmt.Printf("  Unpack error: %v\n", err)
		return
	}
	fmt.Printf("  SrcAddr=%s DstAddr=%s Packets=%d SrcPort=%d DstPort=%d Proto=%d\n",
		parsed.SrcAddr, parsed.DstAddr, parsed.Packets, parsed.SrcPort, parsed.DstPort, parsed.Proto)

	// 2. Netflow V9
	fmt.Println()
	fmt.Println("--- 2. Netflow V9 ---")
	tmpl := netflow.V9Template{
		TemplateID: 256,
		FieldCount: 3,
		Fields: []netflow.V9TemplateField{
			{Type: 1, Len: 4},  // IN_BYTES
			{Type: 2, Len: 4},  // IN_PKTS
			{Type: 7, Len: 2},  // L4_SRC_PORT
		},
	}
	tmplBytes := netflow.PackV9Template(tmpl)
	fmt.Printf("  Packed template: %d bytes\n", len(tmplBytes))
	parsedTmpl, err := netflow.ParseV9Template(tmplBytes)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  TemplateID=%d FieldCount=%d Fields=%v\n", parsedTmpl.TemplateID, parsedTmpl.FieldCount, parsedTmpl.Fields)

	// Template cache
	cache := netflow.NewTemplateCache()
	cache.Store(0, tmpl)
	cached, ok := cache.Get(0, 256)
	fmt.Printf("  Cache lookup: ok=%v id=%d\n", ok, cached.TemplateID)

	// Decode data flow set
	flowData := []byte{
		0, 0, 0, 100, 0, 0, 0, 5, 0, 80,
		0, 0, 1, 44, 0, 0, 0, 10, 1, 87,
	}
	fs := netflow.V9FlowSet{ID: 256, Data: flowData}
	records, err := netflow.DecodeDataFlowSet(fs, cached)
	if err != nil {
		fmt.Printf("  Decode error: %v\n", err)
		return
	}
	fmt.Printf("  Decoded %d data records\n", len(records))
	for i, r := range records {
		fmt.Printf("    record[%d]: %v\n", i, r)
	}

	// 3. IPFIX
	fmt.Println()
	fmt.Println("--- 3. IPFIX ---")
	ipfixTmpl := netflow.IPFIXTemplate{
		TemplateID: 256,
		FieldCount: 3,
		Fields: []netflow.IPFIXTemplateField{
			{Type: 1, Len: 8},     // octetDeltaCount
			{Type: 2, Len: 4},     // packetDeltaCount
			{Type: 100, Len: 4, Pen: 12345}, // enterprise field
		},
	}
	ipfixTmplBytes := netflow.PackIPFIXTemplate(ipfixTmpl)
	fmt.Printf("  Packed IPFIX template: %d bytes\n", len(ipfixTmplBytes))
	parsedIPFIX, err := netflow.ParseIPFIXTemplate(ipfixTmplBytes)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  TemplateID=%d FieldCount=%d\n", parsedIPFIX.TemplateID, parsedIPFIX.FieldCount)
	for i, f := range parsedIPFIX.Fields {
		fmt.Printf("    field[%d]: type=%d len=%d pen=%d\n", i, f.Type, f.Len, f.Pen)
	}

	// Variable-length field (RFC 5101 section 7)
	fmt.Println()
	fmt.Println("--- 4. IPFIX Variable-Length ---")
	varTmpl := netflow.IPFIXTemplate{
		TemplateID: 256, FieldCount: 2,
		Fields: []netflow.IPFIXTemplateField{
			{Type: 1, Len: 4},
			{Type: 100, Len: 65535}, // variable-length
		},
	}
	varData := []byte{
		0, 0, 0, 42,
		5, 'h', 'e', 'l', 'l', 'o',
	}
	varSet := netflow.IPFIXSet{ID: 256, Data: varData}
	varRecords, err := netflow.DecodeIPFIXData(varSet, varTmpl)
	if err != nil {
		fmt.Printf("  Decode error: %v\n", err)
		return
	}
	fmt.Printf("  Decoded %d records\n", len(varRecords))
	for i, r := range varRecords {
		fmt.Printf("    record[%d]: %v\n", i, r)
	}

	// 5. Version detection
	fmt.Println()
	fmt.Println("--- 5. Version Detection ---")
	versions := []struct {
		data []byte
		desc string
	}{
		{[]byte{0, 5}, "V5 raw"},
		{[]byte{0, 9}, "V9 raw"},
		{[]byte{0, 10}, "IPFIX raw"},
	}
	for _, v := range versions {
		detected := netflow.DetectNetflowVersion(v.data)
		fmt.Printf("  %s → %q\n", v.desc, detected)
	}

	// 6. Flow set packing/parsing
	fmt.Println()
	fmt.Println("--- 6. V9 Flow Set Round-Trip ---")
	fs1 := netflow.V9FlowSet{ID: 0, Data: netflow.PackV9Template(netflow.V9Template{
		TemplateID: 300, FieldCount: 2,
		Fields: []netflow.V9TemplateField{{Type: 1, Len: 4}, {Type: 2, Len: 4}},
	})}
	fs2 := netflow.V9FlowSet{ID: 300, Data: []byte{0, 0, 0, 10, 0, 0, 0, 20}}
	var payload []byte
	payload = append(payload, netflow.PackV9FlowSet(fs1)...)
	payload = append(payload, netflow.PackV9FlowSet(fs2)...)
	sets, err := netflow.ParseV9FlowSets(payload)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		return
	}
	fmt.Printf("  Packed %d flow sets into %d bytes\n", 2, len(payload))
	for i, s := range sets {
		fmt.Printf("    set[%d]: id=%d dataLen=%d\n", i, s.ID, len(s.Data))
	}
	_ = binary.BigEndian
}
