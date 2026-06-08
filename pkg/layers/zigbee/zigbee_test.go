package zigbee

import (
	"testing"
)

func TestNewZigbeeNWK(t *testing.T) {
	layer := NewZigbeeNWK()
	fc, _ := layer.Get("frame_control")
	if fc.(uint16) == 0 {
		t.Error("default frame_control should be non-zero")
	}
	radius, _ := layer.Get("radius")
	if radius.(uint8) != 0 {
		t.Errorf("default radius = %d, want 0", radius)
	}
}

func TestZigbeeNWKRountTrip(t *testing.T) {
	layer := NewZigbeeNWK()
	_ = layer.Set("frame_control", uint16(0x0020)) // version=2, frame type=data
	_ = layer.Set("seqnum", uint8(0x7F))
	_ = layer.Set("dst", uint16(0x1234))
	_ = layer.Set("src", uint16(0x5678))
	_ = layer.Set("radius", uint8(5))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// frame_control(2) + seqnum(1) + dst(2) + src(2) + radius(1) = 8
	if len(data) != 8 {
		t.Errorf("size = %d, want 8", len(data))
	}

	layer2 := NewZigbeeNWK()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 8 {
		t.Errorf("consumed = %d, want 8", n)
	}

	seq, _ := layer2.Get("seqnum")
	if seq.(uint8) != 0x7F {
		t.Errorf("seqnum = %#x, want 0x7F", seq)
	}
	dst, _ := layer2.Get("dst")
	if dst.(uint16) != 0x1234 {
		t.Errorf("dst = %#x, want 0x1234", dst)
	}
	src, _ := layer2.Get("src")
	if src.(uint16) != 0x5678 {
		t.Errorf("src = %#x, want 0x5678", src)
	}
	radius, _ := layer2.Get("radius")
	if radius.(uint8) != 5 {
		t.Errorf("radius = %d, want 5", radius)
	}
}

func TestZigbeeNWKWithExtAddr(t *testing.T) {
	layer := NewZigbeeNWK()
	// Set frame_control with both ext_dst and ext_src flags
	fc := uint16(0x0020) | uint16(NWKFlagDstIEEEAddr) | uint16(NWKFlagSrcIEEEAddr)
	_ = layer.Set("frame_control", fc)
	_ = layer.Set("seqnum", uint8(1))
	_ = layer.Set("dst", uint16(0x0001))
	_ = layer.Set("src", uint16(0x0002))
	_ = layer.Set("radius", uint8(3))
	_ = layer.Set("ext_dst", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	_ = layer.Set("ext_src", []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18})

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// fc(2) + seq(1) + dst(2) + src(2) + radius(1) + ext_dst(8) + ext_src(8) = 24
	if len(data) != 24 {
		t.Errorf("size = %d, want 24", len(data))
	}

	layer2 := NewZigbeeNWK()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 24 {
		t.Errorf("consumed = %d, want 24", n)
	}

	extDst, _ := layer2.Get("ext_dst")
	extDstBytes, ok := extDst.([]byte)
	if !ok || len(extDstBytes) != 8 {
		t.Errorf("ext_dst type/len unexpected: %T len=%d", extDst, len(extDstBytes))
	} else if extDstBytes[0] != 0x01 || extDstBytes[7] != 0x08 {
		t.Errorf("ext_dst = %x, want 0102030405060708", extDstBytes)
	}
}

func TestNewZigbeeAPS(t *testing.T) {
	layer := NewZigbeeAPS()
	fc, _ := layer.Get("frame_control")
	// defaultAPSFrameControl = frame type(0) | delivery_mode(0)<<2 = 0
	if fc.(uint8) != 0 {
		t.Errorf("default frame_control = %#x, want 0x00", fc)
	}
}

func TestZigbeeAPSRoundTrip(t *testing.T) {
	layer := NewZigbeeAPS()
	_ = layer.Set("frame_control", uint8(0x00)) // data frame, normal delivery
	_ = layer.Set("counter", uint8(0))
	_ = layer.Set("dst_endpoint", uint8(1))
	_ = layer.Set("cluster", uint16(ClusterOnOff))
	_ = layer.Set("profile", uint16(ProfileHA))
	_ = layer.Set("src_endpoint", uint8(1))
	_ = layer.Set("aps_counter", uint8(5))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// fc(1) + counter(1) + dst_ep(1) + cluster(2) + profile(2) + src_ep(1) + aps_counter(1) = 9
	if len(data) != 9 {
		t.Errorf("size = %d, want 9", len(data))
	}

	layer2 := NewZigbeeAPS()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 9 {
		t.Errorf("consumed = %d, want 9", n)
	}

	cluster, _ := layer2.Get("cluster")
	if cluster.(uint16) != ClusterOnOff {
		t.Errorf("cluster = %#x, want %#x", cluster, ClusterOnOff)
	}
	profile, _ := layer2.Get("profile")
	if profile.(uint16) != ProfileHA {
		t.Errorf("profile = %#x, want %#x", profile, ProfileHA)
	}
}

func TestZigbeeAPSGroupDelivery(t *testing.T) {
	layer := NewZigbeeAPS()
	// Group delivery mode: delivery_mode=1 shifted left by 2 bits
	fc := uint8(APSFrameData) | uint8(APSDeliveryGroup)<<2
	_ = layer.Set("frame_control", fc)
	_ = layer.Set("counter", uint8(0))
	_ = layer.Set("group_addr", uint16(0x0001))
	_ = layer.Set("cluster", uint16(ClusterOnOff))
	_ = layer.Set("profile", uint16(ProfileHA))
	_ = layer.Set("src_endpoint", uint8(1))
	_ = layer.Set("aps_counter", uint8(0))

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// fc(1) + counter(1) + group_addr(2) + cluster(2) + profile(2) + src_ep(1) + aps_counter(1) = 10
	if len(data) != 10 {
		t.Errorf("size = %d, want 10", len(data))
	}
}

func TestNewZigbeeCluster(t *testing.T) {
	layer := NewZigbeeCluster()
	fc, _ := layer.Get("frame_control")
	if fc.(uint8) == 0 {
		t.Error("default frame_control should be non-zero")
	}
}

func TestZigbeeClusterRoundTrip(t *testing.T) {
	layer := NewZigbeeCluster()
	_ = layer.Set("frame_control", uint8(0x00)) // client-to-server, global
	_ = layer.Set("seqnum", uint8(1))
	_ = layer.Set("command", uint8(ZCLCmdReadAttributes))
	_ = layer.Set("payload", []byte{0x00, 0x00}) // attribute ID 0x0000

	data, err := layer.SerializeFields()
	if err != nil {
		t.Fatalf("SerializeFields: %v", err)
	}
	// fc(1) + seqnum(1) + command(1) + payload(2) = 5
	if len(data) != 5 {
		t.Errorf("size = %d, want 5", len(data))
	}

	layer2 := NewZigbeeCluster()
	n, err := layer2.ParseFields(data)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if n != 5 {
		t.Errorf("consumed = %d, want 5", n)
	}

	cmd, _ := layer2.Get("command")
	if cmd.(uint8) != ZCLCmdReadAttributes {
		t.Errorf("command = %#x, want %#x", cmd, ZCLCmdReadAttributes)
	}
}

func TestNWKFrameType(t *testing.T) {
	if NWKFrameType(0x0020) != NWKFrameData {
		t.Errorf("NWKFrameType(0x0020) = %d, want %d", NWKFrameType(0x0020), NWKFrameData)
	}
	if NWKFrameType(0x0021) != NWKFrameCommand {
		t.Errorf("NWKFrameType(0x0021) = %d, want %d", NWKFrameType(0x0021), NWKFrameCommand)
	}
}

func TestNWKSecurity(t *testing.T) {
	if NWKSecurity(0x0020) {
		t.Error("0x0020 should not have security flag")
	}
	if !NWKSecurity(uint16(NWKFlagSecurity)) {
		t.Error("NWKFlagSecurity should have security flag")
	}
}

func TestAPSFrameType(t *testing.T) {
	if APSFrameType(0x00) != APSFrameData {
		t.Errorf("APSFrameType(0x00) = %d, want %d", APSFrameType(0x00), APSFrameData)
	}
}

func TestAPSDeliveryModeFC(t *testing.T) {
	fc := uint8(APSFrameData) | uint8(APSDeliveryGroup)<<2
	if APSDeliveryModeFC(fc) != APSDeliveryGroup {
		t.Errorf("APSDeliveryModeFC = %d, want %d", APSDeliveryModeFC(fc), APSDeliveryGroup)
	}
}

func TestZCLFrameType(t *testing.T) {
	if ZCLFrameType(0x00) != ZCLFrameGlobal {
		t.Errorf("ZCLFrameType(0x00) = %d, want %d", ZCLFrameType(0x00), ZCLFrameGlobal)
	}
}

func TestZCLDirection(t *testing.T) {
	if ZCLDirection(0x01) != ZCLFrameClientToServer {
		t.Errorf("ZCLDirection(0x01) = %d, want %d", ZCLDirection(0x01), ZCLFrameClientToServer)
	}
}

func TestNWKFrameTypeString(t *testing.T) {
	if NWKFrameTypeString(NWKFrameData) != "Data" {
		t.Errorf("unexpected NWKFrameTypeString")
	}
	if NWKFrameTypeString(99) != "Unknown(99)" {
		t.Errorf("unexpected unknown string")
	}
}

func TestAPSFrameTypeString(t *testing.T) {
	if APSFrameTypeString(APSFrameData) != "Data" {
		t.Errorf("unexpected APSFrameTypeString")
	}
}

func TestAPSDeliveryModeString(t *testing.T) {
	if APSDeliveryModeString(APSDeliveryNormal) != "Normal" {
		t.Errorf("unexpected APSDeliveryModeString")
	}
}

func TestZCLFrameTypeString(t *testing.T) {
	if ZCLFrameTypeString(ZCLFrameGlobal) != "Global" {
		t.Errorf("unexpected ZCLFrameTypeString")
	}
}

func TestClusterName(t *testing.T) {
	if ClusterName(ClusterOnOff) != "OnOff" {
		t.Errorf("ClusterName(OnOff) = %q", ClusterName(ClusterOnOff))
	}
	if ClusterName(ClusterTemperature) != "Temperature" {
		t.Errorf("ClusterName(Temperature) = %q", ClusterName(ClusterTemperature))
	}
	if ClusterName(0xFFFF) != "Unknown(0xffff)" {
		t.Errorf("ClusterName(0xFFFF) = %q", ClusterName(0xFFFF))
	}
}

func TestBuildZCLReadAttr(t *testing.T) {
	ids := []uint16{0x0000, 0x0001}
	payload := BuildZCLReadAttr(ids)
	if len(payload) != 4 {
		t.Errorf("payload len = %d, want 4", len(payload))
	}
	// First attribute ID 0x0000 in LE.
	if payload[0] != 0x00 || payload[1] != 0x00 {
		t.Errorf("attr ID 0 = %x", payload[:2])
	}
	// Second attribute ID 0x0001 in LE.
	if payload[2] != 0x01 || payload[3] != 0x00 {
		t.Errorf("attr ID 1 = %x", payload[2:4])
	}
}

func TestParseZCLReadAttrResp(t *testing.T) {
	// Attribute 0x0005: status=0 (success), type=0x20 (uint8), value=0x01
	payload := []byte{
		0x05, 0x00, // attribute ID = 0x0005
		0x00,       // status = success
		0x20,       // data type = uint8
		0x01,       // value = 1
		0x06, 0x00, // attribute ID = 0x0006
		0x86,       // status = unsupported attribute
	}
	attrs, err := ParseZCLReadAttrResp(payload)
	if err != nil {
		t.Fatalf("ParseZCLReadAttrResp: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("attrs = %d, want 2", len(attrs))
	}
	if attrs[0].AttributeID != 0x0005 {
		t.Errorf("attr[0] ID = %#x", attrs[0].AttributeID)
	}
	if attrs[0].DataType != 0x20 {
		t.Errorf("attr[0] type = %#x", attrs[0].DataType)
	}
	if len(attrs[0].Value) != 1 || attrs[0].Value[0] != 0x01 {
		t.Errorf("attr[0] value = %x", attrs[0].Value)
	}
	// Second attribute has error status, no data type/value.
	if attrs[1].AttributeID != 0x0006 {
		t.Errorf("attr[1] ID = %#x", attrs[1].AttributeID)
	}
	if attrs[1].DataType != 0 {
		t.Errorf("attr[1] type should be 0 for error status")
	}
}
