// Package zigbee provides Zigbee IoT wireless protocol layer implementations
// per the Zigbee Specification (IEEE 802.15.4 / Zigbee Alliance).
package zigbee

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- ZigbeeNWK frame type constants ----

const (
	NWKFrameData       uint8 = 0
	NWKFrameCommand    uint8 = 1
	NWKFrameReserved   uint8 = 2
)

// ---- ZigbeeNWK flags (within frame control) ----

const (
	NWKFlagMulticast  uint16 = 1 << 0
	NWKFlagSecurity   uint16 = 1 << 1
	NWKFlagSourceRoute uint16 = 1 << 2
	NWKFlagDstIEEEAddr uint16 = 1 << 3
	NWKFlagSrcIEEEAddr uint16 = 1 << 4
	NWKFlagEndDeviceInitiator uint16 = 1 << 5
)

// Zigbee protocol version.
const NWKProtocolVersion uint8 = 2

// ---- NWK command identifiers ----

const (
	NWMCmdRouteRequest      uint8 = 1
	NWMCmdRouteReply        uint8 = 2
	NWMCmdNetworkStatus     uint8 = 3
	NWMCmdLeave             uint8 = 4
	NWMCmdRouteRecord       uint8 = 7
	NWMCmdRejoinRequest     uint8 = 8
	NWMCmdRejoinResponse    uint8 = 9
	NWMCmdLinkStatus        uint8 = 0x0A
	NWMCmdNetworkReport     uint8 = 0x0B
	NWMCmdNetworkUpdate     uint8 = 0x0C
)

// ---- ZigbeeAPS frame type constants ----

const (
	APSFrameData       uint8 = 0
	APSFrameCommand    uint8 = 1
	APSFrameAck        uint8 = 2
)

// ---- ZigbeeAPS delivery mode (within frame control) ----

const (
	APSDeliveryNormal      uint8 = 0
	APSDeliveryGroup       uint8 = 1
	APSDeliveryIndirect    uint8 = 2
	APSDeliveryBroadcast   uint8 = 3
)

// ---- Zigbee profile IDs ----

const (
	ProfileZDP       uint16 = 0x0000
	ProfileHA        uint16 = 0x0104
	ProfileTA        uint16 = 0x0107
	ProfileCBEE      uint16 = 0x0109
	ProfileHC        uint16 = 0x010A
	ProfileSE        uint16 = 0x0101
)

// ---- ZCL frame control constants ----

const (
	ZCLFrameServerToClient    uint8 = 0
	ZCLFrameClientToServer    uint8 = 1

	ZCLFrameGlobal     uint8 = 0
	ZCLFrameCluster    uint8 = 1
	ZCLFrameProfile    uint8 = 2
	ZCLFrameReserved   uint8 = 3
)

// ---- ZCL global command identifiers ----

const (
	ZCLCmdReadAttributes         uint8 = 0x00
	ZCLCmdReadAttributesResp     uint8 = 0x01
	ZCLCmdWriteAttributes        uint8 = 0x02
	ZCLCmdWriteAttributesResp    uint8 = 0x04
	ZCLCmdConfigureReporting     uint8 = 0x06
	ZCLCmdConfigureReportingResp uint8 = 0x07
	ZCLCmdDefaultResp            uint8 = 0x0B
	ZCLCmdDiscoverAttributes     uint8 = 0x0C
	ZCLCmdDiscoverAttributesResp uint8 = 0x0D
)

// ---- Common ZCL cluster IDs ----

const (
	ClusterBasic            uint16 = 0x0000
	ClusterPowerConfig      uint16 = 0x0001
	ClusterIdentify         uint16 = 0x0003
	ClusterGroups           uint16 = 0x0004
	ClusterScenes           uint16 = 0x0005
	ClusterOnOff            uint16 = 0x0006
	ClusterLevelControl     uint16 = 0x0008
	ClusterColorControl     uint16 = 0x0300
	ClusterTemperature      uint16 = 0x0402
	ClusterHumidity         uint16 = 0x0405
	ClusterOccupancySensing uint16 = 0x0406
	ClusterIASZone          uint16 = 0x0500
)

// ---- ZigbeeNWK layer ----

// NewZigbeeNWK creates a Zigbee Network Layer.
// Fields: frame_control(2 LE), seqnum(1), dst(2 LE), src(2 LE), radius(1),
// plus conditional ext_dst(8) and ext_src(8).
func NewZigbeeNWK() *packet.Layer {
	return packet.NewLayer("ZigbeeNWK", []fields.Field{
		fields.NewLEShortField("frame_control", defaultNWKFrameControl()),
		fields.NewByteField("seqnum", 0),
		fields.NewLEShortField("dst", 0xFFFF),  // broadcast by default
		fields.NewLEShortField("src", 0),
		fields.NewByteField("radius", 0),
		fields.NewConditionalField(
			fields.NewStrFixedField("ext_dst", 8, make([]byte, 8)),
			func(values map[string]any) bool {
				fc, ok := values["frame_control"]
				if !ok {
					return false
				}
				return fc.(uint16)&uint16(NWKFlagDstIEEEAddr) != 0
			},
		),
		fields.NewConditionalField(
			fields.NewStrFixedField("ext_src", 8, make([]byte, 8)),
			func(values map[string]any) bool {
				fc, ok := values["frame_control"]
				if !ok {
					return false
				}
				return fc.(uint16)&uint16(NWKFlagSrcIEEEAddr) != 0
			},
		),
	})
}

func defaultNWKFrameControl() uint16 {
	return uint16(NWKProtocolVersion)<<4 | uint16(NWKFrameData)
}

// NWKFrameType extracts the frame type from NWK frame control.
func NWKFrameType(fc uint16) uint8 { return uint8(fc & 0x03) }

// NWKProtocolVersion extracts the protocol version from NWK frame control.
func NWKProtocolVersionFC(fc uint16) uint8 { return uint8((fc >> 4) & 0x0F) }

// NWKDiscoverRoute extracts the discover route flag from NWK frame control.
func NWKDiscoverRoute(fc uint16) uint8 { return uint8((fc >> 6) & 0x03) }

// NWKSecurity returns whether the security flag is set.
func NWKSecurity(fc uint16) bool { return fc&uint16(NWKFlagSecurity) != 0 }

// ---- ZigbeeAPS layer ----

// NewZigbeeAPS creates a Zigbee Application Support Sub-layer.
// Fields: frame_control(1), counter(1), dst_endpoint(1) or group_addr(2) conditional,
// cluster(2 LE), profile(2 LE), src_endpoint(1).
func NewZigbeeAPS() *packet.Layer {
	return packet.NewLayer("ZigbeeAPS", []fields.Field{
		fields.NewByteField("frame_control", defaultAPSFrameControl()),
		fields.NewByteField("counter", 0),
		fields.NewConditionalField(
			fields.NewByteField("dst_endpoint", 0),
			func(values map[string]any) bool {
				fc, ok := values["frame_control"]
				if !ok {
					return true
				}
				return apsDeliveryMode(fc.(uint8)) != APSDeliveryGroup
			},
		),
		fields.NewConditionalField(
			fields.NewLEShortField("group_addr", 0),
			func(values map[string]any) bool {
				fc, ok := values["frame_control"]
				if !ok {
					return false
				}
				return apsDeliveryMode(fc.(uint8)) == APSDeliveryGroup
			},
		),
		fields.NewLEShortField("cluster", 0),
		fields.NewLEShortField("profile", ProfileHA),
		fields.NewByteField("src_endpoint", 0),
		fields.NewByteField("aps_counter", 0),
	})
}

func defaultAPSFrameControl() uint8 {
	return uint8(APSFrameData) | uint8(APSDeliveryNormal)<<2
}

func apsDeliveryMode(fc uint8) uint8 {
	return (fc >> 2) & 0x03
}

// APSFrameType extracts the APS frame type from frame control.
func APSFrameType(fc uint8) uint8 { return fc & 0x03 }

// APSDeliveryMode extracts the delivery mode from frame control.
func APSDeliveryModeFC(fc uint8) uint8 { return (fc >> 2) & 0x03 }

// APSSecurity returns whether the security flag is set in APS frame control.
func APSSecurity(fc uint8) bool { return fc&0x20 != 0 }

// APSAckRequest returns whether the ack request flag is set.
func APSAckRequest(fc uint8) bool { return fc&0x40 != 0 }

// ---- ZigbeeCluster (ZCL) layer ----

// NewZigbeeCluster creates a Zigbee Cluster Library frame layer.
// Fields: frame_control(1), seqnum(1), command(1), payload(variable).
func NewZigbeeCluster() *packet.Layer {
	return packet.NewLayer("ZigbeeCluster", []fields.Field{
		fields.NewByteField("frame_control", defaultZCLFrameControl()),
		fields.NewByteField("seqnum", 0),
		fields.NewByteField("command", ZCLCmdReadAttributes),
		fields.NewStrField("payload", ""),
	})
}

func defaultZCLFrameControl() uint8 {
	return ZCLFrameClientToServer | ZCLFrameGlobal<<2
}

// ZCLFrameType extracts the ZCL frame type from frame control.
func ZCLFrameType(fc uint8) uint8 { return (fc >> 2) & 0x03 }

// ZCLDirection extracts the direction bit from frame control.
func ZCLDirection(fc uint8) uint8 { return fc & 0x01 }

// ZCLDisableDefaultResp returns whether the disable default response bit is set.
func ZCLDisableDefaultResp(fc uint8) bool { return fc&0x04 != 0 }

// ---- String helpers ----

// NWKFrameTypeString returns a human-readable NWK frame type.
func NWKFrameTypeString(ft uint8) string {
	switch ft {
	case NWKFrameData:
		return "Data"
	case NWKFrameCommand:
		return "Command"
	case NWKFrameReserved:
		return "Reserved"
	default:
		return fmt.Sprintf("Unknown(%d)", ft)
	}
}

// APSFrameTypeString returns a human-readable APS frame type.
func APSFrameTypeString(ft uint8) string {
	switch ft {
	case APSFrameData:
		return "Data"
	case APSFrameCommand:
		return "Command"
	case APSFrameAck:
		return "Ack"
	default:
		return fmt.Sprintf("Unknown(%d)", ft)
	}
}

// APSDeliveryModeString returns a human-readable APS delivery mode.
func APSDeliveryModeString(dm uint8) string {
	switch dm {
	case APSDeliveryNormal:
		return "Normal"
	case APSDeliveryGroup:
		return "Group"
	case APSDeliveryIndirect:
		return "Indirect"
	case APSDeliveryBroadcast:
		return "Broadcast"
	default:
		return fmt.Sprintf("Unknown(%d)", dm)
	}
}

// ZCLFrameTypeString returns a human-readable ZCL frame type.
func ZCLFrameTypeString(ft uint8) string {
	switch ft {
	case ZCLFrameGlobal:
		return "Global"
	case ZCLFrameCluster:
		return "Cluster"
	case ZCLFrameProfile:
		return "Profile"
	default:
		return fmt.Sprintf("Unknown(%d)", ft)
	}
}

// ClusterName returns a common name for a known cluster ID.
func ClusterName(cid uint16) string {
	switch cid {
	case ClusterBasic:
		return "Basic"
	case ClusterPowerConfig:
		return "PowerConfig"
	case ClusterIdentify:
		return "Identify"
	case ClusterGroups:
		return "Groups"
	case ClusterScenes:
		return "Scenes"
	case ClusterOnOff:
		return "OnOff"
	case ClusterLevelControl:
		return "LevelControl"
	case ClusterColorControl:
		return "ColorControl"
	case ClusterTemperature:
		return "Temperature"
	case ClusterHumidity:
		return "Humidity"
	case ClusterOccupancySensing:
		return "OccupancySensing"
	case ClusterIASZone:
		return "IASZone"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", cid)
	}
}

// ---- ZCL attribute helpers ----

// ZCLAttribute represents a ZCL attribute read/write entry.
type ZCLAttribute struct {
	AttributeID uint16
	DataType    uint8
	Value       []byte
}

// ParseZCLReadAttrResp parses a ZCL Read Attributes Response payload.
// Each attribute: ID(2 LE) + status(1) + [datatype(1) + value] if status==0.
func ParseZCLReadAttrResp(payload []byte) ([]ZCLAttribute, error) {
	var attrs []ZCLAttribute
	pos := 0
	for pos < len(payload) {
		if pos+3 > len(payload) {
			break
		}
		attrID := uint16(payload[pos]) | uint16(payload[pos+1])<<8
		status := payload[pos+2]
		pos += 3
		if status != 0 {
			attrs = append(attrs, ZCLAttribute{AttributeID: attrID})
			continue
		}
		if pos+1 > len(payload) {
			break
		}
		dataType := payload[pos]
		pos++
		// Consume value based on data type size.
		valueLen := zclDataTypeSize(dataType)
		if valueLen < 0 || pos+valueLen > len(payload) {
			// Unknown/variable length: consume remaining.
			attrs = append(attrs, ZCLAttribute{AttributeID: attrID, DataType: dataType, Value: payload[pos:]})
			break
		}
		val := make([]byte, valueLen)
		copy(val, payload[pos:pos+valueLen])
		pos += valueLen
		attrs = append(attrs, ZCLAttribute{AttributeID: attrID, DataType: dataType, Value: val})
	}
	return attrs, nil
}

// BuildZCLReadAttr builds a ZCL Read Attributes payload from attribute IDs.
func BuildZCLReadAttr(attrIDs []uint16) []byte {
	buf := make([]byte, 0, len(attrIDs)*2)
	for _, id := range attrIDs {
		buf = append(buf, byte(id), byte(id>>8))
	}
	return buf
}

// zclDataTypeSize returns the wire size for known ZCL data types, or -1 for variable.
func zclDataTypeSize(dt uint8) int {
	switch dt {
	case 0x00: // no data
		return 0
	case 0x08: // data8
		return 1
	case 0x09: // data16
		return 2
	case 0x0A: // data24
		return 3
	case 0x0B: // data32
		return 4
	case 0x10: // boolean
		return 1
	case 0x18: // bitmap8
		return 1
	case 0x19: // bitmap16
		return 2
	case 0x1B: // bitmap32
		return 4
	case 0x20: // uint8
		return 1
	case 0x21: // uint16
		return 2
	case 0x23: // uint32
		return 4
	case 0x24: // uint40
		return 5
	case 0x25: // uint48
		return 6
	case 0x26: // uint56
		return 7
	case 0x27: // uint64
		return 8
	case 0x28: // int8
		return 1
	case 0x29: // int16
		return 2
	case 0x2B: // int32
		return 4
	case 0x30: // enum8
		return 1
	case 0x31: // enum16
		return 2
	case 0x38: // semi (float16)
		return 2
	case 0x39: // float (single)
		return 4
	case 0x3A: // double
		return 8
	case 0x41: // octet string (1-byte length prefix)
		return -1
	case 0x42: // character string (1-byte length prefix)
		return -1
	case 0xE0: // UTC time
		return 4
	case 0xE1: // cluster ID
		return 2
	case 0xE2: // attribute ID
		return 2
	case 0xF0: // IEEE address
		return 8
	case 0xFF: // unknown
		return -1
	default:
		return -1
	}
}

func init() {
	packet.RegisterLayer("ZigbeeNWK", NewZigbeeNWK)
	packet.RegisterLayer("ZigbeeAPS", NewZigbeeAPS)
	packet.RegisterLayer("ZigbeeCluster", NewZigbeeCluster)
}
