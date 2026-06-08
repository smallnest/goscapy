// Package lorawan provides a basic LoRaWAN protocol layer implementation
// per the LoRaWAN Specification v1.0.x.
package lorawan

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ---- MHDR constants ----

// MType (Message Type) values in the MHDR byte.
const (
	MTypeJoinRequest      uint8 = 0
	MTypeJoinAccept       uint8 = 1
	MTypeUnconfirmedUp    uint8 = 2
	MTypeUnconfirmedDown  uint8 = 3
	MTypeConfirmedUp      uint8 = 4
	MTypeConfirmedDown    uint8 = 5
	MTypeRejoinRequest    uint8 = 6
	MTypeProprietary      uint8 = 7
)

// LoRaWAN major version.
const Major uint8 = 0

// ---- FCtrl flags (for FHDR) ----

const (
	FCtrlADR       uint8 = 1 << 6
	FCtrlADRAckReq uint8 = 1 << 5
	FCtrlAck       uint8 = 1 << 4
	FCtrlFPending  uint8 = 1 << 3 // downlink only
)

// ---- MAC command identifiers ----

const (
	MACCmdLinkCheckAns      uint8 = 0x02
	MACCmdLinkADRReq        uint8 = 0x03
	MACCmdLinkADRAck        uint8 = 0x04
	MACCmdDutyCycleReq      uint8 = 0x05
	MACCmdRXParamSetupReq   uint8 = 0x06
	MACCmdDevStatusReq      uint8 = 0x07
	MACCmdNewChannelReq     uint8 = 0x08
	MACCmdRXTimingSetupReq  uint8 = 0x09
	MACCmdTXParamSetupReq   uint8 = 0x0A
	MACCmdDlChannelReq      uint8 = 0x0B
	MACCmdRekeyInd          uint8 = 0x0C
	MACCmdRekeyConf         uint8 = 0x0D
	MACCmdDeviceTimeAns     uint8 = 0x0E
)

// ---- Join Request constants ----

const JoinRequestSize = 23 // MHDR(1) + AppEUI(8) + DevEUI(8) + DevNonce(2) + MIC(4)

// ---- Layer constructors ----

// NewLoRaWAN creates a basic LoRaWAN data frame layer.
// The layer stores the fixed FHDR fields (mhdr, dev_addr, fctrl, fcnt) plus
// a variable "data" field that contains FOpts + FPort + FRMPayload + MIC.
// Use ParseLoRaWANData / BuildLoRaWANData to decompose/compose the data field.
func NewLoRaWAN() *packet.Layer {
	return packet.NewLayer("LoRaWAN", []fields.Field{
		fields.NewByteField("mhdr", uint8(MTypeUnconfirmedUp)<<5|Major),
		fields.NewLEIntField("dev_addr", 0),
		fields.NewByteField("fctrl", 0),
		fields.NewLEShortField("fcnt", 0),
		fields.NewStrField("data", ""), // FOpts + FPort + FRMPayload + MIC
	})
}

// NewLoRaWANJoinReq creates a LoRaWAN Join Request layer.
func NewLoRaWANJoinReq() *packet.Layer {
	return packet.NewLayer("LoRaWANJoinReq", []fields.Field{
		fields.NewByteField("mhdr", uint8(MTypeJoinRequest)<<5|Major),
		fields.NewStrFixedField("app_eui", 8, make([]byte, 8)),
		fields.NewStrFixedField("dev_eui", 8, make([]byte, 8)),
		fields.NewLEShortField("dev_nonce", 0),
		fields.NewStrFixedField("mic", 4, make([]byte, 4)),
	})
}

// NewLoRaWANJoinAccept creates a LoRaWAN Join Accept layer.
// The variable part (cf_list + mic) is stored in "data" for serialization.
// Use ParseJoinAcceptData to decompose.
func NewLoRaWANJoinAccept() *packet.Layer {
	return packet.NewLayer("LoRaWANJoinAccept", []fields.Field{
		fields.NewByteField("mhdr", uint8(MTypeJoinAccept)<<5|Major),
		fields.NewStrFixedField("app_nonce", 3, make([]byte, 3)),
		fields.NewStrFixedField("net_id", 3, make([]byte, 3)),
		fields.NewLEIntField("dev_addr", 0),
		fields.NewByteField("dl_settings", 0),
		fields.NewByteField("rx_delay", 1),
		fields.NewStrField("data", ""), // cf_list(variable) + mic(4)
	})
}

// JoinAcceptData holds the decomposed variable part of a Join Accept.
type JoinAcceptData struct {
	CFList []byte // Channel Frequency list (0 or 16 bytes)
	MIC    []byte // Message Integrity Code (4 bytes)
}

// ParseJoinAcceptData decomposes the "data" field of a Join Accept.
// The last 4 bytes are MIC; any preceding bytes are CFList.
func ParseJoinAcceptData(data []byte) *JoinAcceptData {
	if len(data) <= 4 {
		mic := make([]byte, 4)
		if len(data) == 4 {
			copy(mic, data)
		}
		return &JoinAcceptData{MIC: mic}
	}
	cfList := make([]byte, len(data)-4)
	copy(cfList, data[:len(data)-4])
	mic := make([]byte, 4)
	copy(mic, data[len(data)-4:])
	return &JoinAcceptData{CFList: cfList, MIC: mic}
}

// BuildJoinAcceptData composes the "data" field for a Join Accept.
func BuildJoinAcceptData(d *JoinAcceptData) []byte {
	mic := d.MIC
	if len(mic) < 4 {
		mic = make([]byte, 4)
	}
	buf := make([]byte, 0, len(d.CFList)+4)
	buf = append(buf, d.CFList...)
	buf = append(buf, mic...)
	return buf
}

// ---- LoRaWAN data field decomposition ----

// LoRaWANData holds the decomposed variable part of a LoRaWAN data frame.
type LoRaWANData struct {
	FOpts    []byte // MAC commands (0-15 bytes)
	FPort    uint8  // 0 for MAC-only, 1-223 for application
	Payload  []byte // FRMPayload (encrypted on wire)
	MIC      []byte // Message Integrity Code (4 bytes)
}

// ParseLoRaWANData decomposes the "data" field of a LoRaWAN layer into
// FOpts, FPort, Payload, and MIC. foptsLen comes from fctrl's low nibble.
// The data field must be at least 5 bytes (1 FPort + 4 MIC) when foptsLen=0.
func ParseLoRaWANData(data []byte, foptsLen int) (*LoRaWANData, error) {
	if foptsLen < 0 || foptsLen > 15 {
		return nil, fmt.Errorf("lorawan: invalid FOptsLen %d", foptsLen)
	}
	if len(data) < foptsLen+5 { // at minimum: FOpts + FPort(1) + MIC(4)
		return nil, fmt.Errorf("lorawan: data too short: %d bytes, need at least %d", len(data), foptsLen+5)
	}

	result := &LoRaWANData{
		FOpts: data[:foptsLen],
	}
	rest := data[foptsLen:]
	// MIC is the last 4 bytes
	result.MIC = make([]byte, 4)
	copy(result.MIC, rest[len(rest)-4:])
	// Between FOpts and MIC: FPort(1) + Payload
	middle := rest[:len(rest)-4]
	if len(middle) > 0 {
		result.FPort = middle[0]
		if len(middle) > 1 {
			result.Payload = make([]byte, len(middle)-1)
			copy(result.Payload, middle[1:])
		}
	}
	return result, nil
}

// BuildLoRaWANData composes the "data" field from decomposed parts.
func BuildLoRaWANData(d *LoRaWANData) []byte {
	if d == nil {
		return nil
	}
	foptsLen := len(d.FOpts)
	total := foptsLen + 1 + len(d.Payload) + 4 // FOpts + FPort + Payload + MIC
	buf := make([]byte, 0, total)
	buf = append(buf, d.FOpts...)
	buf = append(buf, d.FPort)
	buf = append(buf, d.Payload...)
	mic := d.MIC
	if len(mic) < 4 {
		mic = make([]byte, 4)
	}
	buf = append(buf, mic...)
	return buf
}

// ---- MHDR helpers ----

// MTypeFromMHDR extracts the MType from the MHDR byte.
func MTypeFromMHDR(mhdr uint8) uint8 { return mhdr >> 5 }

// MajorFromMHDR extracts the major version from the MHDR byte.
func MajorFromMHDR(mhdr uint8) uint8 { return mhdr & 0x03 }

// MTypeString returns a human-readable MType name.
func MTypeString(mt uint8) string {
	switch mt {
	case MTypeJoinRequest:
		return "JoinRequest"
	case MTypeJoinAccept:
		return "JoinAccept"
	case MTypeUnconfirmedUp:
		return "UnconfirmedDataUp"
	case MTypeUnconfirmedDown:
		return "UnconfirmedDataDown"
	case MTypeConfirmedUp:
		return "ConfirmedDataUp"
	case MTypeConfirmedDown:
		return "ConfirmedDataDown"
	case MTypeRejoinRequest:
		return "RejoinRequest"
	case MTypeProprietary:
		return "Proprietary"
	default:
		return fmt.Sprintf("Unknown(%d)", mt)
	}
}

// FCtrlFOptsLen extracts the FOpts length from FCtrl.
func FCtrlFOptsLen(fctrl uint8) uint8 { return fctrl & 0x0F }

// IsFCtrlADR returns whether the ADR bit is set.
func IsFCtrlADR(fctrl uint8) bool { return fctrl&FCtrlADR != 0 }

// IsFCtrlAck returns whether the ACK bit is set.
func IsFCtrlAck(fctrl uint8) bool { return fctrl&FCtrlAck != 0 }

// ---- MAC command helpers ----

// MACCommand represents a parsed LoRaWAN MAC command.
type MACCommand struct {
	CID   uint8
	Value []byte
}

// ParseMACCommands parses FOpts bytes into MAC commands.
func ParseMACCommands(fopts []byte) ([]MACCommand, error) {
	var cmds []MACCommand
	pos := 0
	for pos < len(fopts) {
		cid := fopts[pos]
		pos++
		valueLen := macCmdPayloadLen(cid)
		if valueLen < 0 {
			cmds = append(cmds, MACCommand{CID: cid, Value: fopts[pos:]})
			break
		}
		if pos+valueLen > len(fopts) {
			return cmds, fmt.Errorf("lorawan: MAC command 0x%02x needs %d bytes, have %d", cid, valueLen, len(fopts)-pos)
		}
		val := make([]byte, valueLen)
		copy(val, fopts[pos:pos+valueLen])
		cmds = append(cmds, MACCommand{CID: cid, Value: val})
		pos += valueLen
	}
	return cmds, nil
}

// BuildMACCommands serializes MAC commands to wire format.
func BuildMACCommands(cmds []MACCommand) []byte {
	var buf []byte
	for _, c := range cmds {
		buf = append(buf, c.CID)
		buf = append(buf, c.Value...)
	}
	return buf
}

// macCmdPayloadLen returns the expected payload length for a MAC command CID.
func macCmdPayloadLen(cid uint8) int {
	switch cid {
	case MACCmdLinkCheckAns:
		return 2
	case MACCmdLinkADRReq:
		return 4
	case MACCmdLinkADRAck:
		return 1
	case MACCmdDutyCycleReq:
		return 1
	case MACCmdRXParamSetupReq:
		return 4
	case MACCmdDevStatusReq:
		return 0
	case MACCmdNewChannelReq:
		return 5
	case MACCmdRXTimingSetupReq:
		return 1
	case MACCmdTXParamSetupReq:
		return 1
	case MACCmdDlChannelReq:
		return 4
	case MACCmdRekeyInd:
		return 1
	case MACCmdRekeyConf:
		return 1
	case MACCmdDeviceTimeAns:
		return 5
	default:
		return -1
	}
}

func init() {
	packet.RegisterLayer("LoRaWAN", NewLoRaWAN)
	packet.RegisterLayer("LoRaWANJoinReq", NewLoRaWANJoinReq)
	packet.RegisterLayer("LoRaWANJoinAccept", NewLoRaWANJoinAccept)
}
