package bt

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// HCI packet type constants.
const (
	HCICommand   uint8 = 1
	HCIACLData   uint8 = 2
	HCISCOData   uint8 = 3
	HCIEvent     uint8 = 4
	HCIISOData   uint8 = 5
)

// L2CAP channel ID constants.
const (
	L2CAPCIDATT     uint16 = 0x0004
	L2CAPCIDSM      uint16 = 0x0005
	L2CAPCIDSMP     uint16 = 0x0006
	L2CAPCIDConnectionless uint16 = 0x0002
	L2CAPCIDSignal  uint16 = 0x0001
)

// ATT opcode constants.
const (
	ATTOpcodeErrorResp       uint8 = 0x01
	ATTOpcodeMTUReq          uint8 = 0x02
	ATTOpcodeMTUResp         uint8 = 0x03
	ATTOpcodeFindInfoReq     uint8 = 0x04
	ATTOpcodeFindInfoResp    uint8 = 0x05
	ATTOpcodeFindByTypeReq   uint8 = 0x06
	ATTOpcodeFindByTypeResp  uint8 = 0x07
	ATTOpcodeReadByTypeReq   uint8 = 0x08
	ATTOpcodeReadByTypeResp  uint8 = 0x09
	ATTOpcodeReadReq         uint8 = 0x0A
	ATTOpcodeReadResp        uint8 = 0x0B
	ATTOpcodeReadBlobReq     uint8 = 0x0C
	ATTOpcodeReadBlobResp    uint8 = 0x0D
	ATTOpcodeReadMultiReq    uint8 = 0x0E
	ATTOpcodeReadMultiResp   uint8 = 0x0F
	ATTOpcodeReadByGroupReq  uint8 = 0x10
	ATTOpcodeReadByGroupResp uint8 = 0x11
	ATTOpcodeWriteReq        uint8 = 0x12
	ATTOpcodeWriteResp       uint8 = 0x13
	ATTOpcodeWriteCmd        uint8 = 0x52
	ATTOpcodePrepWriteReq    uint8 = 0x16
	ATTOpcodePrepWriteResp   uint8 = 0x17
	ATTOpcodeExecWriteReq    uint8 = 0x18
	ATTOpcodeExecWriteResp   uint8 = 0x19
	ATTOpcodeNotify          uint8 = 0x1B
	ATTOpcodeIndicate        uint8 = 0x1D
	ATTOpcodeConfirm         uint8 = 0x1E
)

// SM opcode constants.
const (
	SMOpcodePairingReq    uint8 = 0x01
	SMOpcodePairingResp   uint8 = 0x02
	SMOpcodePairingRandom uint8 = 0x04
	SMOpcodePairingFailed uint8 = 0x05
	SMOpcodeEncryptInfo   uint8 = 0x06
	SMOpcodeMasterIdent   uint8 = 0x07
)

// EIR type constants.
const (
	EIRTypeFlags        uint8 = 0x01
	EIRTypeUUID16       uint8 = 0x03
	EIRTypeUUID128      uint8 = 0x07
	EIRTypeShortName    uint8 = 0x08
	EIRTypeCompleteName uint8 = 0x09
	EIRTypeTxPowerLevel uint8 = 0x0A
	EIRTypeClassOfDev   uint8 = 0x0D
	EIRTypeSlaveIntRange uint8 = 0x12
	EIRType16bitSolUUID uint8 = 0x14
	EIRTypeAppearance   uint8 = 0x19
	EIRTypeLEDeviceAddr uint8 = 0x1B
	EIRTypeLERole       uint8 = 0x1C
	EIRTypeManufacturer uint8 = 0xFF
)

// ATT error codes.
const (
	ATTErrorInvalidHandle     uint8 = 0x02
	ATTErrorReadNotPermitted  uint8 = 0x02
	ATTErrorWriteNotPermitted uint8 = 0x03
	ATTErrorInvalidPDU        uint8 = 0x04
	ATTErrorRequestNotSupp    uint8 = 0x06
	ATTErrorInvalidOffset     uint8 = 0x07
	ATTErrorAuthRequired      uint8 = 0x08
	ATTErrorPrepQueueFull     uint8 = 0x09
	ATTErrorNotFound          uint8 = 0x0A
	ATTErrorNotLong           uint8 = 0x0B
	ATTErrorInsufficientEnc   uint8 = 0x0F
	ATTErrorUnsupportedGroup  uint8 = 0x10
	ATTErrorInsufficientAuthz uint8 = 0x18
)

// ---- Layer constructors ----

// NewHCI creates an HCI layer.
// Fields: type(1), opcode_or_event(2), param_len(1), params(variable)
func NewHCI() *packet.Layer {
	return packet.NewLayer("HCI", []fields.Field{
		fields.NewByteField("type", HCICommand),
		fields.NewShortField("opcode", 0), // command opcode or event code
		fields.NewByteField("param_len", 0),
		fields.NewStrField("params", ""),
	})
}

// NewL2CAP creates an L2CAP layer.
func NewL2CAP() *packet.Layer {
	return packet.NewLayer("L2CAP", []fields.Field{
		fields.NewShortField("length", 0),   // PDU length
		fields.NewShortField("cid", 0x0004), // channel ID (ATT by default)
		fields.NewStrField("data", ""),
	})
}

// NewATT creates a BLE ATT (Attribute Protocol) layer.
func NewATT() *packet.Layer {
	return packet.NewLayer("ATT", []fields.Field{
		fields.NewByteField("opcode", ATTOpcodeReadReq),
		fields.NewStrField("params", ""),
	})
}

// NewSM creates a BLE SM (Security Manager) layer.
func NewSM() *packet.Layer {
	return packet.NewLayer("SM", []fields.Field{
		fields.NewByteField("opcode", SMOpcodePairingReq),
		fields.NewStrField("data", ""),
	})
}

// ---- EIR TLV helpers ----

// EIR represents an Extended Inquiry Response entry.
type EIR struct {
	Type uint8
	Data []byte
}

// ParseEIR parses raw EIR data into a list of entries.
func ParseEIR(data []byte) ([]EIR, error) {
	var entries []EIR
	pos := 0
	for pos < len(data) {
		if pos >= len(data) {
			break
		}
		length := int(data[pos])
		if length == 0 {
			break
		}
		if pos+1+length > len(data) {
			return entries, fmt.Errorf("bt: EIR truncated at offset %d", pos)
		}
		eirType := data[pos+1]
		eirData := make([]byte, length-1)
		copy(eirData, data[pos+2:pos+1+length])
		entries = append(entries, EIR{Type: eirType, Data: eirData})
		pos += 1 + length
	}
	return entries, nil
}

// BuildEIR serializes a list of EIR entries into raw bytes.
func BuildEIR(entries []EIR) []byte {
	var buf []byte
	for _, e := range entries {
		totalLen := 1 + len(e.Data)
		buf = append(buf, byte(totalLen))
		buf = append(buf, e.Type)
		buf = append(buf, e.Data...)
	}
	return buf
}

// FindEIR finds the first EIR entry with the given type.
func FindEIR(entries []EIR, eirType uint8) *EIR {
	for i := range entries {
		if entries[i].Type == eirType {
			return &entries[i]
		}
	}
	return nil
}

// DeviceName extracts the device name from EIR entries.
func DeviceName(entries []EIR) string {
	if e := FindEIR(entries, EIRTypeCompleteName); e != nil {
		return string(e.Data)
	}
	if e := FindEIR(entries, EIRTypeShortName); e != nil {
		return string(e.Data)
	}
	return ""
}

// ---- ATT parse helpers ----

// ATTError represents a parsed ATT Error Response.
type ATTError struct {
	RequestOpcode uint8
	Handle        uint16
	ErrorCode     uint8
}

// ParseATTError parses an ATT Error Response params.
func ParseATTError(params []byte) (*ATTError, error) {
	if len(params) < 4 {
		return nil, fmt.Errorf("bt: ATT error response too short: %d", len(params))
	}
	return &ATTError{
		RequestOpcode: params[0],
		Handle:        uint16(params[1]) | uint16(params[2])<<8,
		ErrorCode:     params[3],
	}, nil
}

// ATTReadByTypeReq represents an ATT Read By Type Request.
type ATTReadByTypeReq struct {
	StartHandle uint16
	EndHandle   uint16
	UUID        []byte // 2 or 16 bytes
}

// ParseATTReadByTypeReq parses ATT Read By Type Request params.
func ParseATTReadByTypeReq(params []byte) (*ATTReadByTypeReq, error) {
	if len(params) < 4 {
		return nil, fmt.Errorf("bt: ATT ReadByTypeReq too short")
	}
	req := &ATTReadByTypeReq{
		StartHandle: uint16(params[0]) | uint16(params[1])<<8,
		EndHandle:   uint16(params[2]) | uint16(params[3])<<8,
	}
	if len(params) > 4 {
		req.UUID = make([]byte, len(params)-4)
		copy(req.UUID, params[4:])
	}
	return req, nil
}

// ATTWriteReq represents an ATT Write Request.
type ATTWriteReq struct {
	Handle uint16
	Value  []byte
}

// ParseATTWriteReq parses ATT Write Request params.
func ParseATTWriteReq(params []byte) (*ATTWriteReq, error) {
	if len(params) < 2 {
		return nil, fmt.Errorf("bt: ATT WriteReq too short")
	}
	req := &ATTWriteReq{
		Handle: uint16(params[0]) | uint16(params[1])<<8,
	}
	if len(params) > 2 {
		req.Value = make([]byte, len(params)-2)
		copy(req.Value, params[2:])
	}
	return req, nil
}

// ATTNotify represents a parsed ATT Notification/Indication.
type ATTNotify struct {
	Handle uint16
	Value  []byte
}

// ParseATTNotify parses ATT Notification or Indication params.
func ParseATTNotify(params []byte) (*ATTNotify, error) {
	if len(params) < 2 {
		return nil, fmt.Errorf("bt: ATT Notify too short")
	}
	n := &ATTNotify{
		Handle: uint16(params[0]) | uint16(params[1])<<8,
	}
	if len(params) > 2 {
		n.Value = make([]byte, len(params)-2)
		copy(n.Value, params[2:])
	}
	return n, nil
}

// ---- SM parse helpers ----

// SMPairingReq represents a parsed SM Pairing Request/Response.
type SMPairingReq struct {
	IOCapability  uint8
	OOBDataFlag   uint8
	AuthReq       uint8
	MaxEncSize    uint8
	InitKeyDist   uint8
	RespKeyDist   uint8
}

// ParseSMPairingReq parses SM Pairing Request or Response data.
func ParseSMPairingReq(data []byte) (*SMPairingReq, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("bt: SM PairingReq too short: %d", len(data))
	}
	return &SMPairingReq{
		IOCapability: data[0],
		OOBDataFlag:  data[1],
		AuthReq:      data[2],
		MaxEncSize:   data[3],
		InitKeyDist:  data[4],
		RespKeyDist:  data[5],
	}, nil
}

// ---- String helpers ----

// HCITypeString returns a human-readable HCI packet type.
func HCITypeString(t uint8) string {
	switch t {
	case HCICommand:
		return "Command"
	case HCIACLData:
		return "ACL Data"
	case HCISCOData:
		return "SCO Data"
	case HCIEvent:
		return "Event"
	case HCIISOData:
		return "ISO Data"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// ATTOpcodeString returns a human-readable ATT opcode name.
func ATTOpcodeString(op uint8) string {
	switch op {
	case ATTOpcodeErrorResp:
		return "ErrorResp"
	case ATTOpcodeMTUReq:
		return "MTUReq"
	case ATTOpcodeMTUResp:
		return "MTUResp"
	case ATTOpcodeReadByTypeReq:
		return "ReadByTypeReq"
	case ATTOpcodeReadByTypeResp:
		return "ReadByTypeResp"
	case ATTOpcodeReadReq:
		return "ReadReq"
	case ATTOpcodeReadResp:
		return "ReadResp"
	case ATTOpcodeWriteReq:
		return "WriteReq"
	case ATTOpcodeWriteResp:
		return "WriteResp"
	case ATTOpcodeNotify:
		return "Notify"
	case ATTOpcodeIndicate:
		return "Indicate"
	case ATTOpcodeReadByGroupReq:
		return "ReadByGroupReq"
	case ATTOpcodeReadByGroupResp:
		return "ReadByGroupResp"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", op)
	}
}

func init() {
	packet.RegisterLayer("HCI", NewHCI)
	packet.RegisterLayer("L2CAP", NewL2CAP)
	packet.RegisterLayer("ATT", NewATT)
	packet.RegisterLayer("SM", NewSM)
}
