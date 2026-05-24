package dot11

import (
	"encoding/binary"
	"fmt"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Frame type constants.
const (
	TypeManagement uint8 = 0
	TypeControl    uint8 = 1
	TypeData       uint8 = 2
	TypeExtension  uint8 = 3
)

// Management frame subtype constants.
const (
	SubtypeAssocReq    uint8 = 0
	SubtypeAssocResp   uint8 = 1
	SubtypeReassocReq  uint8 = 2
	SubtypeReassocResp uint8 = 3
	SubtypeProbeReq    uint8 = 4
	SubtypeProbeResp   uint8 = 5
	SubtypeBeacon      uint8 = 8
	SubtypeATIM        uint8 = 9
	SubtypeDisas       uint8 = 10
	SubtypeAuth        uint8 = 11
	SubtypeDeauth      uint8 = 12
	SubtypeAction      uint8 = 13
)

// FC field flag bits.
const (
	FlagToDS      uint8 = 1 << 0
	FlagFromDS    uint8 = 1 << 1
	FlagMoreFrag  uint8 = 1 << 2
	FlagRetry     uint8 = 1 << 3
	FlagPowerMgmt uint8 = 1 << 4
	FlagMoreData  uint8 = 1 << 5
	FlagProtected uint8 = 1 << 6
	FlagOrder     uint8 = 1 << 7
)

// Reason codes.
const (
	ReasonUnspecified         uint16 = 1
	ReasonAuthExpired         uint16 = 2
	ReasonDeauthLeaving       uint16 = 3
	ReasonInactivity          uint16 = 4
	ReasonAPFull              uint16 = 5
	ReasonClass2FromNonAuth   uint16 = 6
	ReasonClass3FromNonAss    uint16 = 7
	ReasonDisasLeaving        uint16 = 8
	ReasonNotAuthenticated    uint16 = 9
)

// Status codes.
const (
	StatusSuccess     uint16 = 0
	StatusFailure     uint16 = 1
	StatusCapabilities uint16 = 10
	StatusAssocDenied uint16 = 11
)

// Dot11Elt ID constants.
const (
	EltIDSSID              uint8 = 0
	EltIDSupportedRates    uint8 = 1
	EltIDDSSS              uint8 = 3
	EltIDTIM               uint8 = 5
	EltIDCountry           uint8 = 7
	EltIDERP               uint8 = 42
	EltIDHTCapabilities    uint8 = 45
	EltIDRSN               uint8 = 48
	EltIDExtSupportedRates uint8 = 50
	EltIDVendorSpecific    uint8 = 221
)

// SetFC constructs a Frame Control byte pair from type, subtype, flags.
// Byte 0: proto(2)=0 | type(2) | subtype(4)
// Byte 1: flags(8)
func SetFC(ftype, subtype, flags uint8) [2]byte {
	return [2]byte{(subtype << 4) | (ftype << 2), flags}
}

// FCType extracts the type (2 bits) from FC byte 0.
func FCType(fc0 byte) uint8 { return (fc0 >> 2) & 0x03 }

// FCSubtype extracts the subtype (4 bits) from FC byte 0.
func FCSubtype(fc0 byte) uint8 { return fc0 >> 4 }

// FCFlags extracts the flags byte from FC byte 1.
func FCFlags(fc [2]byte) uint8 { return fc[1] }

// SCSeq extracts sequence number from SC field.
func SCSeq(sc uint16) uint16 { return sc >> 4 }

// SCFrag extracts fragment number from SC field.
func SCFrag(sc uint16) uint8 { return uint8(sc & 0x0F) }

// NewDot11 creates a base 802.11 frame layer.
// Default: type=0 (management), subtype=8 (beacon), flags=0, addr1=broadcast.
func NewDot11() *packet.Layer {
	return packet.NewLayer("Dot11", []fields.Field{
		fields.NewByteField("fc0", 0x80),               // subtype=8, type=0, proto=0
		fields.NewByteField("fc1", 0),                   // flags
		fields.NewLEShortField("duration", 0),           // duration/ID
		fields.NewMACField("addr1", broadcastMAC()),     // receiver
		fields.NewMACField("addr2", zeroMAC()),          // transmitter
		fields.NewMACField("addr3", zeroMAC()),          // BSSID / filter
		fields.NewLEShortField("sc", 0),                 // sequence control
	})
}

// NewRadioTap creates a RadioTap header layer.
// The variable-length data after the 8-byte fixed header is stored in "data".
func NewRadioTap() *packet.Layer {
	return packet.NewLayer("RadioTap", []fields.Field{
		fields.NewByteField("version", 0),
		fields.NewByteField("pad", 0),
		fields.NewLEShortField("len", 8), // auto-updated by build hook
		fields.NewLEIntField("present", 0),
		fields.NewStrField("data", ""), // variable-length field data
	})
}

// NewDot11Beacon creates a Beacon frame body layer.
func NewDot11Beacon() *packet.Layer {
	return packet.NewLayer("Dot11Beacon", []fields.Field{
		fields.NewLELongField("timestamp", 0),
		fields.NewLEShortField("beacon_interval", 0x0064), // 100 TUs
		fields.NewLEShortField("cap", 0),                  // capability info
	})
}

// NewDot11ProbeReq creates a Probe Request frame body (no fixed fields, just IEs).
func NewDot11ProbeReq() *packet.Layer {
	return packet.NewLayer("Dot11ProbeReq", []fields.Field{
		fields.NewStrField("data", ""),
	})
}

// NewDot11ProbeResp creates a Probe Response frame body (same structure as Beacon).
func NewDot11ProbeResp() *packet.Layer {
	return packet.NewLayer("Dot11ProbeResp", []fields.Field{
		fields.NewLELongField("timestamp", 0),
		fields.NewLEShortField("beacon_interval", 0x0064),
		fields.NewLEShortField("cap", 0),
	})
}

// NewDot11Auth creates an Authentication frame body layer.
func NewDot11Auth() *packet.Layer {
	return packet.NewLayer("Dot11Auth", []fields.Field{
		fields.NewLEShortField("algo", 0),    // 0=open, 1=shared key
		fields.NewLEShortField("seqnum", 0),
		fields.NewLEShortField("status", 0),
	})
}

// NewDot11Deauth creates a Deauthentication frame body layer.
func NewDot11Deauth() *packet.Layer {
	return packet.NewLayer("Dot11Deauth", []fields.Field{
		fields.NewLEShortField("reason", 1),
	})
}

// NewDot11Disas creates a Disassociation frame body layer.
func NewDot11Disas() *packet.Layer {
	return packet.NewLayer("Dot11Disas", []fields.Field{
		fields.NewLEShortField("reason", 1),
	})
}

// NewDot11QoS creates a QoS control field layer (2 bytes).
func NewDot11QoS() *packet.Layer {
	return packet.NewLayer("Dot11QoS", []fields.Field{
		fields.NewByteField("qos0", 0), // TID(4), EOSP(1), AckPolicy(2), A_MSDU(1)
		fields.NewByteField("qos1", 0), // TXOP
	})
}

// NewDot11Elt creates an Information Element layer.
func NewDot11Elt() *packet.Layer {
	return packet.NewLayer("Dot11Elt", []fields.Field{
		fields.NewByteField("id", 0),
		fields.NewByteField("len", 0),
		fields.NewStrField("info", ""),
	})
}

// ---- Dot11Elt TLV helpers ----

// IE represents a tagged information element.
type IE struct {
	ID   uint8
	Info []byte
}

// BuildDot11Elts serializes a list of IEs into raw bytes.
func BuildDot11Elts(elts []IE) []byte {
	var buf []byte
	for _, e := range elts {
		info := e.Info
		if len(info) > 255 {
			info = info[:255]
		}
		buf = append(buf, e.ID, uint8(len(info)))
		buf = append(buf, info...)
	}
	return buf
}

// ParseDot11Elts parses raw bytes into a list of IEs.
func ParseDot11Elts(data []byte) ([]IE, error) {
	var elts []IE
	pos := 0
	for pos+2 <= len(data) {
		id := data[pos]
		length := int(data[pos+1])
		if pos+2+length > len(data) {
			return elts, fmt.Errorf("dot11: IE id=%d len=%d exceeds data (remaining %d)", id, length, len(data)-pos-2)
		}
		info := make([]byte, length)
		copy(info, data[pos+2:pos+2+length])
		elts = append(elts, IE{ID: id, Info: info})
		pos += 2 + length
	}
	return elts, nil
}

// FindIE finds the first IE with the given ID.
func FindIE(elts []IE, id uint8) *IE {
	for i := range elts {
		if elts[i].ID == id {
			return &elts[i]
		}
	}
	return nil
}

// SSIDFromIE extracts SSID string from IE list.
func SSIDFromIE(elts []IE) string {
	ie := FindIE(elts, EltIDSSID)
	if ie == nil {
		return ""
	}
	return string(ie.Info)
}

// ---- RadioTap helpers ----

// RadioTapPresentFlags defines presence bitmap bit indices.
const (
	RTFlagTSFT        = 0
	RTFlagFlags       = 1
	RTFlagRate        = 2
	RTFlagChannel     = 3
	RTFlagDBmAntSignal = 5
	RTFlagDBmAntNoise = 6
	RTFlagAntenna     = 11
	RTFlagRXFlags     = 14
)

// ParseRadioTapData parses variable-length RadioTap field data based on the presence bitmap.
// Returns a map of field name → value.
func ParseRadioTapData(data []byte, present uint32) map[string]any {
	result := make(map[string]any)
	pos := 0

	// Bit 0: TSFT (8 bytes)
	if present&(1<<RTFlagTSFT) != 0 {
		pos = align4(pos)
		if pos+8 <= len(data) {
			result["tsft"] = binary.LittleEndian.Uint64(data[pos : pos+8])
			pos += 8
		}
	}
	// Bit 1: Flags (1 byte)
	if present&(1<<RTFlagFlags) != 0 {
		if pos+1 <= len(data) {
			result["flags"] = data[pos]
			pos++
		}
	}
	// Bit 2: Rate (1 byte, 0.5 Mbps units)
	if present&(1<<RTFlagRate) != 0 {
		if pos+1 <= len(data) {
			result["rate"] = data[pos]
			pos++
		}
	}
	// Bit 3: Channel (4 bytes: freq 2 + flags 2)
	if present&(1<<RTFlagChannel) != 0 {
		pos = align4(pos)
		if pos+4 <= len(data) {
			result["channel_freq"] = binary.LittleEndian.Uint16(data[pos : pos+2])
			result["channel_flags"] = binary.LittleEndian.Uint16(data[pos+2 : pos+4])
			pos += 4
		}
	}
	// Bit 5: dBm Antenna Signal (1 byte signed)
	if present&(1<<RTFlagDBmAntSignal) != 0 {
		if pos+1 <= len(data) {
			result["dbm_antsignal"] = int8(data[pos])
			pos++
		}
	}
	// Bit 6: dBm Antenna Noise (1 byte signed)
	if present&(1<<RTFlagDBmAntNoise) != 0 {
		if pos+1 <= len(data) {
			result["dbm_antnoise"] = int8(data[pos])
			pos++
		}
	}
	// Bit 11: Antenna (1 byte)
	if present&(1<<RTFlagAntenna) != 0 {
		if pos+1 <= len(data) {
			result["antenna"] = data[pos]
			pos++
		}
	}
	// Bit 14: RX Flags (2 bytes)
	if present&(1<<RTFlagRXFlags) != 0 {
		pos = align2(pos)
		if pos+2 <= len(data) {
			result["rxflags"] = binary.LittleEndian.Uint16(data[pos : pos+2])
			pos += 2
		}
	}

	return result
}

// ---- Build hooks ----

func radiotapBuildHook(pkt *packet.Packet, layerIdx int, upperBytes []byte) ([]byte, error) {
	layer := pkt.Layers()[layerIdx]
	totalLen := 8 + len(upperBytes)
	layer.Set("len", uint16(totalLen))
	return layer.SerializeFields()
}

// ---- Header size functions ----

func radiotapHeaderSize(layer *packet.Layer) int {
	l, _ := layer.Get("len")
	return int(l.(uint16))
}

// ---- Helpers ----

func broadcastMAC() []byte { return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} }
func zeroMAC() []byte      { return []byte{0, 0, 0, 0, 0, 0} }

func align2(n int) int { return (n + 1) &^ 1 }
func align4(n int) int { return (n + 3) &^ 3 }

func init() {
	packet.RegisterLayer("Dot11", NewDot11)
	packet.RegisterLayer("RadioTap", NewRadioTap)
	packet.RegisterLayer("Dot11Beacon", NewDot11Beacon)
	packet.RegisterLayer("Dot11ProbeReq", NewDot11ProbeReq)
	packet.RegisterLayer("Dot11ProbeResp", NewDot11ProbeResp)
	packet.RegisterLayer("Dot11Auth", NewDot11Auth)
	packet.RegisterLayer("Dot11Deauth", NewDot11Deauth)
	packet.RegisterLayer("Dot11Disas", NewDot11Disas)
	packet.RegisterLayer("Dot11QoS", NewDot11QoS)
	packet.RegisterLayer("Dot11Elt", NewDot11Elt)

	// RadioTap → Dot11
	packet.RegisterBinding("Dot11", "RadioTap", "len", uint16(0))

	// Build hooks
	packet.RegisterBuildHook("RadioTap", radiotapBuildHook)

	// Variable header size for RadioTap
	packet.RegisterHeaderSizeFunc("RadioTap", radiotapHeaderSize)
}
