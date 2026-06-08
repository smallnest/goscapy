// Package kerberos provides Kerberos (RFC 4120) protocol layer implementation.
// Kerberos messages use ASN.1/BER encoding.
package kerberos

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/asn1"
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Kerberos message type constants (RFC 4120 Section 7.1).
const (
	MsgTypeASREQ   = 10
	MsgTypeASREP   = 11
	MsgTypeTGSREQ  = 12
	MsgTypeTGSREP  = 13
	MsgTypeAPREQ   = 14
	MsgTypeAPREP   = 15
	MsgTypeTICKET  = 16
	MsgTypeAuth    = 17
	MsgTypeKRBPRI  = 20
	MsgTypeKRBERR  = 30
)

// Kerberos application tags (context-specific constructed).
const (
	TagASREQ  byte = 0x6A
	TagASREP  byte = 0x6B
	TagTGSREQ byte = 0x6C
	TagTGSREP byte = 0x6D
	TagAPREQ  byte = 0x6E
	TagAPREP  byte = 0x6F
)

// Kerberos error codes (RFC 4120 Section 7.5.9).
const (
	KDCErrNone                 = 0
	KDCErrNameExp              = 1
	KDCErrServiceExp           = 2
	KDCErrBadKVNO              = 4
	KDCErrCPPrincipalUnknown   = 5
	KDCErrCPrincipalUnknown    = 6
	KDCErrNoTGT                = 8
	KDCErrRealmUnknown         = 10
	KDCErrGeneric              = 60
	KDCErrFieldToolong         = 61
	KDCErrWrongRealm           = 68
	KDCErrSVCUnavail           = 71
	KDCErrKeyExpired           = 65
	KDCErrPreauthFailed        = 24
	KDCErrPreauthRequired      = 25
	KDCErrServerNotFound       = 70
)

// PVNO is the Kerberos protocol version number.
const PVNO = 5

// PrincipalName represents a Kerberos principal name.
type PrincipalName struct {
	NameType   int
	NameString []string
}

// KerberosMsg represents a parsed Kerberos message.
type KerberosMsg struct {
	MsgType int    // 10=AS-REQ, 11=AS-REP, 12=TGS-REQ, 13=TGS-REP, 14=AP-REQ, 15=AP-REP
	PVNO    int    // protocol version number (5)
	Realm   string // realm
	CName   PrincipalName // client principal name
	SName   PrincipalName // server principal name
	Raw     []byte // full raw BER-encoded message for re-serialization
}

// MsgTypeName returns the name for a Kerberos message type.
func MsgTypeName(msgType int) string {
	switch msgType {
	case MsgTypeASREQ:
		return "AS-REQ"
	case MsgTypeASREP:
		return "AS-REP"
	case MsgTypeTGSREQ:
		return "TGS-REQ"
	case MsgTypeTGSREP:
		return "TGS-REP"
	case MsgTypeAPREQ:
		return "AP-REQ"
	case MsgTypeAPREP:
		return "AP-REP"
	case MsgTypeTICKET:
		return "Ticket"
	case MsgTypeAuth:
		return "Authenticator"
	case MsgTypeKRBERR:
		return "KRB-ERROR"
	case MsgTypeKRBPRI:
		return "KRB-PRIV"
	default:
		return fmt.Sprintf("Unknown(%d)", msgType)
	}
}

// ErrCodeName returns the name for a Kerberos error code.
func ErrCodeName(code int) string {
	switch code {
	case KDCErrNone:
		return "none"
	case KDCErrNameExp:
		return "KDC_ERR_NAME_EXP"
	case KDCErrServiceExp:
		return "KDC_ERR_SERVICE_EXP"
	case KDCErrGeneric:
		return "KDC_ERR_GENERIC"
	case KDCErrPreauthFailed:
		return "KDC_ERR_PREAUTH_FAILED"
	case KDCErrPreauthRequired:
		return "KDC_ERR_PREAUTH_REQUIRED"
	case KDCErrServerNotFound:
		return "KDC_ERR_S_PRINCIPAL_UNKNOWN"
	default:
		return fmt.Sprintf("error(%d)", code)
	}
}

// ---- Build / Parse ----

// BuildKerberosMsg builds a Kerberos message from a struct.
// The message type determines the application tag used.
func BuildKerberosMsg(msg *KerberosMsg) []byte {
	tag := msgTypeToTag(msg.MsgType)
	inner := buildKerberosInner(msg)
	return asn1.BERTLV(tag, inner)
}

// ParseKerberosMsg parses a raw Kerberos message.
func ParseKerberosMsg(data []byte) (*KerberosMsg, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("kerberos: empty input")
	}

	tag, value, _, err := asn1.BERDecodeTLV(data)
	if err != nil {
		return nil, fmt.Errorf("kerberos: parse outer: %w", err)
	}

	msg := &KerberosMsg{
		MsgType: tagToMsgType(tag),
		Raw:     data,
	}

	// Parse common fields from the inner SEQUENCE content.
	pos := 0

	// pvno INTEGER
	if pos < len(value) {
		fTag, fVal, fConsumed, err := asn1.BERDecodeTLV(value[pos:])
		if err == nil && fTag == asn1.TagInteger {
			msg.PVNO, _ = asn1.BERDecodeInteger(fVal)
			pos += fConsumed
		}
	}

	// msg-type INTEGER
	if pos < len(value) {
		fTag, fVal, fConsumed, err := asn1.BERDecodeTLV(value[pos:])
		if err == nil && fTag == asn1.TagInteger {
			mt, _ := asn1.BERDecodeInteger(fVal)
			if mt != 0 {
				msg.MsgType = mt
			}
			pos += fConsumed
		}
	}

	// Try to extract realm and principal names by scanning the remaining TLVs.
	// This is a best-effort parse — full ASN.1 schema parsing would require
	// code generation. We look for known patterns:
	//   - Realm: OCTET STRING after msg-type
	//   - PrincipalName: SEQUENCE { INTEGER, SEQUENCE OF OCTET STRING }
	scanKerberosFields(value[pos:], msg)

	return msg, nil
}

// scanKerberosFields does a best-effort extraction of realm and principal names
// from the remaining BER content.
func scanKerberosFields(data []byte, msg *KerberosMsg) {
	pos := 0
	principalCount := 0

	for pos < len(data) && principalCount < 2 {
		tag, val, consumed, err := asn1.BERDecodeTLV(data[pos:])
		if err != nil {
			break
		}
		pos += consumed

		// Realm is an OCTET STRING (GeneralString, tag 0x1B, or sometimes 0x04).
		if (tag == asn1.TagOctetString || tag == 0x1B) && msg.Realm == "" && len(val) > 0 {
			msg.Realm = string(val)
			continue
		}

		// PrincipalName: SEQUENCE { INTEGER (name-type), SEQUENCE OF OCTET STRING }
		if tag == asn1.TagSequence && len(val) > 0 {
			pn := parsePrincipalName(val)
			if pn != nil && len(pn.NameString) > 0 {
				if principalCount == 0 {
					msg.CName = *pn
				} else {
					msg.SName = *pn
				}
				principalCount++
			}
		}
	}
}

// parsePrincipalName parses a PrincipalName from BER content.
// Expects: INTEGER + SEQUENCE { OCTET STRING, ... }
func parsePrincipalName(data []byte) *PrincipalName {
	if len(data) == 0 {
		return nil
	}

	// Name type (INTEGER).
	tag, val, consumed, err := asn1.BERDecodeTLV(data)
	if err != nil || tag != asn1.TagInteger {
		return nil
	}
	nameType, _ := asn1.BERDecodeInteger(val)

	// Name strings (SEQUENCE OF OCTET STRING).
	if consumed >= len(data) {
		return nil
	}
	tag, val, _, err = asn1.BERDecodeTLV(data[consumed:])
	if err != nil || tag != asn1.TagSequence {
		return nil
	}

	var names []string
	pos := 0
	for pos < len(val) {
		sTag, sVal, sConsumed, err := asn1.BERDecodeTLV(val[pos:])
		if err != nil {
			break
		}
		if sTag == asn1.TagOctetString || sTag == 0x1B {
			names = append(names, string(sVal))
		}
		pos += sConsumed
	}

	if len(names) == 0 {
		return nil
	}

	return &PrincipalName{NameType: nameType, NameString: names}
}

// ---- AS-REQ / AS-REP convenience builders ----

// BuildASREQ builds a minimal AS-REQ message.
func BuildASREQ(realm string, cname, sname PrincipalName) []byte {
	// AS-REQ ::= [APPLICATION 10] SEQUENCE {
	//   pvno       INTEGER (5),
	//   msg-type   INTEGER (10),
	//   padata     [3] SEQUENCE OF PA-DATA OPTIONAL,
	//   req-body   [4] KDC-REQ-BODY }
	pvno := asn1.BEREncodeInteger(PVNO)
	msgType := asn1.BEREncodeInteger(MsgTypeASREQ)
	reqBody := buildKDCReqBody(realm, cname, sname)
	inner := append(pvno, msgType...)
	inner = append(inner, reqBody...)

	return asn1.BERTLV(TagASREQ, inner)
}

// BuildASREP builds a minimal AS-REP message.
func BuildASREP(realm string, cname PrincipalName) []byte {
	pvno := asn1.BEREncodeInteger(PVNO)
	msgType := asn1.BEREncodeInteger(MsgTypeASREP)
	inner := append(pvno, msgType...)
	// In a real AS-REP there would be crealm, cname, ticket, enc-part.
	// For building, we include what we can.
	inner = append(inner, buildGeneralString(realm)...)
	inner = append(inner, buildPrincipalName(cname)...)
	// Placeholder encrypted part.
	inner = append(inner, asn1.BERTLV(0x80, []byte{})...)

	return asn1.BERTLV(TagASREP, inner)
}

// ---- Internal helpers ----

func msgTypeToTag(msgType int) byte {
	switch msgType {
	case MsgTypeASREQ:
		return TagASREQ
	case MsgTypeASREP:
		return TagASREP
	case MsgTypeTGSREQ:
		return TagTGSREQ
	case MsgTypeTGSREP:
		return TagTGSREP
	case MsgTypeAPREQ:
		return TagAPREQ
	case MsgTypeAPREP:
		return TagAPREP
	default:
		return asn1.TagSequence
	}
}

func tagToMsgType(tag byte) int {
	switch tag {
	case TagASREQ:
		return MsgTypeASREQ
	case TagASREP:
		return MsgTypeASREP
	case TagTGSREQ:
		return MsgTypeTGSREQ
	case TagTGSREP:
		return MsgTypeTGSREP
	case TagAPREQ:
		return MsgTypeAPREQ
	case TagAPREP:
		return MsgTypeAPREP
	default:
		return 0
	}
}

func buildKerberosInner(msg *KerberosMsg) []byte {
	pvno := asn1.BEREncodeInteger(msg.PVNO)
	msgType := asn1.BEREncodeInteger(msg.MsgType)
	inner := append(pvno, msgType...)
	if msg.Realm != "" {
		inner = append(inner, buildGeneralString(msg.Realm)...)
	}
	if len(msg.SName.NameString) > 0 {
		inner = append(inner, buildPrincipalName(msg.SName)...)
	}
	return inner
}

func buildKDCReqBody(realm string, cname, sname PrincipalName) []byte {
	// KDC-REQ-BODY ::= [4] SEQUENCE { ... }
	var inner []byte
	inner = append(inner, buildPrincipalName(cname)...)
	inner = append(inner, buildGeneralString(realm)...)
	inner = append(inner, buildPrincipalName(sname)...)
	return asn1.BERTLV(0x84, inner) // [4] EXPLICIT
}

func buildPrincipalName(pn PrincipalName) []byte {
	// PrincipalName ::= SEQUENCE { name-type INTEGER, name-string SEQUENCE OF GeneralString }
	nameType := asn1.BEREncodeInteger(pn.NameType)
	var strs []byte
	for _, s := range pn.NameString {
		strs = append(strs, buildGeneralString(s)...)
	}
	inner := append(nameType, asn1.BERTLV(asn1.TagSequence, strs)...)
	return asn1.BERTLV(asn1.TagSequence, inner)
}

func buildGeneralString(s string) []byte {
	// GeneralString tag is 0x1B (tag class 0, constructed 0, tag number 27)
	return asn1.BERTLV(0x1B, []byte(s))
}

// ---- Layer ----

// NewKerberos creates a Kerberos layer with an empty payload.
func NewKerberos() *packet.Layer {
	return packet.NewLayer("Kerberos", []fields.Field{
		fields.NewStrField("payload", ""),
	})
}
