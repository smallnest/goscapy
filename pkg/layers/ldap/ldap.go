// Package ldap provides LDAP (Lightweight Directory Access Protocol) layer
// implementation per RFC 4511. LDAP messages use BER encoding.
package ldap

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/asn1"
	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// LDAP protocol operation tags (RFC 4511 Section 4.1.1).
// These are context-specific constructed tags.
const (
	TagBindRequest       byte = 0x60
	TagBindResponse      byte = 0x61
	TagUnbindRequest     byte = 0x42
	TagSearchRequest     byte = 0x63
	TagSearchResultEntry byte = 0x64
	TagSearchResultDone  byte = 0x65
	TagSearchResultRef   byte = 0x73
	TagModifyRequest     byte = 0x66
	TagModifyResponse    byte = 0x67
	TagAddRequest        byte = 0x68
	TagAddResponse       byte = 0x69
	TagDelRequest        byte = 0x4A
	TagDelResponse       byte = 0x6B
	TagModifyDNRequest   byte = 0x6C
	TagModifyDNResponse  byte = 0x6D
	TagCompareRequest    byte = 0x6E
	TagCompareResponse   byte = 0x6F
	TagAbandonRequest    byte = 0x50
	TagExtendedRequest   byte = 0x77
	TagExtendedResponse  byte = 0x78
	TagIntermediateResponse byte = 0x79
)

// LDAP result codes (RFC 4511 Section 4.1.9).
const (
	ResultSuccess                  = 0
	ResultOperationsError          = 1
	ResultProtocolError            = 2
	ResultTimeLimitExceeded        = 3
	ResultSizeLimitExceeded        = 4
	ResultCompareFalse             = 5
	ResultCompareTrue              = 6
	ResultAuthMethodNotSupported   = 7
	ResultStrongerAuthRequired     = 8
	ResultReferral                 = 10
	ResultAdminLimitExceeded       = 11
	ResultUnavailableCriticalExtension = 12
	ResultConfidentialityRequired  = 13
	ResultSaslBindInProgress       = 14
	ResultNoSuchObject             = 32
	ResultAliasProblem             = 33
	ResultInvalidDNSyntax          = 34
	ResultAliasDereferencingProblem = 36
	ResultInappropriateAuthentication = 48
	ResultInvalidCredentials       = 49
	ResultInsufficientAccessRights = 50
	ResultBusy                     = 51
	ResultUnavailable              = 52
	ResultUnwillingToPerform       = 53
	ResultLoopDetect               = 54
	ResultNamingViolation          = 64
	ResultObjectClassViolation     = 65
	ResultNotAllowedOnNonLeaf      = 66
	ResultNotAllowedOnRDN          = 67
	ResultEntryAlreadyExists       = 68
	ResultObjectClassModsProhibited = 69
	ResultAffectsMultipleDSAs      = 71
	ResultOther                    = 80
)

// Search scope values (RFC 4511 Section 4.5.1).
const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
)

// Deref aliases values (RFC 4511 Section 4.5.1).
const (
	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3
)

// LDAPMessage represents a parsed LDAP message (RFC 4511 Section 4.1.1).
type LDAPMessage struct {
	MessageID  int
	ProtocolOp LDAPOp
	Controls   []byte // Raw BER-encoded controls, if present
}

// LDAPOp represents a protocol operation within an LDAP message.
type LDAPOp struct {
	Tag   byte   // BER tag identifying the operation type
	Value []byte // Raw BER-encoded operation content
}

// OpName returns the human-readable name for an LDAP operation tag.
func OpName(tag byte) string {
	switch tag {
	case TagBindRequest:
		return "BindRequest"
	case TagBindResponse:
		return "BindResponse"
	case TagUnbindRequest:
		return "UnbindRequest"
	case TagSearchRequest:
		return "SearchRequest"
	case TagSearchResultEntry:
		return "SearchResultEntry"
	case TagSearchResultDone:
		return "SearchResultDone"
	case TagSearchResultRef:
		return "SearchResultReference"
	case TagModifyRequest:
		return "ModifyRequest"
	case TagModifyResponse:
		return "ModifyResponse"
	case TagAddRequest:
		return "AddRequest"
	case TagAddResponse:
		return "AddResponse"
	case TagDelRequest:
		return "DelRequest"
	case TagDelResponse:
		return "DelResponse"
	case TagModifyDNRequest:
		return "ModifyDNRequest"
	case TagModifyDNResponse:
		return "ModifyDNResponse"
	case TagCompareRequest:
		return "CompareRequest"
	case TagCompareResponse:
		return "CompareResponse"
	case TagAbandonRequest:
		return "AbandonRequest"
	case TagExtendedRequest:
		return "ExtendedRequest"
	case TagExtendedResponse:
		return "ExtendedResponse"
	case TagIntermediateResponse:
		return "IntermediateResponse"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", tag)
	}
}

// ResultName returns the human-readable name for an LDAP result code.
func ResultName(code int) string {
	switch code {
	case ResultSuccess:
		return "success"
	case ResultOperationsError:
		return "operationsError"
	case ResultProtocolError:
		return "protocolError"
	case ResultInvalidCredentials:
		return "invalidCredentials"
	case ResultNoSuchObject:
		return "noSuchObject"
	case ResultInsufficientAccessRights:
		return "insufficientAccessRights"
	case ResultBusy:
		return "busy"
	case ResultUnavailable:
		return "unavailable"
	case ResultUnwillingToPerform:
		return "unwillingToPerform"
	case ResultOther:
		return "other"
	default:
		return fmt.Sprintf("code(%d)", code)
	}
}

// ---- Build / Parse ----

// BuildLDAPMessage builds a complete LDAP BER-encoded message.
func BuildLDAPMessage(msg *LDAPMessage) []byte {
	inner := asn1.BEREncodeInteger(msg.MessageID)
	inner = append(inner, msg.ProtocolOp.Value...)
	if len(msg.Controls) > 0 {
		inner = append(inner, msg.Controls...)
	}
	return asn1.BERTLV(asn1.TagSequence, inner)
}

// ParseLDAPMessage parses a raw LDAP message.
func ParseLDAPMessage(data []byte) (*LDAPMessage, error) {
	tag, value, _, err := asn1.BERDecodeTLV(data)
	if err != nil {
		return nil, fmt.Errorf("ldap: parse outer: %w", err)
	}
	if tag != asn1.TagSequence {
		return nil, fmt.Errorf("ldap: expected SEQUENCE, got 0x%02x", tag)
	}

	pos := 0

	// MessageID.
	idTag, idVal, idConsumed, err := asn1.BERDecodeTLV(value[pos:])
	if err != nil {
		return nil, fmt.Errorf("ldap: parse messageID: %w", err)
	}
	if idTag != asn1.TagInteger {
		return nil, fmt.Errorf("ldap: messageID tag = 0x%02x", idTag)
	}
	msgID, _ := asn1.BERDecodeInteger(idVal)
	pos += idConsumed

	// ProtocolOp — next TLV.
	opTag, _, opConsumed, err := asn1.BERDecodeTLV(value[pos:])
	if err != nil {
		return nil, fmt.Errorf("ldap: parse protocolOp: %w", err)
	}

	msg := &LDAPMessage{
		MessageID: msgID,
		ProtocolOp: LDAPOp{
			Tag:   opTag,
			Value: append([]byte(nil), value[pos:pos+opConsumed]...),
		},
	}

	pos += opConsumed

	// Controls (optional, context-specific tag 0).
	if pos < len(value) {
		msg.Controls = append([]byte(nil), value[pos:]...)
	}

	return msg, nil
}

// ---- Convenience builders ----

// BuildBindRequest builds a simple BindRequest.
// authentication: 0 = simple (password), 3 = SASL.
func BuildBindRequest(msgID int, name, password string) []byte {
	// BindRequest ::= [APPLICATION 0] SEQUENCE {
	//   version      INTEGER (3),
	//   name         LDAPDN,
	//   authentication AuthenticationChoice }
	version := asn1.BEREncodeInteger(3)
	dn := asn1.BEREncodeOctetString([]byte(name))
	// Simple authentication: [0] OCTET STRING (context-specific, tag 0x80)
	auth := asn1.BERTLV(0x80, []byte(password))

	inner := append(version, dn...)
	inner = append(inner, auth...)

	return BuildLDAPMessage(&LDAPMessage{
		MessageID:  msgID,
		ProtocolOp: LDAPOp{Tag: TagBindRequest, Value: asn1.BERTLV(TagBindRequest, inner)},
	})
}

// BuildBindResponse builds a BindResponse with the given result code.
func BuildBindResponse(msgID int, resultCode int, matchedDN, diagnostic string) []byte {
	// BindResponse ::= [APPLICATION 1] SEQUENCE {
	//   COMPONENTS OF LDAPResult }
	result := buildLDAPResult(resultCode, matchedDN, diagnostic)
	return BuildLDAPMessage(&LDAPMessage{
		MessageID:  msgID,
		ProtocolOp: LDAPOp{Tag: TagBindResponse, Value: asn1.BERTLV(TagBindResponse, result)},
	})
}

// BuildSearchRequest builds a SearchRequest.
func BuildSearchRequest(msgID int, baseDN string, scope, derefAliases, sizeLimit, timeLimit int, typesOnly bool, filter []byte, attributes []string) []byte {
	// SearchRequest ::= [APPLICATION 3] SEQUENCE {
	//   baseObject      LDAPDN,
	//   scope           ENUMERATED,
	//   derefAliases    ENUMERATED,
	//   sizeLimit       INTEGER,
	//   timeLimit       INTEGER,
	//   typesOnly       BOOLEAN,
	//   filter          Filter,
	//   attributes      AttributeDescriptionList }
	base := asn1.BEREncodeOctetString([]byte(baseDN))
	sc := asn1.BEREncodeEnumerated(scope)
	deref := asn1.BEREncodeEnumerated(derefAliases)
	sLimit := asn1.BEREncodeInteger(sizeLimit)
	tLimit := asn1.BEREncodeInteger(timeLimit)
	types := asn1.BEREncodeBoolean(typesOnly)

	inner := append(base, sc...)
	inner = append(inner, deref...)
	inner = append(inner, sLimit...)
	inner = append(inner, tLimit...)
	inner = append(inner, types...)

	if filter != nil {
		inner = append(inner, filter...)
	} else {
		// Default: present filter "(objectClass=*)"
		inner = append(inner, asn1.BERTLV(0x87, []byte("objectClass"))...)
	}

	// Attributes list.
	var attrs []byte
	for _, a := range attributes {
		attrs = append(attrs, asn1.BEREncodeOctetString([]byte(a))...)
	}
	inner = append(inner, asn1.BERTLV(asn1.TagSequence, attrs)...)

	return BuildLDAPMessage(&LDAPMessage{
		MessageID:  msgID,
		ProtocolOp: LDAPOp{Tag: TagSearchRequest, Value: asn1.BERTLV(TagSearchRequest, inner)},
	})
}

// BuildSearchResultEntry builds a search result entry.
func BuildSearchResultEntry(msgID int, objectName string, attributes []byte) []byte {
	name := asn1.BEREncodeOctetString([]byte(objectName))
	inner := append(name, attributes...)
	return BuildLDAPMessage(&LDAPMessage{
		MessageID:  msgID,
		ProtocolOp: LDAPOp{Tag: TagSearchResultEntry, Value: asn1.BERTLV(TagSearchResultEntry, inner)},
	})
}

// BuildSearchResultDone builds a search result done message.
func BuildSearchResultDone(msgID int, resultCode int, matchedDN, diagnostic string) []byte {
	result := buildLDAPResult(resultCode, matchedDN, diagnostic)
	return BuildLDAPMessage(&LDAPMessage{
		MessageID:  msgID,
		ProtocolOp: LDAPOp{Tag: TagSearchResultDone, Value: asn1.BERTLV(TagSearchResultDone, result)},
	})
}

// buildLDAPResult encodes an LDAPResult SEQUENCE.
func buildLDAPResult(resultCode int, matchedDN, diagnostic string) []byte {
	code := asn1.BEREncodeEnumerated(resultCode)
	dn := asn1.BEREncodeOctetString([]byte(matchedDN))
	msg := asn1.BEREncodeOctetString([]byte(diagnostic))
	inner := append(code, dn...)
	inner = append(inner, msg...)
	return inner
}

// ParseLDAPResult parses an LDAPResult from the value bytes of a response operation.
// The value should be the content bytes of the operation's SEQUENCE.
func ParseLDAPResult(data []byte) (resultCode int, matchedDN string, diagnostic string, err error) {
	pos := 0

	// Result code.
	tag, val, consumed, decodeErr := asn1.BERDecodeTLV(data[pos:])
	if decodeErr != nil {
		err = fmt.Errorf("ldap: parse result code: %w", decodeErr)
		return
	}
	if tag != asn1.TagEnumerated {
		err = fmt.Errorf("ldap: result code tag = 0x%02x", tag)
		return
	}
	resultCode, _ = asn1.BERDecodeEnumerated(val)
	pos += consumed

	// Matched DN.
	tag, val, consumed, decodeErr = asn1.BERDecodeTLV(data[pos:])
	if decodeErr != nil {
		err = fmt.Errorf("ldap: parse matchedDN: %w", decodeErr)
		return
	}
	if tag != asn1.TagOctetString {
		err = fmt.Errorf("ldap: matchedDN tag = 0x%02x", tag)
		return
	}
	matchedDN = string(val)
	pos += consumed

	// Diagnostic message.
	tag, val, _, decodeErr = asn1.BERDecodeTLV(data[pos:])
	if decodeErr != nil {
		err = fmt.Errorf("ldap: parse diagnostic: %w", decodeErr)
		return
	}
	if tag != asn1.TagOctetString {
		err = fmt.Errorf("ldap: diagnostic tag = 0x%02x", tag)
		return
	}
	diagnostic = string(val)

	return resultCode, matchedDN, diagnostic, nil
}

// ---- Layer ----

// NewLDAP creates an LDAP layer with an empty payload.
func NewLDAP() *packet.Layer {
	return packet.NewLayer("LDAP", []fields.Field{
		fields.NewStrField("payload", ""),
	})
}
