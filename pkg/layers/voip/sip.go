package voip

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// SIP methods (RFC 3261).
const (
	SIPInvite    = "INVITE"
	SIPAck       = "ACK"
	SIPBye       = "BYE"
	SIPCancel    = "CANCEL"
	SIPRegister  = "REGISTER"
	SIPOptions   = "OPTIONS"
	SIPInfo      = "INFO"
	SIPRefer     = "REFER"
	SIPNotify    = "NOTIFY"
	SIPSubscribe = "SUBSCRIBE"
	SIPMethodMessage = "MESSAGE"
	SIPPrack     = "PRACK"
	SIPUpdate    = "UPDATE"
)

// SIPMessage represents a parsed SIP message.
type SIPMessage struct {
	Method      string // empty for responses
	RequestURI  string // empty for responses
	StatusCode  int    // 0 for requests
	Reason      string // empty for requests
	Version     string // e.g. "SIP/2.0"
	Headers     []SIPHeader
	Body        string
}

// SIPHeader is a single SIP header (name: value).
type SIPHeader struct {
	Name  string
	Value string
}

// NewSIP creates a SIP layer (raw text stored in a StrField).
func NewSIP() *packet.Layer {
	return packet.NewLayer("SIP", []fields.Field{
		fields.NewStrField("raw", ""),
	})
}

// ParseSIP parses a SIP message from raw bytes.
func ParseSIP(data []byte) (SIPMessage, error) {
	text := string(data)
	return ParseSIPString(text)
}

// ParseSIPString parses a SIP message from a string.
func ParseSIPString(text string) (SIPMessage, error) {
	msg := SIPMessage{}

	reader := strings.NewReader(text)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 4096), 65536)

	// First line: Request-Line or Status-Line.
	if !scanner.Scan() {
		return msg, fmt.Errorf("sip: empty message")
	}
	firstLine := strings.TrimRight(scanner.Text(), "\r")
	if err := parseFirstLine(firstLine, &msg); err != nil {
		return msg, err
	}

	// Headers.
	var headerLines []string
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
	}
	msg.Headers = parseHeaders(headerLines)

	// Body: everything after the blank line.
	rest := text
	if idx := strings.Index(rest, "\r\n\r\n"); idx >= 0 {
		msg.Body = rest[idx+4:]
	} else if idx := strings.Index(rest, "\n\n"); idx >= 0 {
		msg.Body = rest[idx+2:]
	}

	return msg, nil
}

// PackSIP serializes a SIP message to bytes.
func PackSIP(msg SIPMessage) []byte {
	return []byte(SerializeSIP(msg))
}

// SerializeSIP serializes a SIP message to a string.
func SerializeSIP(msg SIPMessage) string {
	var sb strings.Builder

	// Start line.
	if msg.Method != "" {
		// Request.
		uri := msg.RequestURI
		if uri == "" {
			uri = "sip:user@example.com"
		}
		sb.WriteString(fmt.Sprintf("%s %s %s\r\n", msg.Method, uri, msg.Version))
	} else {
		// Response.
		reason := msg.Reason
		if reason == "" {
			reason = statusText(msg.StatusCode)
		}
		sb.WriteString(fmt.Sprintf("%s %d %s\r\n", msg.Version, msg.StatusCode, reason))
	}

	// Headers.
	for _, h := range msg.Headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", h.Name, h.Value))
	}

	// Blank line + body.
	sb.WriteString("\r\n")
	sb.WriteString(msg.Body)

	return sb.String()
}

// SIP helpers.

func (m *SIPMessage) GetHeader(name string) string {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func (m *SIPMessage) IsRequest() bool {
	return m.Method != ""
}

func (m *SIPMessage) CallID() string {
	return m.GetHeader("Call-ID")
}

func (m *SIPMessage) From() string {
	return m.GetHeader("From")
}

func (m *SIPMessage) To() string {
	return m.GetHeader("To")
}

func (m *SIPMessage) CSeq() string {
	return m.GetHeader("CSeq")
}

func (m *SIPMessage) Via() string {
	return m.GetHeader("Via")
}

func (m *SIPMessage) Contact() string {
	return m.GetHeader("Contact")
}

func (m *SIPMessage) ContentType() string {
	return m.GetHeader("Content-Type")
}

func (m *SIPMessage) ContentLength() int {
	v := m.GetHeader("Content-Length")
	if v == "" {
		return 0
	}
	n, _ := strconv.Atoi(v)
	return n
}

func parseFirstLine(line string, msg *SIPMessage) error {
	if strings.HasPrefix(line, "SIP/") {
		// Status-Line: SIP/2.0 <code> <reason>
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return fmt.Errorf("sip: malformed status line: %q", line)
		}
		msg.Version = parts[0]
		code, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("sip: invalid status code: %q", parts[1])
		}
		msg.StatusCode = code
		if len(parts) == 3 {
			msg.Reason = parts[2]
		}
	} else {
		// Request-Line: METHOD URI SIP/2.0
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			return fmt.Errorf("sip: malformed request line: %q", line)
		}
		msg.Method = parts[0]
		msg.RequestURI = parts[1]
		msg.Version = parts[2]
	}
	return nil
}

func parseHeaders(lines []string) []SIPHeader {
	var headers []SIPHeader
	for _, line := range lines {
		// Handle line folding (obs-fold: continuation with leading whitespace).
		if len(headers) > 0 && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			headers[len(headers)-1].Value += " " + strings.TrimSpace(line)
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		headers = append(headers, SIPHeader{
			Name:  strings.TrimSpace(line[:idx]),
			Value: strings.TrimSpace(line[idx+1:]),
		})
	}
	return headers
}

func statusText(code int) string {
	switch code {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 181:
		return "Call Is Being Forwarded"
	case 182:
		return "Queued"
	case 183:
		return "Session Progress"
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 300:
		return "Multiple Choices"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Moved Temporarily"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 406:
		return "Not Acceptable"
	case 407:
		return "Proxy Authentication Required"
	case 408:
		return "Request Timeout"
	case 410:
		return "Gone"
	case 413:
		return "Request Entity Too Large"
	case 414:
		return "Request-URI Too Long"
	case 415:
		return "Unsupported Media Type"
	case 416:
		return "Unsupported URI Scheme"
	case 420:
		return "Bad Extension"
	case 421:
		return "Extension Required"
	case 423:
		return "Interval Too Brief"
	case 480:
		return "Temporarily Unavailable"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 482:
		return "Loop Detected"
	case 483:
		return "Too Many Hops"
	case 484:
		return "Address Incomplete"
	case 485:
		return "Ambiguous"
	case 486:
		return "Busy Here"
	case 487:
		return "Request Terminated"
	case 488:
		return "Not Acceptable Here"
	case 491:
		return "Request Pending"
	case 493:
		return "Undecipherable"
	case 500:
		return "Server Internal Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Server Time-out"
	case 505:
		return "Version Not Supported"
	case 513:
		return "Message Too Large"
	case 600:
		return "Busy Everywhere"
	case 603:
		return "Decline"
	case 604:
		return "Does Not Exist Anywhere"
	case 606:
		return "Not Acceptable"
	default:
		return ""
	}
}
