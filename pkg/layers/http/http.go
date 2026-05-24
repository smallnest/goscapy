// Package http provides HTTP/1.1 request and response layer definitions
// for parsing and crafting HTTP messages within network packets.
package http

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/smallnest/goscapy/pkg/fields"
	"github.com/smallnest/goscapy/pkg/packet"
)

// HTTP methods.
const (
	MethodGet     = "GET"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodDelete  = "DELETE"
	MethodHead    = "HEAD"
	MethodOptions = "OPTIONS"
	MethodPatch   = "PATCH"
	MethodConnect = "CONNECT"
	MethodTrace   = "TRACE"
)

// HTTPRequest represents a parsed HTTP request.
type HTTPRequest struct {
	Method  string
	Path    string
	Version string
	Headers map[string]string
	Body    []byte
}

// HTTPResponse represents a parsed HTTP response.
type HTTPResponse struct {
	Version      string
	StatusCode   int
	ReasonPhrase string
	Headers      map[string]string
	Body         []byte
}

// NewHTTPRequestLayer creates an HTTP layer initialized as a request.
func NewHTTPRequestLayer() *packet.Layer {
	return packet.NewLayer("HTTP", []fields.Field{
		fields.NewStrField("raw", ""),
	})
}

// NewHTTPResponseLayer creates an HTTP layer initialized as a response.
func NewHTTPResponseLayer() *packet.Layer {
	return packet.NewLayer("HTTP", []fields.Field{
		fields.NewStrField("raw", ""),
	})
}

// NewHTTP creates an HTTP layer (empty, caller sets raw or structured data).
func NewHTTP() *packet.Layer {
	return packet.NewLayer("HTTP", []fields.Field{
		fields.NewStrField("raw", ""),
	})
}

// BuildHTTPRequest constructs raw HTTP bytes from structured request data.
func BuildHTTPRequest(req HTTPRequest) []byte {
	if req.Version == "" {
		req.Version = "HTTP/1.1"
	}
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteString(" ")
	b.WriteString(req.Path)
	b.WriteString(" ")
	b.WriteString(req.Version)
	b.WriteString("\r\n")

	for k, v := range req.Headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}

	if len(req.Body) > 0 {
		if _, ok := req.Headers["Content-Length"]; !ok {
			b.WriteString("Content-Length: ")
			b.WriteString(strconv.Itoa(len(req.Body)))
			b.WriteString("\r\n")
		}
	}

	b.WriteString("\r\n")
	b.Write(req.Body)

	return []byte(b.String())
}

// BuildHTTPResponse constructs raw HTTP bytes from structured response data.
func BuildHTTPResponse(resp HTTPResponse) []byte {
	if resp.Version == "" {
		resp.Version = "HTTP/1.1"
	}
	if resp.ReasonPhrase == "" && resp.StatusCode > 0 {
		resp.ReasonPhrase = StatusText(resp.StatusCode)
	}

	var b strings.Builder
	b.WriteString(resp.Version)
	b.WriteString(" ")
	b.WriteString(strconv.Itoa(resp.StatusCode))
	b.WriteString(" ")
	b.WriteString(resp.ReasonPhrase)
	b.WriteString("\r\n")

	for k, v := range resp.Headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}

	if len(resp.Body) > 0 {
		if _, ok := resp.Headers["Content-Length"]; !ok {
			b.WriteString("Content-Length: ")
			b.WriteString(strconv.Itoa(len(resp.Body)))
			b.WriteString("\r\n")
		}
	}

	b.WriteString("\r\n")
	b.Write(resp.Body)

	return []byte(b.String())
}

// ParseHTTP parses raw HTTP bytes into either a request or response.
func ParseHTTP(data []byte) (req *HTTPRequest, resp *HTTPResponse, err error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("http: empty data")
	}

	s := string(data)

	// Find the first line.
	lineEnd := strings.Index(s, "\r\n")
	if lineEnd < 0 {
		lineEnd = strings.Index(s, "\n")
		if lineEnd < 0 {
			return nil, nil, fmt.Errorf("http: no line terminator found")
		}
	}
	firstLine := s[:lineEnd]

	if strings.HasPrefix(firstLine, "HTTP/") {
		resp, err = parseHTTPResponseFrom(s, lineEnd)
		return nil, resp, err
	}

	req, err = parseHTTPRequestFrom(s, lineEnd)
	return req, nil, err
}

func parseHTTPRequestFrom(s string, lineEnd int) (*HTTPRequest, error) {
	firstLine := s[:lineEnd]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("http: malformed request line: %q", firstLine)
	}

	req := &HTTPRequest{
		Method:  parts[0],
		Path:    parts[1],
		Version: "HTTP/1.1",
		Headers: make(map[string]string),
	}
	if len(parts) >= 3 {
		req.Version = parts[2]
	}

	headers, bodyStart := parseHeadersFromString(s, lineEnd)
	req.Headers = headers

	if bodyStart < len(s) {
		req.Body = []byte(s[bodyStart:])
	}

	return req, nil
}

func parseHTTPResponseFrom(s string, lineEnd int) (*HTTPResponse, error) {
	firstLine := s[:lineEnd]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("http: malformed status line: %q", firstLine)
	}

	resp := &HTTPResponse{
		Version:      parts[0],
		ReasonPhrase: "",
		Headers:      make(map[string]string),
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("http: invalid status code: %q", parts[1])
	}
	resp.StatusCode = code

	if len(parts) >= 3 {
		resp.ReasonPhrase = parts[2]
	}

	headers, bodyStart := parseHeadersFromString(s, lineEnd)
	resp.Headers = headers

	if bodyStart < len(s) {
		resp.Body = []byte(s[bodyStart:])
	}

	return resp, nil
}

// parseHeadersFromString parses headers starting after the first line.
// Returns headers map and the byte offset where the body starts.
func parseHeadersFromString(s string, afterFirstLine int) (map[string]string, int) {
	headers := make(map[string]string)
	pos := afterFirstLine

	// Skip past the \r\n of the first line.
	if pos < len(s) && s[pos] == '\r' {
		pos++
	}
	if pos < len(s) && s[pos] == '\n' {
		pos++
	}

	for pos < len(s) {
		// Find end of this header line.
		lineEnd := strings.Index(s[pos:], "\r\n")
		if lineEnd < 0 {
			lineEnd = strings.Index(s[pos:], "\n")
			if lineEnd < 0 {
				break
			}
			lineEnd += pos
			if s[lineEnd-1] == '\r' {
				lineEnd--
			}
		} else {
			lineEnd += pos
		}

		line := s[pos:lineEnd]

		// Empty line = end of headers.
		if line == "" {
			// Skip past the \r\n\r\n.
			pos = lineEnd
			if pos < len(s) && s[pos] == '\r' {
				pos++
			}
			if pos < len(s) && s[pos] == '\n' {
				pos++
			}
			break
		}

		// Folded header (starts with whitespace) — append to previous.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			pos = lineEnd
			if pos < len(s) && s[pos] == '\r' {
				pos++
			}
			if pos < len(s) && s[pos] == '\n' {
				pos++
			}
			continue
		}

		k, v, ok := strings.Cut(line, ":")
		if ok {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}

		// Advance past this line.
		pos = lineEnd
		if pos < len(s) && s[pos] == '\r' {
			pos++
		}
		if pos < len(s) && s[pos] == '\n' {
			pos++
		}
	}

	return headers, pos
}

// GetContentLength returns the Content-Length header value, or -1 if absent.
func GetContentLength(headers map[string]string) int {
	v, ok := headers["Content-Length"]
	if !ok {
		return -1
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}

// IsChunked returns true if Transfer-Encoding contains "chunked".
func IsChunked(headers map[string]string) bool {
	te, ok := headers["Transfer-Encoding"]
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(te), "chunked")
}

// StatusText returns the standard reason phrase for an HTTP status code.
func StatusText(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 206:
		return "Partial Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 307:
		return "Temporary Redirect"
	case 308:
		return "Permanent Redirect"
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
	case 408:
		return "Request Timeout"
	case 409:
		return "Conflict"
	case 410:
		return "Gone"
	case 413:
		return "Payload Too Large"
	case 415:
		return "Unsupported Media Type"
	case 418:
		return "I'm a Teapot"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return ""
	}
}

func init() {
	packet.RegisterLayer("HTTP", NewHTTP)
}
