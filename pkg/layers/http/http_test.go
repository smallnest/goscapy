package http

import (
	"strings"
	"testing"
)

func TestBuildRequest(t *testing.T) {
	raw := BuildHTTPRequest(HTTPRequest{
		Method: MethodGet,
		Path:   "/index.html",
		Headers: map[string]string{
			"Host": "example.com",
		},
	})

	s := string(raw)
	if !strings.HasPrefix(s, "GET /index.html HTTP/1.1\r\n") {
		t.Errorf("Request line wrong: %q", s[:40])
	}
	if !strings.Contains(s, "Host: example.com\r\n") {
		t.Errorf("Missing Host header")
	}
	if !strings.HasSuffix(s, "\r\n\r\n") {
		t.Errorf("Missing terminal CRLF CRLF")
	}
}

func TestBuildRequestWithBody(t *testing.T) {
	body := []byte("hello=world")
	raw := BuildHTTPRequest(HTTPRequest{
		Method: MethodPost,
		Path:   "/submit",
		Headers: map[string]string{
			"Host": "example.com",
		},
		Body: body,
	})

	s := string(raw)
	if !strings.HasPrefix(s, "POST /submit HTTP/1.1") {
		t.Errorf("Request line wrong")
	}
	if !strings.Contains(s, "Content-Length: 11") {
		t.Errorf("Missing Content-Length")
	}
	if !strings.HasSuffix(s, "hello=world") {
		t.Errorf("Missing body")
	}
}

func TestBuildResponse(t *testing.T) {
	body := []byte("<html>OK</html>")
	raw := BuildHTTPResponse(HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "text/html",
		},
		Body: body,
	})

	s := string(raw)
	if !strings.HasPrefix(s, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("Status line wrong: %q", s[:30])
	}
	if !strings.Contains(s, "Content-Type: text/html") {
		t.Errorf("Missing Content-Type")
	}
	if !strings.Contains(s, "Content-Length: 15") {
		t.Errorf("Missing Content-Length")
	}
	if !strings.HasSuffix(s, "<html>OK</html>") {
		t.Errorf("Missing body")
	}
}

func TestParseRequest(t *testing.T) {
	raw := "GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
	req, resp, err := ParseHTTP([]byte(raw))
	if err != nil {
		t.Fatalf("ParseHTTP error: %v", err)
	}
	if resp != nil {
		t.Fatal("Expected nil response")
	}
	if req == nil {
		t.Fatal("Expected non-nil request")
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q", req.Method)
	}
	if req.Path != "/path" {
		t.Errorf("Path = %q", req.Path)
	}
	if req.Version != "HTTP/1.1" {
		t.Errorf("Version = %q", req.Version)
	}
	if req.Headers["Host"] != "example.com" {
		t.Errorf("Host = %q", req.Headers["Host"])
	}
	if req.Headers["User-Agent"] != "test" {
		t.Errorf("User-Agent = %q", req.Headers["User-Agent"])
	}
}

func TestParseResponse(t *testing.T) {
	raw := "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nnot found"
	req, resp, err := ParseHTTP([]byte(raw))
	if err != nil {
		t.Fatalf("ParseHTTP error: %v", err)
	}
	if req != nil {
		t.Fatal("Expected nil request")
	}
	if resp == nil {
		t.Fatal("Expected non-nil response")
	}
	if resp.StatusCode != 404 {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
	if resp.ReasonPhrase != "Not Found" {
		t.Errorf("ReasonPhrase = %q", resp.ReasonPhrase)
	}
	if string(resp.Body) != "not found" {
		t.Errorf("Body = %q", string(resp.Body))
	}
}

func TestParseRequestWithBody(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello=world"
	req, _, err := ParseHTTP([]byte(raw))
	if err != nil {
		t.Fatalf("ParseHTTP error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q", req.Method)
	}
	if string(req.Body) != "hello=world" {
		t.Errorf("Body = %q", string(req.Body))
	}
}

func TestBuildAndParseRoundTrip(t *testing.T) {
	original := HTTPRequest{
		Method: MethodPost,
		Path:   "/submit",
		Headers: map[string]string{
			"Host":       "example.com",
			"User-Agent": "goscapy-test",
		},
		Body: []byte("key=value"),
	}

	raw := BuildHTTPRequest(original)
	req, _, err := ParseHTTP(raw)
	if err != nil {
		t.Fatalf("Round-trip parse error: %v", err)
	}

	if req.Method != original.Method {
		t.Errorf("Method: got %q, want %q", req.Method, original.Method)
	}
	if req.Path != original.Path {
		t.Errorf("Path: got %q, want %q", req.Path, original.Path)
	}
	if string(req.Body) != string(original.Body) {
		t.Errorf("Body: got %q, want %q", string(req.Body), string(original.Body))
	}
}

func TestGetContentLength(t *testing.T) {
	headers := map[string]string{"Content-Length": "42"}
	if n := GetContentLength(headers); n != 42 {
		t.Errorf("GetContentLength = %d, want 42", n)
	}
	headers = map[string]string{}
	if n := GetContentLength(headers); n != -1 {
		t.Errorf("GetContentLength = %d, want -1", n)
	}
}

func TestIsChunked(t *testing.T) {
	if IsChunked(map[string]string{"Transfer-Encoding": "chunked"}) != true {
		t.Error("Expected chunked")
	}
	if IsChunked(map[string]string{}) != false {
		t.Error("Expected not chunked")
	}
	if IsChunked(map[string]string{"Transfer-Encoding": "gzip"}) != false {
		t.Error("Expected not chunked for gzip")
	}
}

func TestStatusText(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{200, "OK"},
		{404, "Not Found"},
		{500, "Internal Server Error"},
		{301, "Moved Permanently"},
		{0, ""},
	}
	for _, tt := range tests {
		if got := StatusText(tt.code); got != tt.want {
			t.Errorf("StatusText(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestParseEmptyData(t *testing.T) {
	_, _, err := ParseHTTP([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

func TestBuildResponseWithCustomReason(t *testing.T) {
	raw := BuildHTTPResponse(HTTPResponse{
		StatusCode:   418,
		ReasonPhrase: "I'm a Teapot",
		Headers:      map[string]string{},
	})
	if !strings.HasPrefix(string(raw), "HTTP/1.1 418 I'm a Teapot") {
		t.Errorf("Wrong status line: %q", string(raw[:30]))
	}
}

func TestContentLengthAutoSet(t *testing.T) {
	// Without explicit Content-Length, it should be auto-added.
	raw := BuildHTTPRequest(HTTPRequest{
		Method:  MethodPost,
		Path:    "/",
		Headers: map[string]string{"Host": "test"},
		Body:    []byte("abc"),
	})
	if !strings.Contains(string(raw), "Content-Length: 3") {
		t.Error("Content-Length not auto-set")
	}

	// With explicit Content-Length, should not override.
	raw = BuildHTTPRequest(HTTPRequest{
		Method: MethodPost,
		Path:   "/",
		Headers: map[string]string{
			"Host":           "test",
			"Content-Length": "999",
		},
		Body: []byte("abc"),
	})
	if !strings.Contains(string(raw), "Content-Length: 999") {
		t.Error("Explicit Content-Length was overridden")
	}
}
