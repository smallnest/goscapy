package p0f

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Signature represents a single p0f signature entry.
type Signature struct {
	Window    uint16 // TCP window size (0 = wildcard)
	TTLMin    uint8  // Minimum TTL (for range matching)
	TTLMax    uint8  // Maximum TTL
	OptsLen   int    // TCP options length (-1 = wildcard)
	MSS       uint16 // MSS value (0 = wildcard unless MSSWild)
	MSSWild   bool   // MSS wildcard (just check presence)
	WScale    int    // Window scale value (-1 = wildcard, -2 = absent)
	WScaleWild bool  // WScale wildcard (just check presence)
	SACK      int    // SACK permitted (-1 = wildcard, 0 = no, 1 = yes)
	NOP       int    // NOP present (-1 = wildcard, 0 = no, 1 = yes)
	DF        int    // Don't Fragment (-1 = wildcard, 0 = no, 1 = yes)
	Label     string // OS identification label
}

// fieldCount returns the number of non-wildcard fields for scoring.
func (s *Signature) fieldCount() int {
	n := 0
	if s.Window != 0 {
		n++
	}
	if s.TTLMin != 0 || s.TTLMax != 0 {
		n++
	}
	if s.OptsLen >= 0 {
		n++
	}
	if s.MSSWild || s.MSS != 0 {
		n++
	}
	if s.WScaleWild || s.WScale >= 0 {
		n++
	}
	if s.SACK >= 0 {
		n++
	}
	if s.NOP >= 0 {
		n++
	}
	if s.DF >= 0 {
		n++
	}
	return n
}

// Database holds the loaded p0f signature database.
type Database struct {
	Syn    []Signature // SYN mode signatures
	SynAck []Signature // SYN+ACK mode signatures
	Rst    []Signature // RST mode signatures (reserved)
}

// LoadDatabase reads a p0f-format signature file.
// The file format follows the p0f v2 convention:
//
//	[section]
//	signature::label
//
// SYN signature format: window:ttl:opts_len:mss:wscale:sack:nop:df::label
// Fields can be * for wildcard. TTL can be a range like 32-64.
func LoadDatabase(path string) (*Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("p0f: load: %w", err)
	}
	defer f.Close()

	db := &Database{}
	scanner := bufio.NewScanner(f)
	var section string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section header.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}

		sig, err := parseSignatureLine(line)
		if err != nil {
			continue // skip malformed lines
		}

		switch section {
		case "syn":
			db.Syn = append(db.Syn, sig)
		case "syn+ack":
			db.SynAck = append(db.SynAck, sig)
		case "rst":
			db.Rst = append(db.Rst, sig)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("p0f: load: %w", err)
	}

	return db, nil
}

// parseSignatureLine parses "window:ttl:opts_len:mss:wscale:sack:nop:df::label".
func parseSignatureLine(line string) (Signature, error) {
	parts := strings.SplitN(line, "::", 2)
	if len(parts) != 2 {
		return Signature{}, fmt.Errorf("p0f: missing :: separator in %q", line)
	}

	sig := Signature{
		OptsLen: -1,
		WScale:  -1,
		SACK:    -1,
		NOP:     -1,
		DF:      -1,
	}

	fields := strings.Split(parts[0], ":")
	if len(fields) < 8 {
		return Signature{}, fmt.Errorf("p0f: need 8 fields, got %d in %q", len(fields), line)
	}

	// Window size.
	if fields[0] != "*" {
		v, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return Signature{}, fmt.Errorf("p0f: invalid window %q", fields[0])
		}
		sig.Window = uint16(v)
	}

	// TTL (can be a single value or range like 32-64).
	if fields[1] != "*" {
		if dash := strings.Index(fields[1], "-"); dash >= 0 {
			lo, err1 := strconv.ParseUint(fields[1][:dash], 10, 8)
			hi, err2 := strconv.ParseUint(fields[1][dash+1:], 10, 8)
			if err1 != nil || err2 != nil {
				return Signature{}, fmt.Errorf("p0f: invalid ttl range %q", fields[1])
			}
			sig.TTLMin = uint8(lo)
			sig.TTLMax = uint8(hi)
		} else {
			v, err := strconv.ParseUint(fields[1], 10, 8)
			if err != nil {
				return Signature{}, fmt.Errorf("p0f: invalid ttl %q", fields[1])
			}
			sig.TTLMin = uint8(v)
			sig.TTLMax = uint8(v)
		}
	}

	// Options length.
	if fields[2] != "*" {
		v, err := strconv.Atoi(fields[2])
		if err != nil {
			return Signature{}, fmt.Errorf("p0f: invalid opts_len %q", fields[2])
		}
		sig.OptsLen = v
	}

	// MSS.
	if fields[3] == "*" {
		sig.MSSWild = true
	} else if fields[3] != "" {
		v, err := strconv.ParseUint(fields[3], 10, 16)
		if err != nil {
			return Signature{}, fmt.Errorf("p0f: invalid mss %q", fields[3])
		}
		sig.MSS = uint16(v)
	}

	// Window scale.
	if fields[4] == "*" {
		sig.WScaleWild = true
	} else if fields[4] != "" {
		v, err := strconv.Atoi(fields[4])
		if err != nil {
			return Signature{}, fmt.Errorf("p0f: invalid wscale %q", fields[4])
		}
		sig.WScale = v
	}

	// SACK.
	if fields[5] != "*" && fields[5] != "" {
		v, err := strconv.Atoi(fields[5])
		if err != nil {
			return Signature{}, fmt.Errorf("p0f: invalid sack %q", fields[5])
		}
		sig.SACK = v
	}

	// NOP.
	if fields[6] != "*" && fields[6] != "" {
		v, err := strconv.Atoi(fields[6])
		if err != nil {
			return Signature{}, fmt.Errorf("p0f: invalid nop %q", fields[6])
		}
		sig.NOP = v
	}

	// DF.
	if fields[7] != "*" && fields[7] != "" {
		v, err := strconv.Atoi(fields[7])
		if err != nil {
			return Signature{}, fmt.Errorf("p0f: invalid df %q", fields[7])
		}
		sig.DF = v
	}

	sig.Label = strings.TrimSpace(parts[1])
	return sig, nil
}

// DefaultDatabase returns a built-in signature database with common OS fingerprints.
// This is useful when no external p0f.fp file is available.
func DefaultDatabase() *Database {
	return &Database{
		Syn: []Signature{
			// Linux
			{Window: 5840, TTLMin: 64, TTLMax: 64, OptsLen: 1, MSSWild: true, MSS: 1460, WScale: -1, SACK: 0, NOP: 0, DF: 1, Label: "Linux 2.4"},
			{Window: 5840, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 4, SACK: 1, NOP: 1, DF: 1, Label: "Linux 2.6"},
			{Window: 14600, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 6, SACK: 1, NOP: 1, DF: 1, Label: "Linux 3.x"},
			{Window: 29200, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 7, SACK: 1, NOP: 1, DF: 1, Label: "Linux 4.x-6.x"},
			{Window: 64240, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 7, SACK: 1, NOP: 1, DF: 1, Label: "Linux 5.x-6.x (high window)"},
			// Windows
			{Window: 8192, TTLMin: 128, TTLMax: 128, OptsLen: 1, MSS: 1460, WScale: -1, SACK: 0, NOP: 0, DF: 1, Label: "Windows XP"},
			{Window: 8192, TTLMin: 128, TTLMax: 128, OptsLen: 12, MSS: 1460, WScale: 8, SACK: 1, NOP: 1, DF: 1, Label: "Windows 7"},
			{Window: 8192, TTLMin: 128, TTLMax: 128, OptsLen: 20, MSS: 1460, WScale: 8, SACK: 1, NOP: 1, DF: 1, Label: "Windows 8/10"},
			{Window: 65535, TTLMin: 128, TTLMax: 128, OptsLen: 20, MSS: 1460, WScale: 8, SACK: 1, NOP: 1, DF: 1, Label: "Windows 10/11 (high window)"},
			// macOS / iOS
			{Window: 65535, TTLMin: 64, TTLMax: 64, OptsLen: 20, MSS: 1460, WScale: 5, SACK: 1, NOP: 1, DF: 1, Label: "macOS / iOS"},
			{Window: 65535, TTLMin: 64, TTLMax: 64, OptsLen: 20, MSS: 1440, WScale: 5, SACK: 1, NOP: 1, DF: 1, Label: "iOS (MSS 1440)"},
			// FreeBSD / OpenBSD
			{Window: 65535, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 6, SACK: 1, NOP: 1, DF: 1, Label: "FreeBSD 9.x+"},
			{Window: 16384, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 6, SACK: 1, NOP: 1, DF: 1, Label: "OpenBSD"},
			// Solaris
			{Window: 33360, TTLMin: 64, TTLMax: 64, OptsLen: 8, MSS: 1460, WScale: -1, SACK: 1, NOP: 1, DF: 1, Label: "Solaris 10"},
			// Network devices
			{Window: 4128, TTLMin: 64, TTLMax: 64, OptsLen: 1, MSSWild: true, WScale: -1, SACK: 0, NOP: 0, DF: 0, Label: "Network device / embedded"},
			{Window: 16384, TTLMin: 64, TTLMax: 64, OptsLen: 0, MSSWild: true, WScale: -1, SACK: -1, NOP: 0, DF: 0, Label: "Network device (simple)"},
			// Generic
			{Window: 0, TTLMin: 32, TTLMax: 64, OptsLen: -1, MSSWild: true, WScale: -1, SACK: -1, NOP: -1, DF: -1, Label: "Generic *nix (low TTL)"},
			{Window: 0, TTLMin: 100, TTLMax: 128, OptsLen: -1, MSSWild: true, WScale: -1, SACK: -1, NOP: -1, DF: -1, Label: "Generic Windows (high TTL)"},
		},
		SynAck: []Signature{
			{Window: 5840, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 4, SACK: 1, NOP: 1, DF: 1, Label: "Linux 2.6"},
			{Window: 29200, TTLMin: 64, TTLMax: 64, OptsLen: 12, MSS: 1460, WScale: 7, SACK: 1, NOP: 1, DF: 1, Label: "Linux 4.x-6.x"},
			{Window: 8192, TTLMin: 128, TTLMax: 128, OptsLen: 20, MSS: 1460, WScale: 8, SACK: 1, NOP: 1, DF: 1, Label: "Windows 8/10"},
			{Window: 65535, TTLMin: 128, TTLMax: 128, OptsLen: 20, MSS: 1460, WScale: 8, SACK: 1, NOP: 1, DF: 1, Label: "Windows 10/11"},
			{Window: 65535, TTLMin: 64, TTLMax: 64, OptsLen: 20, MSS: 1460, WScale: 5, SACK: 1, NOP: 1, DF: 1, Label: "macOS / iOS"},
		},
	}
}
