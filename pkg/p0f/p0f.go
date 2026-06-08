// Package p0f provides passive OS fingerprinting by analyzing TCP/IP header
// characteristics, compatible with the p0f signature format.
//
// Basic usage:
//
//	result := p0f.P0fFingerprint(pkt, db)
//	fmt.Println(result.OS, result.Confidence)
package p0f

import (
	"fmt"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// Confidence levels for fingerprint matches.
type Confidence int

const (
	ConfNone      Confidence = iota // No match
	ConfLow                         // Generic or partial match
	ConfMedium                      // Good match, multiple fields aligned
	ConfHigh                        // Strong match, all fields aligned
)

func (c Confidence) String() string {
	switch c {
	case ConfLow:
		return "low"
	case ConfMedium:
		return "medium"
	case ConfHigh:
		return "high"
	default:
		return "none"
	}
}

// P0fResult holds the outcome of a passive OS fingerprint attempt.
type P0fResult struct {
	OS         string     // Identified OS name (e.g. "Linux 3.x", "Windows 10")
	Confidence Confidence // Match confidence level
	Matched    []string   // Fields that matched (e.g. "ttl", "window", "mss")
	Details    string     // Human-readable details of the match
}

// P0fFingerprint analyzes a packet's TCP/IP header characteristics against
// the provided signature database to identify the remote OS. Only SYN and
// SYN+ACK packets produce meaningful results; other packets return an empty result.
func P0fFingerprint(pkt *packet.Packet, db *Database) P0fResult {
	if db == nil || pkt == nil {
		return P0fResult{}
	}

	ipLayer, tcpLayer := findIPTCP(pkt)
	if ipLayer == nil || tcpLayer == nil {
		return P0fResult{}
	}

	flags, _ := tcpLayer.Get("flags")
	flagsU8, ok := flags.(uint8)
	if !ok {
		return P0fResult{}
	}

	// Determine which signature set to use based on TCP flags.
	isSyn := flagsU8 == layers.TCPSyn
	isSynAck := flagsU8 == (layers.TCPSyn | layers.TCPAck)

	if !isSyn && !isSynAck {
		return P0fResult{}
	}

	// Extract fingerprint fields from the packet.
	fp := extractFingerprint(ipLayer, tcpLayer)

	var sigs []Signature
	var modeName string
	if isSyn {
		sigs = db.Syn
		modeName = "syn"
	} else {
		sigs = db.SynAck
		modeName = "syn+ack"
	}

	return matchFingerprint(fp, sigs, modeName)
}

// Fingerprint holds the extracted TCP/IP characteristics used for matching.
type Fingerprint struct {
	Window    uint16 // TCP window size
	TTL       uint8  // IP TTL
	OptsLen   int    // Total TCP options length in bytes
	MSS       uint16 // MSS option value (0 if absent)
	WScale    uint8  // Window scale option value (0 if absent)
	SACK      bool   // SACK permitted option present
	NOP       bool   // NOP option present
	DF        bool   // Don't Fragment bit set
	HasMSS    bool   // MSS option present
	HasWScale bool   // Window scale option present
}

// extractFingerprint builds a Fingerprint from IP and TCP layers.
func extractFingerprint(ipLayer, tcpLayer *packet.Layer) Fingerprint {
	fp := Fingerprint{}

	// IP fields.
	if v, err := ipLayer.Get("ttl"); err == nil {
		if t, ok := v.(uint8); ok {
			fp.TTL = t
		}
	}
	if v, err := ipLayer.Get("frag"); err == nil {
		if f, ok := v.(uint16); ok {
			fp.DF = (f & 0x4000) != 0
		}
	}

	// TCP fields.
	if v, err := tcpLayer.Get("window"); err == nil {
		if w, ok := v.(uint16); ok {
			fp.Window = w
		}
	}

	// Compute options length from actual options, not dataofs.
	// dataofs is only accurate after Build(); for dissected packets the
	// PostParseHook sets the options correctly, but for manually-constructed
	// layers we need to serialize the options to measure them.
	optsVal, _ := tcpLayer.Get("options")
	if opts, ok := optsVal.([]layers.TCPOption); ok && len(opts) > 0 {
		if v, err := tcpLayer.Get("dataofs"); err == nil {
			if d, ok := v.(uint8); ok {
				headerSize := layers.TCPDataOffset(d)
				if headerSize > 20 {
					fp.OptsLen = headerSize - 20
				} else {
					fp.OptsLen = len(layers.SerializeTCPOptions(opts))
				}
			}
		} else {
			fp.OptsLen = len(layers.SerializeTCPOptions(opts))
		}
	}

	// Parse TCP options.
	if opts, ok := optsVal.([]layers.TCPOption); ok {
		for _, opt := range opts {
			switch opt.Kind {
			case layers.TCPOptMSS:
				fp.HasMSS = true
				if len(opt.Data) >= 2 {
					fp.MSS = uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
				}
			case layers.TCPOptWScale:
				fp.HasWScale = true
				if len(opt.Data) >= 1 {
					fp.WScale = opt.Data[0]
				}
			case layers.TCPOptSACKPerm:
				fp.SACK = true
			case layers.TCPOptNOP:
				fp.NOP = true
			}
		}
	}

	return fp
}

// matchFingerprint compares the observed fingerprint against the signature database.
func matchFingerprint(fp Fingerprint, sigs []Signature, modeName string) P0fResult {
	bestResult := P0fResult{}
	bestScore := 0

	for i := range sigs {
		matched, score := matchSig(fp, &sigs[i])
		if score > bestScore {
			bestScore = score
			conf := scoreToConfidence(score)
			bestResult = P0fResult{
				OS:         sigs[i].Label,
				Confidence: conf,
				Matched:    matched,
				Details:    fmt.Sprintf("mode=%s score=%d/%d", modeName, score, sigs[i].fieldCount()),
			}
		}
	}

	return bestResult
}

// matchSig compares a fingerprint against a single signature and returns
// the matched field names and a score (number of matching fields).
func matchSig(fp Fingerprint, sig *Signature) ([]string, int) {
	var matched []string
	score := 0

	// Window size.
	if sig.Window != 0 {
		if fp.Window == sig.Window {
			matched = append(matched, "window")
			score++
		} else {
			return nil, 0 // Window mismatch is fatal for this signature
		}
	}

	// TTL (match if fp.TTL is within sig.TTLMin..sig.TTLMax).
	if sig.TTLMin != 0 || sig.TTLMax != 0 {
		if fp.TTL >= sig.TTLMin && fp.TTL <= sig.TTLMax {
			matched = append(matched, "ttl")
			score++
		} else {
			return nil, 0
		}
	}

	// Options length.
	if sig.OptsLen >= 0 {
		if fp.OptsLen == sig.OptsLen {
			matched = append(matched, "opts_len")
			score++
		} else {
			return nil, 0
		}
	}

	// MSS.
	if sig.MSSWild {
		// Wildcard: just check presence.
		if fp.HasMSS {
			matched = append(matched, "mss")
			score++
		}
	} else if sig.MSS != 0 {
		if fp.HasMSS && fp.MSS == sig.MSS {
			matched = append(matched, "mss")
			score++
		} else {
			return nil, 0
		}
	}

	// Window scale.
	if sig.WScaleWild {
		if fp.HasWScale {
			matched = append(matched, "wscale")
			score++
		}
	} else if sig.WScale >= 0 {
		if fp.HasWScale && fp.WScale == uint8(sig.WScale) {
			matched = append(matched, "wscale")
			score++
		} else {
			return nil, 0
		}
	}

	// SACK.
	if sig.SACK >= 0 {
		if fp.SACK == (sig.SACK != 0) {
			matched = append(matched, "sack")
			score++
		} else {
			return nil, 0
		}
	}

	// NOP.
	if sig.NOP >= 0 {
		if fp.NOP == (sig.NOP != 0) {
			matched = append(matched, "nop")
			score++
		} else {
			return nil, 0
		}
	}

	// DF.
	if sig.DF >= 0 {
		if fp.DF == (sig.DF != 0) {
			matched = append(matched, "df")
			score++
		} else {
			return nil, 0
		}
	}

	return matched, score
}

// scoreToConfidence converts a match score to a confidence level.
func scoreToConfidence(score int) Confidence {
	switch {
	case score >= 6:
		return ConfHigh
	case score >= 4:
		return ConfMedium
	case score >= 2:
		return ConfLow
	default:
		return ConfNone
	}
}

// findIPTCP locates the first IP and TCP layers in a packet.
func findIPTCP(pkt *packet.Packet) (*packet.Layer, *packet.Layer) {
	var ipLayer, tcpLayer *packet.Layer
	for _, l := range pkt.Layers() {
		switch l.Proto() {
		case "IP":
			ipLayer = l
		case "TCP":
			tcpLayer = l
		}
	}
	return ipLayer, tcpLayer
}
