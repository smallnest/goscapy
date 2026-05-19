package sniff

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// CompileFilter compiles a BPF filter expression into raw BPF instructions
// by shelling out to tcpdump. Returns an error if tcpdump is not available
// on PATH or the filter expression is invalid.
//
// Note: On macOS, tcpdump requires root privileges to compile filters.
// Users who cannot run as root should provide pre-compiled BPFInstructions
// via SniffConfig.Instructions instead.
//
// Example:
//
//	insns, err := CompileFilter("tcp port 80")
func CompileFilter(filter string) ([]sendrecv.BPFInstruction, error) {
	cmd := exec.Command("tcpdump", "-dd", filter)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sniff: compile filter %q: %w (stderr: %s)",
			filter, err, strings.TrimSpace(stderr.String()))
	}

	return parseDDOutput(stdout.String())
}

// parseDDOutput parses the output of tcpdump -dd into BPFInstructions.
// Each line has the form: { 0x28, 0, 0, 0x0000000c },
func parseDDOutput(output string) ([]sendrecv.BPFInstruction, error) {
	var instructions []sendrecv.BPFInstruction
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		// Strip braces and trailing comma/semicolon.
		line = strings.Trim(line, "{},; ")
		parts := strings.Split(line, ",")
		if len(parts) != 4 {
			return nil, fmt.Errorf("sniff: unexpected tcpdump output line: {%s}", line)
		}

		code, err := parseValue(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("sniff: parse code: %w", err)
		}
		jt, err := parseValue(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("sniff: parse jt: %w", err)
		}
		jf, err := parseValue(strings.TrimSpace(parts[2]))
		if err != nil {
			return nil, fmt.Errorf("sniff: parse jf: %w", err)
		}
		k, err := parseValue(strings.TrimSpace(parts[3]))
		if err != nil {
			return nil, fmt.Errorf("sniff: parse k: %w", err)
		}

		instructions = append(instructions, sendrecv.BPFInstruction{
			Code: uint16(code),
			Jt:   uint8(jt),
			Jf:   uint8(jf),
			K:    uint32(k),
		})
	}

	if len(instructions) == 0 {
		return nil, fmt.Errorf("sniff: tcpdump produced no BPF instructions")
	}
	return instructions, nil
}

// parseValue parses a decimal or hex value string into uint64.
func parseValue(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}
