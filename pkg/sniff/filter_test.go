package sniff

import (
	"os/exec"
	"testing"
)

func TestParseDDOutput(t *testing.T) {
	input := `{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 6, 0x000086dd },
{ 0x06, 0, 0, 0x0000ffff },
`
	insns, err := parseDDOutput(input)
	if err != nil {
		t.Fatalf("parseDDOutput failed: %v", err)
	}
	if len(insns) != 3 {
		t.Fatalf("expected 3 instructions, got %d", len(insns))
	}
	if insns[0].Code != 0x28 || insns[0].K != 0x0000000c {
		t.Errorf("first instruction mismatch: code=0x%04x k=0x%08x", insns[0].Code, insns[0].K)
	}
	if insns[1].Code != 0x15 || insns[1].K != 0x000086dd {
		t.Errorf("second instruction mismatch: code=0x%04x k=0x%08x", insns[1].Code, insns[1].K)
	}
	if insns[2].Code != 0x06 || insns[2].K != 0x0000ffff {
		t.Errorf("third instruction mismatch: code=0x%04x k=0x%08x", insns[2].Code, insns[2].K)
	}
}

func TestParseDDOutputDecimal(t *testing.T) {
	input := `{ 6, 0, 0, 65535 },
`
	insns, err := parseDDOutput(input)
	if err != nil {
		t.Fatalf("parseDDOutput failed: %v", err)
	}
	if len(insns) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(insns))
	}
	if insns[0].Code != 6 || insns[0].K != 65535 {
		t.Errorf("instruction mismatch: code=%d k=%d", insns[0].Code, insns[0].K)
	}
}

func TestParseDDOutputEmpty(t *testing.T) {
	_, err := parseDDOutput("")
	if err == nil {
		t.Fatal("expected error for empty output")
	}
	t.Logf("got expected error: %v", err)
}

func TestParseDDOutputInvalidLine(t *testing.T) {
	_, err := parseDDOutput("{ 0x28, 0, 0x0000000c },")
	if err == nil {
		t.Fatal("expected error for invalid line (wrong number of fields)")
	}
	t.Logf("got expected error: %v", err)
}

func TestCompileFilterInvalidExpression(t *testing.T) {
	// Skip if tcpdump is not available.
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("skipping: tcpdump not found on PATH")
	}

	_, err := CompileFilter("not a valid !!! filter !!!")
	if err == nil {
		t.Fatal("expected error for invalid filter expression")
	}
	t.Logf("got expected error: %v", err)
}
