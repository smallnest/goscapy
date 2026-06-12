// Package external bridges goscapy packets to external analysis tools by
// writing them to a temporary pcap file and launching tcpdump, tshark, or
// Wireshark on it. It mirrors Scapy's wireshark(pkt) / tcpdump(pkt) helpers.
//
// These functions shell out to programs that must be installed and on PATH.
// They are intended for interactive debugging, not for production pipelines —
// each call writes a capture to a temp file and spawns a process.
package external

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/pcap"
)

// WritePcapTemp builds the given packets into a temporary pcap file with the
// given link type and returns its path. The caller is responsible for removing
// the file when done (the launch helpers below do this for blocking tools).
func WritePcapTemp(linkType uint32, pkts ...*packet.Packet) (string, error) {
	f, err := os.CreateTemp("", "goscapy-*.pcap")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	w, err := pcap.NewWriter(f, linkType, 65535)
	if err != nil {
		return "", err
	}
	for _, p := range pkts {
		if err := w.WritePkt(p); err != nil {
			_ = os.Remove(f.Name())
			return "", fmt.Errorf("external: build packet: %w", err)
		}
	}
	return f.Name(), nil
}

// Wireshark writes pkts to a temporary pcap and opens it in Wireshark
// (non-blocking: Wireshark keeps running after this returns). The temp file is
// left on disk for Wireshark to read; the returned path lets the caller remove
// it later. linkType is typically pcap.LinkTypeEthernet.
//
// It requires the "wireshark" binary on PATH and returns an error if it is not
// found or fails to start.
func Wireshark(linkType uint32, pkts ...*packet.Packet) (path string, err error) {
	bin, err := exec.LookPath("wireshark")
	if err != nil {
		return "", fmt.Errorf("external: wireshark not found on PATH: %w", err)
	}
	path, err = WritePcapTemp(linkType, pkts...)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(bin, "-r", path)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("external: start wireshark: %w", err)
	}
	// Detach: do not wait. Caller may remove path after Wireshark loads it.
	go func() { _ = cmd.Wait() }()
	return path, nil
}

// Tcpdump writes pkts to a temporary pcap, runs `tcpdump -r <file> <args...>`
// to completion, removes the temp file, and returns tcpdump's combined output.
// Pass extra args such as "-n", "-vv", or a filter expression.
//
// It requires the "tcpdump" binary on PATH.
func Tcpdump(linkType uint32, args []string, pkts ...*packet.Packet) (string, error) {
	bin, err := exec.LookPath("tcpdump")
	if err != nil {
		return "", fmt.Errorf("external: tcpdump not found on PATH: %w", err)
	}
	path, err := WritePcapTemp(linkType, pkts...)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(path) }()

	full := append([]string{"-r", path}, args...)
	cmd := exec.Command(bin, full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("external: tcpdump: %w", err)
	}
	return out.String(), nil
}

// Tshark writes pkts to a temporary pcap, runs `tshark -r <file> <args...>` to
// completion, removes the temp file, and returns tshark's combined output.
// tshark is Wireshark's CLI; it gives richer dissection than tcpdump.
//
// It requires the "tshark" binary on PATH.
func Tshark(linkType uint32, args []string, pkts ...*packet.Packet) (string, error) {
	bin, err := exec.LookPath("tshark")
	if err != nil {
		return "", fmt.Errorf("external: tshark not found on PATH: %w", err)
	}
	path, err := WritePcapTemp(linkType, pkts...)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(path) }()

	full := append([]string{"-r", path}, args...)
	cmd := exec.Command(bin, full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("external: tshark: %w", err)
	}
	return out.String(), nil
}
