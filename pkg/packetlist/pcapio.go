package packetlist

import (
	"io"
	"os"
	"time"

	"github.com/smallnest/goscapy/pkg/pcap"
)

// ReadPcap reads an entire pcap/pcapng file into a PacketList, dissecting each
// record with the file's link-layer type. It mirrors Scapy's rdpcap(). Records
// that fail to dissect are skipped. The list's name is set to the file path.
func ReadPcap(path string) (*PacketList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	pl, err := ReadPcapReader(f)
	if err != nil {
		return nil, err
	}
	pl.name = path
	return pl, nil
}

// ReadPcapReader reads all packets from an io.Reader (pcap or pcapng) into a
// PacketList. Undissectable records are skipped.
func ReadPcapReader(r io.Reader) (*PacketList, error) {
	rd, err := pcap.NewReader(r)
	if err != nil {
		return nil, err
	}
	pl := New("")
	for {
		rec, err := rd.ReadPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return pl, err
		}
		pkt, err := rec.Packet()
		if err != nil {
			continue // skip undissectable records
		}
		pl.entries = append(pl.entries, Entry{
			Packet: pkt,
			Time:   rec.Timestamp,
			Data:   rec.Data,
		})
	}
	return pl, nil
}

// WritePcap writes the list to a pcap file with the given link type, mirroring
// Scapy's wrpcap(). Each entry is built (or its cached Data reused) and written
// with its timestamp; entries with a zero timestamp are written at time.Now().
func (pl *PacketList) WritePcap(path string, linkType uint32) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return pl.WritePcapWriter(f, linkType)
}

// WritePcapWriter writes the list to an io.Writer as a pcap stream.
func (pl *PacketList) WritePcapWriter(w io.Writer, linkType uint32) error {
	wr, err := pcap.NewWriter(w, linkType, 65535)
	if err != nil {
		return err
	}
	for _, e := range pl.entries {
		ts := e.Time
		if ts.IsZero() {
			ts = time.Now()
		}
		data := e.Data
		if data == nil {
			data, err = e.Packet.Build()
			if err != nil {
				return err
			}
		}
		if err := wr.WritePacket(data, ts); err != nil {
			return err
		}
	}
	return nil
}
