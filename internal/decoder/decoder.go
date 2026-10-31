// Package decoder implements a TZSP (TaZmen Sniffer Protocol) decoder
// that captures UDP traffic and writes the decoded packets to rotating
// pcap files.
package decoder

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	// maxPacketSize is the maximum size of a UDP datagram we accept.
	maxPacketSize = 65536
	// readBufferSize is the kernel socket receive buffer size in bytes.
	readBufferSize = 4 * 1024 * 1024
	// readTimeout is how long ReadFromUDP blocks before the loop checks
	// for context cancellation.
	readTimeout = 1 * time.Second
	// statsInterval is how often periodic stats are logged.
	statsInterval = 10 * time.Second
	// syncInterval is how many packets are written before fsync.
	syncInterval = 100
	// maxLoggedErrors is how many per-packet errors are logged before
	// logging is throttled to avoid flooding on sustained bad traffic.
	maxLoggedErrors = 10
)

// Accepted pcap link type names. The zero value means LinkTypeEthernet.
const (
	LinkTypeEthernet = "ethernet"
	LinkTypeRaw      = "raw"
)

// Config holds the decoder configuration.
type Config struct {
	// ListenAddr is the UDP address to listen on, e.g. ":37008".
	ListenAddr string
	// OutputDir is the directory where pcap files are written.
	OutputDir string
	// RotateInterval is how often a new pcap file is started.
	RotateInterval time.Duration
	// LinkType is the pcap link type recorded in the file header:
	// LinkTypeEthernet (default) for Ethernet frames, LinkTypeRaw for
	// raw IP packets.
	LinkType string
}

// Validate checks that the configuration is usable.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen address must not be empty")
	}
	if c.OutputDir == "" {
		return errors.New("output directory must not be empty")
	}
	if c.RotateInterval <= 0 {
		return errors.New("rotate interval must be positive")
	}
	switch c.LinkType {
	case "", LinkTypeEthernet, LinkTypeRaw:
	default:
		return fmt.Errorf("unsupported link type %q (use %q or %q)",
			c.LinkType, LinkTypeEthernet, LinkTypeRaw)
	}
	return nil
}

// TZSPDecoder receives TZSP packets over UDP and writes the decoded
// payloads to rotating pcap files.
type TZSPDecoder struct {
	conn           *net.UDPConn
	outputDir      string
	rotateInterval time.Duration
	linkType       layers.LinkType

	file       *os.File
	pcapWriter *pcapgo.Writer
	lastRotate time.Time
	fileSeq    int

	stats Stats
}

// New creates a TZSPDecoder bound to the given configuration. The first
// pcap file is created immediately.
func New(cfg Config) (*TZSPDecoder, error) {
	if cfg.LinkType == "" {
		cfg.LinkType = LinkTypeEthernet
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	if err := conn.SetReadBuffer(readBufferSize); err != nil {
		log.Printf("Warning: failed to set read buffer: %v", err)
	}

	linkType := layers.LinkTypeEthernet
	if cfg.LinkType == LinkTypeRaw {
		linkType = layers.LinkTypeRaw
	}

	d := &TZSPDecoder{
		conn:           conn,
		outputDir:      cfg.OutputDir,
		rotateInterval: cfg.RotateInterval,
		linkType:       linkType,
		lastRotate:     time.Now(),
	}

	if err := d.rotateFile(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return d, nil
}

// Run receives and decodes TZSP packets until ctx is cancelled or a
// fatal read error occurs. It must be called at most once.
func (d *TZSPDecoder) Run(ctx context.Context) error {
	log.Printf("Listening for TZSP packets on %s", d.conn.LocalAddr())
	log.Printf("Writing decoded packets to: %s", d.outputDir)
	log.Printf("File rotation interval: %v", d.rotateInterval)

	buf := make([]byte, maxPacketSize)
	statsTicker := time.NewTicker(statsInterval)
	defer statsTicker.Stop()

	done := make(chan struct{})
	defer close(done)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-statsTicker.C:
				log.Printf("Stats: %s", d.stats.String())
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if time.Since(d.lastRotate) >= d.rotateInterval {
			if err := d.rotateFile(); err != nil {
				log.Printf("Error rotating file: %v", err)
			}
		}

		if err := d.conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}

		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("read UDP: %w", err)
		}

		d.stats.Received.Add(1)

		payload, err := DecodeTZSP(buf[:n])
		if err != nil {
			d.recordError("TZSP decode error: %v", err)
			continue
		}

		d.stats.Decoded.Add(1)

		if len(payload) < minPayloadLen {
			d.recordError("Payload too short: %d bytes", len(payload))
			continue
		}

		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(payload),
			Length:        len(payload),
		}

		if err := d.pcapWriter.WritePacket(ci, payload); err != nil {
			d.recordError("Error writing packet: %v", err)
			continue
		}

		d.stats.Written.Add(1)

		if d.stats.Written.Load()%syncInterval == 0 {
			if err := d.file.Sync(); err != nil {
				log.Printf("Error syncing file: %v", err)
			}
		}
	}
}

// Close flushes and closes the current pcap file and the UDP socket.
// It is safe to call multiple times, but not concurrently with Run.
func (d *TZSPDecoder) Close() {
	if d.file != nil {
		if err := d.file.Sync(); err != nil {
			log.Printf("Warning: failed to sync file: %v", err)
		}
		if err := d.file.Close(); err != nil {
			log.Printf("Warning: failed to close file: %v", err)
		}
		d.file = nil
	}
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
}

// Stats returns a snapshot of the decoder statistics.
func (d *TZSPDecoder) Stats() StatsSnapshot {
	return d.stats.Snapshot()
}

// recordError increments the error counter and logs the first few errors
// to avoid flooding the log on sustained malformed traffic.
func (d *TZSPDecoder) recordError(format string, args ...any) {
	d.stats.Errors.Add(1)
	if d.stats.Errors.Load() <= maxLoggedErrors {
		log.Printf(format, args...)
	}
}

// rotateFile opens a new timestamped pcap file and retires the previous
// one. The new file is fully created before the old one is closed so a
// failure leaves the current file intact and writable.
func (d *TZSPDecoder) rotateFile() error {
	d.fileSeq++
	filename := filepath.Join(d.outputDir, fmt.Sprintf("capture_%s_%03d.pcap",
		time.Now().Format("20060102_150405"), d.fileSeq))

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create pcap file: %w", err)
	}

	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(maxPacketSize, d.linkType); err != nil {
		_ = f.Close()
		_ = os.Remove(filename)
		return fmt.Errorf("write pcap header: %w", err)
	}

	// Success: retire the old file before swapping in the new one.
	if d.file != nil {
		if err := d.file.Sync(); err != nil {
			log.Printf("Warning: failed to sync file: %v", err)
		}
		if err := d.file.Close(); err != nil {
			log.Printf("Warning: failed to close file: %v", err)
		}
	}

	d.file = f
	d.pcapWriter = writer
	d.lastRotate = time.Now()

	log.Printf("Rotated to new file: %s", filename)
	return nil
}
