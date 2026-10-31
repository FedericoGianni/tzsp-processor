package decoder

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestDecodeTZSP(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []byte
		wantErr error
	}{
		{
			name: "simple packet",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef},
			want: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name: "padding tags",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb},
			want: []byte{0xaa, 0xbb},
		},
		{
			name: "data tag",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x11, 0x22, 0x01, 0xcc},
			want: []byte{0xcc},
		},
		{
			name:    "too short",
			data:    []byte{0x01, 0x00},
			wantErr: ErrPacketTooShort,
		},
		{
			name:    "invalid version",
			data:    []byte{0x02, 0x00, 0x00, 0x00, 0x01, 0xaa},
			wantErr: ErrInvalidVersion,
		},
		{
			name:    "not packet type",
			data:    []byte{0x01, 0x01, 0x00, 0x00, 0x01, 0xaa},
			wantErr: ErrNotPacketType,
		},
		{
			name:    "no payload",
			data:    []byte{0x01, 0x00, 0x00, 0x00, 0x01},
			wantErr: ErrNoPayload,
		},
		{
			name:    "tag overflow",
			data:    []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x05, 0xaa},
			wantErr: ErrTagOverflow,
		},
		{
			name:    "truncated tag",
			data:    []byte{0x01, 0x00, 0x00, 0x00, 0x02},
			wantErr: ErrTruncatedTag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeTZSP(tt.data)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("got %x, want %x", got, tt.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid",
			cfg:  Config{ListenAddr: ":37008", OutputDir: "/tmp", RotateInterval: time.Minute},
		},
		{
			name:    "empty listen address",
			cfg:     Config{OutputDir: "/tmp", RotateInterval: time.Minute},
			wantErr: true,
		},
		{
			name:    "empty output directory",
			cfg:     Config{ListenAddr: ":37008", RotateInterval: time.Minute},
			wantErr: true,
		},
		{
			name:    "zero rotate interval",
			cfg:     Config{ListenAddr: ":37008", OutputDir: "/tmp"},
			wantErr: true,
		},
		{
			name: "valid ethernet link type",
			cfg: Config{
				ListenAddr: ":37008", OutputDir: "/tmp", RotateInterval: time.Minute,
				LinkType: LinkTypeEthernet,
			},
		},
		{
			name: "valid raw link type",
			cfg: Config{
				ListenAddr: ":37008", OutputDir: "/tmp", RotateInterval: time.Minute,
				LinkType: LinkTypeRaw,
			},
		},
		{
			name: "unsupported link type",
			cfg: Config{
				ListenAddr: ":37008", OutputDir: "/tmp", RotateInterval: time.Minute,
				LinkType: "bogus",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestTZSPDecoderRun(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		ListenAddr:     "127.0.0.1:0",
		OutputDir:      dir,
		RotateInterval: time.Hour,
	}

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	conn, err := net.Dial("udp", d.conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Send a valid TZSP packet with a 20-byte payload.
	payload := make([]byte, 20)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := append([]byte{0x01, 0x00, 0x00, 0x00, 0x01}, payload...)
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, func() bool { return d.stats.Written.Load() == 1 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(dir, "capture_*.pcap"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 pcap file, got %d", len(files))
	}
}

// TestTZSPDecoderLinkType verifies the pcap file header records the
// configured link type and that an empty value defaults to Ethernet.
func TestTZSPDecoderLinkType(t *testing.T) {
	tests := []struct {
		name     string
		linkType string
		want     layers.LinkType
	}{
		{"ethernet", LinkTypeEthernet, layers.LinkTypeEthernet},
		{"raw", LinkTypeRaw, layers.LinkTypeRaw},
		{"default", "", layers.LinkTypeEthernet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			d, err := New(Config{
				ListenAddr:     "127.0.0.1:0",
				OutputDir:      dir,
				RotateInterval: time.Hour,
				LinkType:       tt.linkType,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer d.Close()

			files, err := filepath.Glob(filepath.Join(dir, "capture_*.pcap"))
			if err != nil {
				t.Fatalf("glob: %v", err)
			}
			if len(files) != 1 {
				t.Fatalf("expected 1 pcap file, got %d", len(files))
			}

			f, err := os.Open(files[0])
			if err != nil {
				t.Fatalf("open pcap: %v", err)
			}
			defer func() { _ = f.Close() }()

			r, err := pcapgo.NewReader(f)
			if err != nil {
				t.Fatalf("pcap reader: %v", err)
			}
			if got := r.LinkType(); got != tt.want {
				t.Fatalf("link type = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTZSPDecoderRunInvalidPacket(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		ListenAddr:     "127.0.0.1:0",
		OutputDir:      dir,
		RotateInterval: time.Hour,
	}

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	conn, err := net.Dial("udp", d.conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Send an invalid TZSP packet (bad version).
	if _, err := conn.Write([]byte{0x02, 0x00, 0x00, 0x00, 0x01, 0xaa}); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, func() bool { return d.stats.Errors.Load() == 1 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

// waitFor polls cond until it returns true or the deadline expires.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}
