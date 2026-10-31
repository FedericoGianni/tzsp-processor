// Command tzsp-processor receives TZSP packets over UDP and writes the
// decoded packets to rotating pcap files.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/forbay/tzsp-processor/internal/decoder"
)

// version is set at build time via -ldflags="-X main.version=...".
var version = "dev"

func main() {
	listenAddr := flag.String("listen", ":37008", "UDP address to listen on")
	outputDir := flag.String("output", "/var/log/tzsp", "Output directory for pcap files")
	linkType := flag.String("linktype", decoder.LinkTypeEthernet,
		"pcap link type: ethernet (Ethernet frames) or raw (raw IP packets)")
	rotateMinutes := flag.Int("rotate", 5, "File rotation interval in minutes")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	d, err := decoder.New(decoder.Config{
		ListenAddr:     *listenAddr,
		OutputDir:      *outputDir,
		RotateInterval: time.Duration(*rotateMinutes) * time.Minute,
		LinkType:       *linkType,
	})
	if err != nil {
		log.Fatalf("Failed to create decoder: %v", err)
	}
	defer d.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errChan := make(chan error, 1)
	go func() {
		errChan <- d.Run(ctx)
	}()

	select {
	case err := <-errChan:
		// Close explicitly: log.Fatalf calls os.Exit, which skips deferred
		// calls, and we want the pcap file flushed and the socket closed.
		d.Close()
		if err != nil {
			log.Fatalf("Decoder error: %v", err)
		}
		log.Printf("Final stats: %s", d.Stats())
	case <-ctx.Done():
		log.Println("Shutting down...")
		stop()
		if err := <-errChan; err != nil {
			d.Close()
			log.Fatalf("Decoder error: %v", err)
		}
		log.Printf("Final stats: %s", d.Stats())
	}
}
