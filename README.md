# tzsp-processor

A Go service that receives [TZSP](https://en.wikipedia.org/wiki/TZSP) (TaZmen Sniffer Protocol) packets over UDP, decapsulates them, and writes the decoded packets to rotating pcap files.

Typical use case: capture traffic from MikroTik routers (which can send TZSP-encapsulated packets) and feed the resulting pcap files to Suricata for inspection.

## How it works

```
  MikroTik / TZSP sender ──UDP :37008──► tzsp-processor ──► /var/log/tzsp/capture_*.pcap
                                              │
                                              └── rotates every N minutes
```

- Listens on a UDP port (default `:37008`)
- Validates the TZSP header (version, type) and skips the tag section
- Writes the decapsulated payload to timestamped pcap files
- Records the pcap link type in the file header: `ethernet` by default
  (MikroTik sends Ethernet frames), or `raw` for raw IP payloads
- Rotates files on a configurable interval and fsyncs periodically

## Quick Start

Requires Go 1.27 or newer to build from source.

```bash
# Build
make build

# Run
./bin/tzsp-processor -listen :37008 -output /var/log/tzsp -rotate 5
```

### Flags

| Flag         | Default          | Description                                                    |
|--------------|------------------|----------------------------------------------------------------|
| `-listen`    | `:37008`         | UDP address to listen on                                       |
| `-output`    | `/var/log/tzsp`  | Output directory for pcap files                                |
| `-linktype`  | `ethernet`       | pcap link type: `ethernet` (Ethernet frames) or `raw` (raw IP) |
| `-rotate`    | `5`              | File rotation interval in minutes                              |
| `-version`   |                  | Print the version and exit                                     |

The service shuts down gracefully on `SIGINT`/`SIGTERM`, flushing the current pcap file and logging final stats.

## Project Structure

```
├── cmd/tzsp-processor/   # Application entrypoint
├── internal/decoder/     # TZSP decoding, pcap writing, rotation
├── build/Dockerfile      # Production image (multi-stage, distroless)
├── scripts/              # Cron helpers for pcap lifecycle
├── Makefile              # fmt / lint / vet / test / build / dist targets
└── .gitlab-ci.yml        # CI pipeline
```

## Development

```bash
make fmt        # format with gofmt
make lint       # golangci-lint (see .golangci.yml)
make vet        # go vet
make test       # go test -race -cover
make build      # static binary with version stamp
make dist       # linux/amd64 + linux/arm64 release binaries and SHA256SUMS
```

## CI Pipeline

The GitLab CI pipeline runs on every push:

1. **format** — `gofmt` check + `go mod tidy` consistency
2. **lint** — `golangci-lint`
3. **vet** — `go vet`
4. **test** — `go test -race -cover`
5. **security** — SonarQube analysis (internal runners only)
6. **build** — release binaries for linux/amd64 and linux/arm64; the container image is pushed to the internal registry only from `main` and tags
7. **release** — on tags, uploads the binaries to the GitLab generic package registry and creates a release

The SonarQube and container-registry jobs target the project's internal
`k8s` runner and private registry. They are skipped on forks.

## Deployment

### systemd

```ini
[Service]
ExecStart=/usr/local/bin/tzsp-processor -listen :37008 -output /var/log/tzsp/processing -rotate 1 -linktype ethernet
WorkingDirectory=/var/log/tzsp/processing
```

### Docker

```bash
make docker-build
docker run --rm -p 37008:37008/udp \
  -v /var/log/tzsp:/var/log/tzsp \
  tzsp-processor:latest
```

Mount a writable volume at `/var/log/tzsp` (the container runs as a non-root user).

### Cron helpers

- `scripts/tzsp-cleanup.sh` — delete pcap files older than 7 days from the `done` folder
- `scripts/tzsp-mover.sh` — move closed pcap files from `processing` to `done`

## Security notes

TZSP has no authentication or encryption. Only expose the listen port to
trusted senders on a trusted network, and firewall it from the internet.

## Testing

```bash
go test -v -race -cover ./...
```

Tests cover TZSP header/tag parsing (valid and malformed packets), config
validation, pcap link-type selection, and an end-to-end run over a real
UDP socket.

## License

MIT — see [LICENSE](LICENSE). Third-party notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
