#!/bin/bash
set -euo pipefail

# Delete old .pcap files (>7 days)
find /var/log/tzsp/done -type f -name "*.pcap" -mtime +7 -exec rm -f {} \;