#!/bin/bash
set -euo pipefail

PROCESS_DIR="/var/log/tzsp/processing"
DONE_DIR="/var/log/tzsp/done"
FILE_AGE_THRESHOLD=60
LOGFILE="/var/log/tzsp-mover.log"

mkdir -p "$DONE_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}

moved_count=0

for pcap in "$PROCESS_DIR"/capture_*.pcap; do
    [ -f "$pcap" ] || continue

    filename=$(basename "$pcap")

    # Check if file is open by tzsp-processor
    if lsof "$pcap" 2>/dev/null | grep -q tzsp-processor; then
        continue
    fi

    # Check file age
    file_age=$(($(date +%s) - $(stat -c %Y "$pcap")))
    if [ $file_age -lt $FILE_AGE_THRESHOLD ]; then
        continue
    fi

    # Move the file
    if mv "$pcap" "$DONE_DIR/$filename" 2>/dev/null; then
        file_size=$(stat -c %s "$DONE_DIR/$filename")
        log "Moved: $filename (age: ${file_age}s, size: $((file_size / 1024))KB)"
        moved_count=$((moved_count + 1))
    else
        log "ERROR: Failed to move $filename"
    fi
done

# Only log if we actually moved files (reduces log spam)
[ $moved_count -gt 0 ] && log "Run complete: moved $moved_count file(s)"

exit 0