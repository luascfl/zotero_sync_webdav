#!/usr/bin/env bash

LOG="zotero_loop.log"
echo "Starting continuous Zotero sync loop..." > "$LOG"

while true; do
    echo "Running python3 zotero_sync_webdav.py at $(date)" >> "$LOG"
    python3 zotero_sync_webdav.py >> "$LOG" 2>&1
    
    EXIT_CODE=$?
    echo "Exit code: $EXIT_CODE" >> "$LOG"
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "Sync completed successfully at $(date)." >> "$LOG"
        break
    else
        echo "Sync timed out or failed. Retrying in 10 seconds..." >> "$LOG"
        sleep 10
    fi
done
