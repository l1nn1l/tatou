#!/bin/bash
# backup_storage.sh — backs up Tatou’s storage directory

DATE=$(date +'%Y%m%d_%H%M%S')
SRC="./storage"
DEST="./backups/storage_$DATE"

mkdir -p ./backups
cp -r "$SRC" "$DEST"

echo "[+] Storage directory backed up to $DEST"
