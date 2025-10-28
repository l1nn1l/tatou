#!/bin/bash
set -euo pipefail

# backup_storage.sh — backs up Tatou’s storage directory

# --- Configuration ---
BASE_DIR="/home/lab"
SRC="$BASE_DIR/storage"
BACKUP_DIR="$BASE_DIR/backups/storage"
DATE=$(date +"%Y-%m-%d_%H-%M")

# --- Run backup ---
mkdir -p "$BACKUP_DIR"
/bin/cp -r "$SRC" "$BACKUP_DIR/storage_$DATE"

/bin/echo "[+] Storage directory backed up to $BACKUP_DIR/storage_$DATE"
