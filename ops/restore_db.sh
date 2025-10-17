#!/bin/bash
# restore_db.sh — restore the Tatou database from a dump

# --- Configuration ---
DB_CONTAINER="tatou-db-1"     # check with `docker ps`
DB_USER="tatou"
DB_PASS="tatou"
DB_NAME="tatou"
BACKUP_DIR="/home/lab/tatou/backups/db"

# --- Select most recent dump ---
LATEST_DUMP=$(ls -t ${BACKUP_DIR}/tatou_*.sql 2>/dev/null | head -n 1)

if [ -z "$LATEST_DUMP" ]; then
    echo "[!] No backup SQL file found in $BACKUP_DIR"
    exit 1
fi

echo "[*] Restoring database from: $LATEST_DUMP"

# --- Run restore inside DB container ---
cat "$LATEST_DUMP" | docker exec -i "$DB_CONTAINER" \
    mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME"

if [ $? -eq 0 ]; then
    echo "[+] Database successfully restored."
else
    echo "[!] Restore failed."
fi
