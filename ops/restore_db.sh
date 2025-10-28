#!/bin/bash
set -euo pipefail

# restore_db.sh — restore the Tatou database from a dump

# --- Load environment variables (for DB password etc.) ---
set -a
source /home/lab/tatou/.env
set +a

# --- Configuration ---
DB_CONTAINER="tatou-db-1"       # check with `docker ps`
DB_USER="root"
DB_PASS="${MARIADB_ROOT_PASSWORD}"
DB_NAME="tatou"
BACKUP_DIR="/home/lab/backups"

# --- Select most recent dump ---
LATEST_DUMP=$(ls -t ${BACKUP_DIR}/db_*.sql.gz 2>/dev/null | head -n 1 || true)

if [ -z "$LATEST_DUMP" ]; then
    echo "[!] No backup SQL file found in $BACKUP_DIR"
    exit 1
fi

echo "[*] Restoring database from: $LATEST_DUMP"

# --- Decompress if needed ---
TMP_SQL="/tmp/restore_$$.sql"
gunzip -c "$LATEST_DUMP" > "$TMP_SQL"

# --- Run restore inside DB container ---
/usr/bin/docker exec -i "$DB_CONTAINER" mariadb -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" < "$TMP_SQL"

/bin/rm -f "$TMP_SQL"
/bin/echo "[+] Database restored successfully."
