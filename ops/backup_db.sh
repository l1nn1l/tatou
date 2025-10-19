#!/bin/bash
# Dump the MariaDB database used by Tatou

DATE=$(date +'%Y%m%d_%H%M%S')
BACKUP_DIR="./backups/db"
mkdir -p "$BACKUP_DIR"

echo "[*] Dumping tatou database..."
docker exec tatou-db-1 mysqldump -u tatou -ptatou tatou > "$BACKUP_DIR/tatou_$DATE.sql"
echo "[+] Database dump saved to $BACKUP_DIR/tatou_$DATE.sql"
