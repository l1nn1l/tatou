#!/bin/bash
set -euo pipefail

# Load environment variables from Docker .env file
set -a
source /home/lab/tatou/.env
set +a

BACKUP_DIR="/home/lab/backups"
DATE=$(date +"%Y-%m-%d_%H-%M")
DB_HOST="127.0.0.1"
DB_PORT="3306"
DB_USER="root"
DB_PASS="${MARIADB_ROOT_PASSWORD}"
DB_NAME="tatou"

mkdir -p "$BACKUP_DIR"

/usr/bin/mysqldump -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" > "$BACKUP_DIR/db_$DATE.sql"
gzip "$BACKUP_DIR/db_$DATE.sql"
