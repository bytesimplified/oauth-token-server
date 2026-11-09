#!/usr/bin/env bash
set -euo pipefail
umask 077
# Restore into a staging database first. Requires PGHOST, PGDATABASE, PGUSER,
# PGPASSWORD and AGE_IDENTITY_FILE; plaintext is streamed, never saved.
if [[ "$#" -ne 1 || -z "${AGE_IDENTITY_FILE:-}" || "${CONFIRM_RESTORE:-}" != "YES" ]]; then
  echo "Usage: CONFIRM_RESTORE=YES AGE_IDENTITY_FILE=/path/key.txt scripts/restore_postgres.sh backup.dump.age" >&2
  exit 2
fi
for cmd in pg_restore age; do command -v "$cmd" >/dev/null || { echo "$cmd not installed" >&2; exit 2; }; done
age --decrypt --identity "$AGE_IDENTITY_FILE" "$1" | pg_restore --clean --if-exists --no-owner --no-acl --exit-on-error --single-transaction --dbname="${PGDATABASE:?Set PGDATABASE}"
echo "PostgreSQL restore completed. Verify application health and data consistency."
