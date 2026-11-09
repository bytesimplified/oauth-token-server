#!/usr/bin/env bash
set -euo pipefail
umask 077
# Requires pg_dump, age, PGHOST, PGDATABASE, PGUSER, PGPASSWORD and AGE_RECIPIENT.
if [[ "$#" -ne 1 || -z "${AGE_RECIPIENT:-}" ]]; then
  echo "Usage: AGE_RECIPIENT=age1... scripts/backup_postgres.sh /secure/path/backup.dump.age" >&2
  exit 2
fi
for cmd in pg_dump age; do command -v "$cmd" >/dev/null || { echo "$cmd not installed" >&2; exit 2; }; done
outfile="$1"
[[ ! -e "$outfile" ]] || { echo "Backup file exists" >&2; exit 2; }
temp="${outfile}.tmp.$$"
trap 'rm -f "$temp"' EXIT
pg_dump --format=custom --no-owner --no-acl | age --recipient "$AGE_RECIPIENT" > "$temp"
mv "$temp" "$outfile"
echo "Encrypted PostgreSQL backup written to $outfile"
