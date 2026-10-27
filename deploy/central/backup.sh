#!/bin/bash
# Daily logical backup of the vuln database into /backups, keeping BACKUP_KEEP_DAYS.
# BACKUP_RUN_NOW=1 takes one backup immediately (useful to test the setup).
set -euo pipefail # pipefail: a failed mysqldump must not look like a good backup
: "${MYSQL_PASSWORD:?}" "${BACKUP_KEEP_DAYS:=14}" "${BACKUP_AT:=02:30}"

backup() {
	f="/backups/vuln-$(date -u +%Y%m%d-%H%M%S).sql.gz"
	# Temp name first, renamed only after a complete dump. MYSQL_PWD keeps the
	# password out of the process list.
	if MYSQL_PWD="$MYSQL_PASSWORD" mysqldump -h mysql -u central --single-transaction --no-tablespaces \
		--routines --triggers vuln | gzip > "$f.tmp"; then
		mv "$f.tmp" "$f"
		echo "backup ok: $f ($(du -h "$f" | cut -f1))"
	else
		rm -f "$f.tmp"
		echo "backup FAILED" >&2
	fi
	find /backups -name 'vuln-*.sql.gz' -mtime +"$BACKUP_KEEP_DAYS" -delete
}

[ "${BACKUP_RUN_NOW:-0}" = "1" ] && backup
while :; do
	now=$(date -u +%s)
	next=$(date -u -d "$(date -u +%Y-%m-%d) $BACKUP_AT" +%s)
	[ "$next" -le "$now" ] && next=$((next + 86400))
	sleep $((next - now))
	backup
done
