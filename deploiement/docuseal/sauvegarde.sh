#!/usr/bin/env bash
# Sauvegarde DocuSeal : base de données + documents signés, dans une seule archive.
# Garde les archives des 14 derniers jours. Usage : ./sauvegarde.sh
# À programmer chaque nuit (crontab -e) :  0 3 * * * /chemin/vers/docuseal/sauvegarde.sh
set -euo pipefail
cd "$(dirname "$0")"
umask 077  # les archives contiennent les clés secrètes de DocuSeal : lisibles par toi seul

dest="${BACKUP_DIR:-$PWD/sauvegardes}"
keep_days="${KEEP_DAYS:-14}"
mkdir -p "$dest"
archive="$dest/docuseal_$(date +%Y-%m-%d_%H%M).tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

docker compose exec -T postgres pg_dump -U docuseal -d docuseal --clean --if-exists > "$tmp/base.sql"
tar -czf "$tmp/archive.tar.gz" -C "$tmp" base.sql -C "$PWD" docuseal
mv "$tmp/archive.tar.gz" "$archive"

find "$dest" -name 'docuseal_*.tar.gz' -mtime +"$keep_days" -delete
echo "Sauvegarde créée : $archive"
