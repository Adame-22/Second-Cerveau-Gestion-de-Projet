#!/usr/bin/env bash
# Restaure une sauvegarde faite par sauvegarde.sh. Remplace les données actuelles.
# Usage : ./restaurer.sh sauvegardes/docuseal_AAAA-MM-JJ_HHMM.tar.gz
set -euo pipefail
cd "$(dirname "$0")"

archive=$(realpath "${1:?Usage : ./restaurer.sh <archive .tar.gz>}")
if [ "${CONFIRMER:-}" != "oui" ]; then
  read -rp "Ceci remplace toutes les données actuelles de DocuSeal. Taper oui pour continuer : " rep
  [ "$rep" = "oui" ] || { echo "Annulé."; exit 1; }
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$archive" -C "$tmp"
[ -f "$tmp/base.sql" ] && [ -d "$tmp/docuseal" ] || { echo "Archive invalide."; exit 1; }

docker compose stop app
docker compose up -d --wait postgres
docker compose exec -T postgres psql -q -U docuseal -d docuseal -v ON_ERROR_STOP=1 < "$tmp/base.sql" > /dev/null
rm -rf docuseal
cp -a "$tmp/docuseal" docuseal
docker compose up -d
echo "Restauration terminée depuis : $archive"
