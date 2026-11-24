#!/usr/bin/env bash
# Installe et démarre DocuSeal. À lancer sur le serveur, dans ce dossier : ./installer.sh
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null || {
  echo "Docker n'est pas installé. Installe-le avec : curl -fsSL https://get.docker.com | sh"
  exit 1
}

if [ ! -f .env ]; then
  host="${HOST:-}"
  [ -n "$host" ] || read -rp "Adresse de DocuSeal (ex. signature.monentreprise.fr) : " host
  [ -n "$host" ] || { echo "L'adresse est obligatoire."; exit 1; }
  umask 077
  printf 'HOST=%s\nPOSTGRES_PASSWORD=%s\n' "$host" "$(openssl rand -hex 24)" > .env
  echo "Fichier .env créé (garde-le secret)."
fi

docker compose up -d
host=$(grep '^HOST=' .env | cut -d= -f2-)
echo
echo "DocuSeal démarre. Dans 1 à 2 minutes, ouvre https://$host"
echo "pour créer ton compte administrateur."
