#!/bin/bash
# Scan rapide d'un pseudo - Usage: ./quick_username.sh target_username
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/../venv/bin"
USERNAME="${1:?Usage: $0 username}"

echo "[*] Scan rapide de: $USERNAME"
echo ""

echo "=== SHERLOCK - Reseaux sociaux ==="
"$VENV/sherlock" "$USERNAME" --timeout 10 --print-found --no-color 2>/dev/null || echo "[!] sherlock a echoue"

echo ""
echo "=== MAIGRET - Recherche approfondie ==="
"$VENV/maigret" "$USERNAME" --timeout 10 --no-color 2>/dev/null || echo "[!] maigret a echoue"

echo ""
echo "[*] Scan termine pour $USERNAME"
