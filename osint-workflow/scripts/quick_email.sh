#!/bin/bash
# Scan rapide d'un email - Usage: ./quick_email.sh target@example.com
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/../venv/bin"
EMAIL="${1:?Usage: $0 email@example.com}"

echo "[*] Scan rapide de: $EMAIL"
echo ""

echo "=== HOLEHE - Comptes lies ==="
"$VENV/holehe" "$EMAIL" 2>/dev/null || echo "[!] holehe a echoue"

echo ""
echo "[*] Scan termine pour $EMAIL"
