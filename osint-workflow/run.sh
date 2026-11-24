#!/bin/bash
# Point d'entree principal du workflow OSINT
# Usage:
#   ./run.sh -m MANDAT-001 --email target@email.com
#   ./run.sh -m MANDAT-001 --email target@email.com --username pseudo123 --nom "Jean Dupont"
#   ./run.sh -m MANDAT-001 -e target@email.com -u pseudo123 -p +33612345678 -n "Jean Dupont" --pdf
#   ./run.sh -m MANDAT-001 -e target@email.com --json-only --quiet
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "[!] venv introuvable. Creation automatique..."
    python3 -m venv "$SCRIPT_DIR/venv"
    "$SCRIPT_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null || true
fi

source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/scripts/osint_runner.py" "$@"
