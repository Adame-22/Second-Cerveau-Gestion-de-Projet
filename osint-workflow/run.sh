#!/bin/bash
# Point d'entree principal du workflow OSINT
# Usage:
#   ./run.sh --email target@email.com
#   ./run.sh --username pseudo123
#   ./run.sh --email target@email.com --username pseudo123 --nom "Jean Dupont"
#   ./run.sh --email target@email.com --username pseudo123 --phone +33612345678 --nom "Jean Dupont"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/scripts/osint_runner.py" "$@"
