#!/usr/bin/env bash
# Launch the native blackbar analyzer on :5002 (the default PRESIDIO_ANALYZER_URL).
# Loads the spaCy models once and serves POST /analyze. Set BLACKBAR_LANGUAGES /
# BLACKBAR_MODEL_SIZE to the same values used in setup.sh.
#
# Binds 127.0.0.1 by default (this serves PII; keep it off the LAN). Override
# with BLACKBAR_BIND_HOST=0.0.0.0 only if you really need remote access.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${BLACKBAR_VENV:-$HOME/.local/share/blackbar/presidio-venv}"

export PORT="${PORT:-5002}"
export BLACKBAR_BIND_HOST="${BLACKBAR_BIND_HOST:-127.0.0.1}"
export BLACKBAR_LANGUAGES="${BLACKBAR_LANGUAGES:-en,es,fr,de,it,pt}"
export BLACKBAR_MODEL_SIZE="${BLACKBAR_MODEL_SIZE:-md}"

exec "$VENV/bin/python" "$HERE/analyzer_service.py"
