#!/usr/bin/env bash
set -euo pipefail

if [ ! -d ".venv" ]; then
  bash scripts/setup.sh
fi

if ! .venv/bin/python -c "import flask" >/dev/null 2>&1; then
  bash scripts/setup.sh
fi

exec .venv/bin/python app.py
