#!/usr/bin/env sh
set -eu
PYTHON_BIN="${PYTHON:-python3}"
exec "$PYTHON_BIN" "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/tools/allvm.py" "$@"
