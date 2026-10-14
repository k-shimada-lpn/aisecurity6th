#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
if command -v py >/dev/null 2>&1; then
    py -m unittest discover -s tests -v
elif command -v python3 >/dev/null 2>&1; then
    python3 -m unittest discover -s tests -v
else
    echo "Python 3 is required to run the tests." >&2
    exit 1
fi
