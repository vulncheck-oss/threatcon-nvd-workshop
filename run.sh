#!/bin/sh
# NVD Switch Lab launcher — macOS / Linux.
# Double-click or run ./run.sh . Passes any arguments through to lab.py.
cd "$(dirname "$0")" || exit 1

for PY in python3 python; do
    if command -v "$PY" >/dev/null 2>&1; then
        if "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
            exec "$PY" lab.py "${@:-doctor}"
        fi
    fi
done

cat <<'EOF'
Python 3.8 or newer was not found on this machine.

  macOS  : brew install python3     (or install from https://python.org/downloads)
  Linux  : sudo apt install python3 / sudo dnf install python3
EOF
exit 1
