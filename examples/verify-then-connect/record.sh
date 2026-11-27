#!/usr/bin/env bash
# Records the verify-then-connect demo to demo.cast (asciicast v3) and renders
# demo.gif for the README. Needs asciinema (3.x) and agg on PATH:
#   brew install asciinema agg
#
# Run from the repository root:  ./examples/verify-then-connect/record.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACE="${PACE:-0.45s}"
COLS="${COLS:-104}"
ROWS="${ROWS:-17}"
BIN="$(mktemp -d)"
trap 'rm -rf "${BIN}"' EXIT

go build -o "${BIN}/verify-then-connect" ./examples/verify-then-connect

# The binary is found via PATH so the cast header records a clean command line
# rather than a temporary build path.
PATH="${BIN}:${PATH}" asciinema rec --headless --overwrite --quiet \
  --window-size "${COLS}x${ROWS}" \
  --title "ANS: verify, then connect" \
  --command "verify-then-connect --pace ${PACE}" \
  "${DIR}/demo.cast"

# bg, fg, then the 16 ANSI colors: dark slate with mint accents.
THEME="10181a,f2f7f7,161c1f,ff6b6b,3ddc84,ffb000,58a6ff,bc8cff,1bdbdb,c9d1d9,6e8188,ff8a8a,5ee89a,ffc53d,79c0ff,d2a8ff,5ff0f0,ffffff"

agg --quiet \
  --theme "${THEME}" \
  --font-family "JetBrains Mono,Menlo,DejaVu Sans Mono" \
  --font-size 14 \
  --line-height 1.3 \
  --fps-cap 15 \
  --idle-time-limit 3 \
  --last-frame-duration 4 \
  "${DIR}/demo.cast" "${DIR}/demo.gif"

ls -la "${DIR}/demo.cast" "${DIR}/demo.gif"
