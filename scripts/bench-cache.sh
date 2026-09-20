#!/usr/bin/env bash
# Time --demo with an empty cache, a warm cache, and --no-cache.
# Cold and no-cache each make one Jev call per fixture batch (7 today).
# Usage: scripts/bench-cache.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/jev-logtriage-bench.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
DB="$WORK/answers.sqlite3"

run() {
  local label=$1
  shift
  echo "== ${label} =="
  TIMEFORMAT='real %R s'
  time uv run logtriage --demo --no-report "$@"
  echo
}

run "cold (empty cache)" --cache-db "$DB"
run "warm (same db)" --cache-db "$DB"
run "no-cache" --no-cache
