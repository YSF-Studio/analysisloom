#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED="${1:-42}"
mkdir -p "$ROOT/test-fixtures"
cd "$ROOT/packages/analysisloom/src-tauri"
cargo run --example export_fixtures -- "$ROOT/test-fixtures" "$SEED"
echo "Fixtures ready in $ROOT/test-fixtures/"
