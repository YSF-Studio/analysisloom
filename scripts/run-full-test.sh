#!/usr/bin/env bash
# Full test suite: fixtures, integration, unit tests, frontend build, GUI smoke
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "═══════════════════════════════════════════"
echo " AnalysisLoom — Full Test Suite"
echo "═══════════════════════════════════════════"

echo ""
echo "▶ 1/5 Generate random test fixtures"
mkdir -p test-fixtures
cd packages/analysisloom/src-tauri
cargo run --example export_fixtures -- "$ROOT/test-fixtures" "$(date +%s)"
cd "$ROOT"
ls -la test-fixtures/

echo ""
echo "▶ 2/5 Rust unit tests"
cd packages/analysisloom/src-tauri
cargo test --lib -- --nocapture
cd "$ROOT"

echo ""
echo "▶ 3/5 Full integration test (all commands + random fixtures)"
cd packages/analysisloom/src-tauri
cargo test --test full_integration -- --nocapture
cd "$ROOT"

echo ""
echo "▶ 4/5 Frontend production build"
npm run build:analysisloom

echo ""
echo "▶ 5/5 GUI smoke test"
node scripts/smoke-gui.mjs

echo ""
echo "═══════════════════════════════════════════"
echo " ✅ ALL TESTS PASSED"
echo "═══════════════════════════════════════════"
echo " Fixtures at: $ROOT/test-fixtures/"
echo " Use: npm run dev:analysisloom"
echo "   → Add Image: test-fixtures/random_ntfs.dd"
echo "   → Open .db:  test-fixtures/messages.db"
