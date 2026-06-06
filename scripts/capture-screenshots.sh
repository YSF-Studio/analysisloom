#!/usr/bin/env bash
# Capture AnalysisLoom screenshots for GitHub README.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "▶ Generating test fixtures (for docs paths)..."
bash "$ROOT/scripts/generate-test-fixtures.sh" 42

echo "▶ Capturing screenshots via Chrome headless..."
node "$ROOT/scripts/capture-screenshots-browser.mjs"

ls -la "$ROOT/screenshots/"
