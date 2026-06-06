#!/usr/bin/env bash
# Package AnalysisLoom installers + portable archives for the current platform.
# Run after: cd packages/analysisloom && npm run tauri build
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/packages/analysisloom"
TAURI_DIR="$APP_DIR/src-tauri"
BUNDLE_DIR="$TAURI_DIR/target/release/bundle"
OUT_DIR="${1:-$ROOT/dist/releases}"
VERSION="$(node -p "require('$APP_DIR/src-tauri/tauri.conf.json').version" 2>/dev/null || echo "0.1.0")"
PRODUCT="AnalysisLoom"
STAMP="${PRODUCT}-${VERSION}"

mkdir -p "$OUT_DIR"

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH_TAG="x64" ;;
  aarch64|arm64) ARCH_TAG="arm64" ;;
  *) ARCH_TAG="$ARCH" ;;
esac

echo "📦 Packaging $STAMP ($OS / $ARCH_TAG) → $OUT_DIR"

copy_if_exists() {
  local pattern="$1"
  local dest_name="$2"
  shopt -s nullglob
  local files=($pattern)
  shopt -u nullglob
  if [ ${#files[@]} -eq 0 ]; then
    echo "  ⚠ skip (not found): $pattern"
    return 0
  fi
  for f in "${files[@]}"; do
    cp "$f" "$OUT_DIR/$dest_name"
    echo "  ✅ $dest_name"
  done
}

package_linux() {
  echo "── Linux installers ──"
  copy_if_exists "$BUNDLE_DIR/deb/${PRODUCT}_"*.deb "$STAMP-linux-${ARCH_TAG}.deb"
  copy_if_exists "$BUNDLE_DIR/deb/${PRODUCT,,}_"*.deb "$STAMP-linux-${ARCH_TAG}.deb"
  copy_if_exists "$BUNDLE_DIR/rpm/${PRODUCT}-"*.rpm "$STAMP-linux-${ARCH_TAG}.rpm"

  echo "── Linux portable (AppImage) ──"
  copy_if_exists "$BUNDLE_DIR/appimage/${PRODUCT}_"*.AppImage "$STAMP-linux-${ARCH_TAG}-portable.AppImage"
  copy_if_exists "$BUNDLE_DIR/appimage/${PRODUCT}-"*.AppImage "$STAMP-linux-${ARCH_TAG}-portable.AppImage"

  local BIN="$TAURI_DIR/target/release/analysisloom"
  if [ -f "$BIN" ] && [ ! -f "$OUT_DIR/$STAMP-linux-${ARCH_TAG}-portable.AppImage" ]; then
    local PORT_DIR="$OUT_DIR/.portable-linux-$$"
    mkdir -p "$PORT_DIR/$PRODUCT"
    cp "$BIN" "$PORT_DIR/$PRODUCT/"
    cp "$TAURI_DIR/icons/icon.png" "$PORT_DIR/$PRODUCT/" 2>/dev/null || true
    cat > "$PORT_DIR/$PRODUCT/README-portable.txt" <<EOF
AnalysisLoom ${VERSION} — Linux Portable
Run: ./analysisloom
Requires: libwebkit2gtk-4.1, libayatana-appindicator3
EOF
    (cd "$PORT_DIR" && tar -czf "$OUT_DIR/$STAMP-linux-${ARCH_TAG}-portable.tar.gz" "$PRODUCT")
    rm -rf "$PORT_DIR"
    echo "  ✅ $STAMP-linux-${ARCH_TAG}-portable.tar.gz"
  fi
}

package_macos() {
  echo "── macOS installer ──"
  copy_if_exists "$BUNDLE_DIR/dmg/${PRODUCT}_"*.dmg "$STAMP-macos-${ARCH_TAG}.dmg"
  copy_if_exists "$BUNDLE_DIR/dmg/${PRODUCT}-"*.dmg "$STAMP-macos-${ARCH_TAG}.dmg"

  echo "── macOS portable (.app zip) ──"
  local APP_PATH=""
  shopt -s nullglob
  local apps=("$BUNDLE_DIR/macos/$PRODUCT.app")
  shopt -u nullglob
  if [ -d "${apps[0]:-}" ]; then
    APP_PATH="${apps[0]}"
  fi
  if [ -n "$APP_PATH" ]; then
    (cd "$(dirname "$APP_PATH")" && zip -qr "$OUT_DIR/$STAMP-macos-${ARCH_TAG}-portable.zip" "$(basename "$APP_PATH")")
    echo "  ✅ $STAMP-macos-${ARCH_TAG}-portable.zip"
  else
    echo "  ⚠ skip: $BUNDLE_DIR/macos/$PRODUCT.app"
  fi
}

package_windows() {
  echo "── Windows installers ──"
  copy_if_exists "$BUNDLE_DIR/msi/${PRODUCT}_"*.msi "$STAMP-windows-${ARCH_TAG}.msi"
  copy_if_exists "$BUNDLE_DIR/msi/${PRODUCT}-"*.msi "$STAMP-windows-${ARCH_TAG}.msi"
  copy_if_exists "$BUNDLE_DIR/nsis/${PRODUCT}_"*.exe "$STAMP-windows-${ARCH_TAG}-setup.exe"
  copy_if_exists "$BUNDLE_DIR/nsis/${PRODUCT}-"*.exe "$STAMP-windows-${ARCH_TAG}-setup.exe"

  echo "── Windows portable (zip) ──"
  local RELEASE_DIR="$TAURI_DIR/target/release"
  local EXE=""
  shopt -s nullglob
  for candidate in "$RELEASE_DIR/$PRODUCT.exe" "$RELEASE_DIR/analysisloom.exe"; do
    if [ -f "$candidate" ]; then EXE="$candidate"; break; fi
  done
  shopt -u nullglob
  if [ -n "$EXE" ]; then
    local PORT_DIR="$OUT_DIR/.portable-win-$$"
    mkdir -p "$PORT_DIR/$PRODUCT"
    cp "$EXE" "$PORT_DIR/$PRODUCT/"
    shopt -s nullglob
    for dll in "$RELEASE_DIR"/*.dll "$RELEASE_DIR/resources" "$RELEASE_DIR/data"; do
      [ -e "$dll" ] && cp -r "$dll" "$PORT_DIR/$PRODUCT/" 2>/dev/null || true
    done
    shopt -u nullglob
    cat > "$PORT_DIR/$PRODUCT/README-portable.txt" <<EOF
AnalysisLoom ${VERSION} — Windows Portable
Run: ${PRODUCT}.exe
Requires: WebView2 Runtime (pre-installed on Windows 10/11)
EOF
    (cd "$PORT_DIR" && zip -qr "$OUT_DIR/$STAMP-windows-${ARCH_TAG}-portable.zip" "$PRODUCT")
    rm -rf "$PORT_DIR"
    echo "  ✅ $STAMP-windows-${ARCH_TAG}-portable.zip"
  else
    echo "  ⚠ skip: Windows executable not found in $RELEASE_DIR"
  fi
}

case "$OS" in
  Linux) package_linux ;;
  Darwin) package_macos ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) package_windows ;;
  *) echo "Unknown OS: $OS"; exit 1 ;;
esac

echo ""
echo "Done. Artifacts in $OUT_DIR:"
ls -lh "$OUT_DIR" | grep "$STAMP" || ls -lh "$OUT_DIR"
