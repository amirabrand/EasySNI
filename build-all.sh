#!/usr/bin/env bash
# ============================================================
#  V2RayEz - build for all platforms (run on macOS/Linux)
#  Output goes to ./dist/
#  Note: embedding the Windows .exe icon is done by build-all.bat
#  on Windows (via goversioninfo). This script builds plain binaries.
# ============================================================
set -e
cd "$(dirname "$0")"

APP=v2rayez
OUT=dist
mkdir -p "$OUT"
export GOTOOLCHAIN=local CGO_ENABLED=0
LD="-s -w"

echo "=== V2RayEz build-all ==="

build() { echo "  - $1/$2"; GOOS=$1 GOARCH=$2 go build -trimpath -ldflags "$LD" -o "$OUT/$3" .; }

build windows amd64 "$APP-windows-amd64.exe"
build windows arm64 "$APP-windows-arm64.exe"
build darwin  amd64 "$APP-macos-amd64"
build darwin  arm64 "$APP-macos-arm64"
build linux   amd64 "$APP-linux-amd64"
build linux   arm64 "$APP-linux-arm64"

echo "=== Done. Binaries are in $OUT/ ==="
ls -1 "$OUT"
