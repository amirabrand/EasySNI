#!/usr/bin/env bash
# ============================================================
#  V2RayEz - build for all platforms (macOS/Linux)
#  Output goes to ./dist/
#
#  Optional build tags (extra features):
#    ./build-all.sh                 # standard
#    ./build-all.sh psiphon         # with Psiphon  (fetches deps)
#    ./build-all.sh livekit         # with LiveKit  (fetches deps)
#    ./build-all.sh "psiphon livekit"   # all tags
#  (or set TAGS="psiphon livekit" ./build-all.sh)
# ============================================================
set -e
cd "$(dirname "$0")"

APP=v2rayez
OUT=dist
mkdir -p "$OUT"
export GOTOOLCHAIN=local CGO_ENABLED=0
LD="-s -w"

# tags from $1 or $TAGS
TAGS="${1:-${TAGS:-}}"

echo "=== V2RayEz build-all ==="
if [ -n "$TAGS" ]; then
  echo "Build tags: $TAGS"
  echo "Fetching tag dependencies (needs internet)..."
  case "$TAGS" in *psiphon*)
    echo "  [!] Embedded Psiphon is NOT fetchable with 'go get' (local-path replace,"
    echo "      forked quic-go/utls, needs Go 1.26+). See PSIPHON.md."
    echo "      Recommended: use the app's 'Start Psiphon over MITM' button and point"
    echo "      the Psiphon APP's upstream proxy at it. Continuing without psiphon tag..."
    TAGS="$(echo "$TAGS" | sed 's/psiphon//g' | xargs)"
    ;;
  esac
  case "$TAGS" in *livekit*) echo "  - livekit server-sdk";   go get github.com/livekit/server-sdk-go/v2@latest ;; esac
  go mod tidy
  if [ -n "$TAGS" ]; then TAGFLAG=(-tags "$TAGS"); else TAGFLAG=(); fi
else
  echo "Build tags: (none - standard build)"
  TAGFLAG=()
fi

build() {
  echo "  - $1/$2"
  GOOS=$1 GOARCH=$2 go build -trimpath "${TAGFLAG[@]}" -ldflags "$LD" -o "$OUT/$3" .
}

build windows amd64 "$APP-windows-amd64.exe"
build windows arm64 "$APP-windows-arm64.exe"
build darwin  amd64 "$APP-macos-amd64"
build darwin  arm64 "$APP-macos-arm64"
build linux   amd64 "$APP-linux-amd64"
build linux   arm64 "$APP-linux-arm64"

echo "=== Done. Binaries are in $OUT/ ==="
ls -1 "$OUT"
echo
echo "Tip: build manually with tags BEFORE the dot:  go build -tags psiphon ."
