#!/usr/bin/env bash
set -euo pipefail

VARIANT="${1:-both}"
IMAGE_NAME="${IMAGE_NAME:-wgturn-android-builder:latest}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORCE_REBUILD="${FORCE_REBUILD:-0}"

case "$VARIANT" in
  debug)
    GRADLE_TASKS="assembleDebug"
    ;;
  release)
    GRADLE_TASKS="assembleRelease"
    ;;
  both)
    GRADLE_TASKS="assembleDebug assembleRelease"
    ;;
  *)
    echo "Usage: $0 [debug|release|both]"
    exit 1
    ;;
esac

if [[ "$FORCE_REBUILD" == "1" ]] || ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  docker build -f "$PROJECT_DIR/Dockerfile.android" -t "$IMAGE_NAME" "$PROJECT_DIR"
fi

# Ensure native tool sources from submodules are present before mounting into container.
git -C "$PROJECT_DIR" submodule sync --recursive
git -C "$PROJECT_DIR" submodule update --init --recursive

if [[ ! -f "$PROJECT_DIR/tunnel/tools/wireguard-tools/src/wg-quick/android.c" ]]; then
  rm -rf "$PROJECT_DIR/tunnel/tools/wireguard-tools"
  git clone --depth 1 https://github.com/WireGuard/wireguard-tools "$PROJECT_DIR/tunnel/tools/wireguard-tools"
fi

mkdir -p \
  "$PROJECT_DIR/.gradle/home/.android" \
  "$PROJECT_DIR/.gradle/xdg-cache" \
  "$PROJECT_DIR/.gradle/go"
touch "$PROJECT_DIR/.gradle/home/.android/repositories.cfg"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/workspace/.gradle/home \
  -e GRADLE_USER_HOME=/workspace/.gradle \
  -e XDG_CACHE_HOME=/workspace/.gradle/xdg-cache \
  -e GOPATH=/workspace/.gradle/go \
  -v "$PROJECT_DIR:/workspace" \
  -w /workspace \
  "$IMAGE_NAME" \
  bash -lc "./gradlew --no-daemon $GRADLE_TASKS"
