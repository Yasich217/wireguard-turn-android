#!/usr/bin/env bash
set -euo pipefail

VARIANT="${1:-both}"
IMAGE_NAME="${IMAGE_NAME:-wgturn-android-builder:latest}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORCE_REBUILD="${FORCE_REBUILD:-0}"
DOCKER_PROJECT_DIR="${DOCKER_PROJECT_DIR:-}"
OTA_ENV_VARS=(
  UPDATE_CHANNEL
  OTA_RELEASE_META_URL
  OTA_DEBUG_META_URL
  OTA_PINNED_CA_ENABLED
  OTA_PINNED_CA_RES
  GITHUB_RELEASE_META_URL
  GITHUB_DEBUG_META_URL
  DONATIONS_URL
)
DOCKER_ENV_ARGS=()

for var_name in "${OTA_ENV_VARS[@]}"; do
  if [[ -v "$var_name" ]]; then
    DOCKER_ENV_ARGS+=(--env "$var_name")
  fi
done

if [[ -z "$DOCKER_PROJECT_DIR" ]]; then
  DOCKER_PROJECT_DIR="$PROJECT_DIR"
  if [[ -n "${HOSTNAME:-}" ]] && docker inspect "$HOSTNAME" >/dev/null 2>&1; then
    best_container_path=""
    while IFS=$'\t' read -r host_path container_path; do
      if [[ "$PROJECT_DIR" == "$container_path" || "$PROJECT_DIR" == "$container_path/"* ]]; then
        if (( ${#container_path} > ${#best_container_path} )); then
          best_container_path="$container_path"
          DOCKER_PROJECT_DIR="${host_path}${PROJECT_DIR#"$container_path"}"
        fi
      fi
    done < <(docker inspect "$HOSTNAME" --format '{{range .Mounts}}{{printf "%s\t%s\n" .Source .Destination}}{{end}}')
  fi
fi

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
  "${DOCKER_ENV_ARGS[@]}" \
  -v "$DOCKER_PROJECT_DIR:/workspace" \
  -w /workspace \
  "$IMAGE_NAME" \
  bash -lc "./gradlew --no-daemon $GRADLE_TASKS"
