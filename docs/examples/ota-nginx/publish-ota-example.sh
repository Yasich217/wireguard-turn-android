#!/usr/bin/env bash
set -euo pipefail

# Example usage:
#   ./publish-ota-example.sh release /path/to/ui-release.apk 529 2.2.4 /home/yaroslav.kazarin/Documents/nginx-server/data
#   ./publish-ota-example.sh debug   /path/to/ui-debug.apk   529 2.2.4-debug /home/yaroslav.kazarin/Documents/nginx-server/data

BUILD_TYPE="${1:?debug|release}"
APK_PATH="${2:?apk path}"
VERSION_CODE="${3:?version code}"
VERSION_NAME="${4:?version name}"
OTA_DATA_DIR="${5:?ota data dir}"

if [[ "$BUILD_TYPE" != "debug" && "$BUILD_TYPE" != "release" ]]; then
  echo "BUILD_TYPE must be debug or release"
  exit 1
fi

TARGET_DIR="${OTA_DATA_DIR}/${BUILD_TYPE}"
mkdir -p "$TARGET_DIR"

OTA_BASE_URL="${OTA_BASE_URL:-https://ota.example.com}"

if [[ "$BUILD_TYPE" == "debug" ]]; then
  APK_NAME="wg-turn-debug.apk"
  JSON_NAME="wg-turn-debug.json"
  APK_URL="${OTA_BASE_URL}/wg-turn/debug/latest.apk"
else
  APK_NAME="wg-turn-release.apk"
  JSON_NAME="wg-turn-release.json"
  APK_URL="${OTA_BASE_URL}/wg-turn/release/latest.apk"
fi

cp "$APK_PATH" "${TARGET_DIR}/${APK_NAME}"
SHA256="$(sha256sum "${TARGET_DIR}/${APK_NAME}" | awk '{print $1}')"

cat > "${TARGET_DIR}/${JSON_NAME}" <<EOF
{
  "version_code": ${VERSION_CODE},
  "version_name": "${VERSION_NAME}",
  "apk_url": "${APK_URL}",
  "sha256": "${SHA256}"
}
EOF

ln -sfn "${APK_NAME}" "${TARGET_DIR}/latest.apk"
ln -sfn "${JSON_NAME}" "${TARGET_DIR}/latest.json"

echo "Published ${BUILD_TYPE}: ${TARGET_DIR}/${APK_NAME}"
