# OTA nginx Example

## Структура

```text
nginx-server/
  docker-compose.yml
  nginx.conf
  certs/
    ota.example.com.fullchain.pem
    ota.example.com.key
    ca-chain.pem
  data/
    debug/
      wg-turn-debug.apk
      wg-turn-debug.json
      latest.apk -> wg-turn-debug.apk
      latest.json -> wg-turn-debug.json
    release/
      wg-turn-release.apk
      wg-turn-release.json
      latest.apk -> wg-turn-release.apk
      latest.json -> wg-turn-release.json
```

`ota.example.com.fullchain.pem` должен содержать leaf + intermediate цепочку.

## Endpoints

- `https://ota.example.com/wg-turn-debug.json`
- `https://ota.example.com/wg-turn-release.json`
- `https://ota.example.com/wg-turn/debug/latest.json`
- `https://ota.example.com/wg-turn/release/latest.json`

JSON формат:

```json
{
  "version_code": 529,
  "version_name": "2.2.4",
  "apk_url": "https://ota.example.com/wg-turn/release/latest.apk",
  "sha256": "..."
}
```

## Build-time OTA config

Клиент читает OTA конфиг через `BuildConfig` поля, которые можно задать через env:

- `OTA_RELEASE_META_URL`
- `OTA_DEBUG_META_URL`
- `OTA_PINNED_CA_ENABLED` (`true`/`false`)
- `OTA_PINNED_CA_RES` (имя ресурса в `res/raw`, по умолчанию `ota_root_ca`)

Для GitHub Release обычно используется:

- `OTA_RELEASE_META_URL=https://github.com/<owner>/<repo>/releases/latest/download/ota-release.json`
- `OTA_PINNED_CA_ENABLED=false`

Для локальной/внутренней OTA-сети можно включить pinning и положить свой CA в `res/raw`.
