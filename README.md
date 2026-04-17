# WireGuard Android с VK TURN Proxy

[English version (README.en.md)](README.en.md)

Это специализированный форк официального клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android) с интегрированной поддержкой **VK TURN Proxy**.

Проект инкапсулирует трафик WireGuard в потоки DTLS/TURN через инфраструктуру VK Calls и WB Stream. В форке сохранены штатный UI WireGuard, OTA-обновления, расширенный TURN-статус в интерфейсе и дополнительная мета-передача для `proxy_v2_meta`.

## Важное предупреждение

**Данный проект создан исключительно в учебных и исследовательских целях.**

Использование инфраструктуры VK Calls (TURN-серверов) без явного разрешения со стороны правообладателя может нарушать Условия использования сервиса и правила платформы VK. Автор проекта не несет ответственности за любой ущерб или нарушение правил, возникшее в результате использования данного программного обеспечения. Проект демонстрирует техническую возможность интеграции протоколов и не предназначен для нецелевого использования ресурсов сторонних сервисов.

## Ключевые особенности

- **Нативная интеграция**: TURN-клиент встроен напрямую в `libwg-go.so` для максимальной производительности и минимального расхода заряда батареи.
- **Два режима авторизации**:
  - **VK Link** — получение учетных данных TURN через анонимные токены VK Calls.
  - **WB** — получение учетных данных TURN через WB Stream API.
- **Режимы протокола**:
  - **proxy_v2_meta** — наш основной режим по умолчанию, с передачей дополнительной меты и серверными webhook/script hooks.
  - **proxy_v2** — режим форка kiper292 без дополнительной меты.
  - **proxy_v1** — legacy-совместимый режим для старых серверов.
  - **wireguard** — прямой relay без DTLS.
- **Многопоточная балансировка**: параллельные DTLS-потоки, агрегация по Session ID и Round-Robin балансировка исходящего трафика.
- **VK captcha popup**: автоматическое решение капчи с fallback на WebView popup, если ручное подтверждение необходимо.
- **ОТА и статусы**: debug/release OTA, уведомления, и расширенный TURN-статус/ошибки в UI.
- **Кастомный DNS резолвер**: HTTP и WebSocket запросы проходят через встроенный DNS резолвер с защитой сокетов через VPN.
- **Оптимизация MTU**: автоматическая установка MTU в 1280 при использовании TURN для стабильной работы инкапсулированных пакетов.
- **Автоматический рестарт при смене сети**: TURN автоматически переподключается при переключении между WiFi и 4G/5G с защитой от частых перезапусков.
- **Быстрое восстановление сети**: сброс DNS и HTTP-соединений при смене сети для ускоренного переподключения.
- **Удобная настройка**: параметры TURN хранятся прямо в стандартных `.conf` файлах WireGuard в виде специальных комментариев-метаданных (`#@wgt:`).

## Благодарности

Этот проект построен на базе:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — основное приложение VPN и пользовательский интерфейс.
2. **[vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)** — автор идеи и вдохновитель проекта.
3. **[lionheart](https://github.com/jaykaiperson/lionheart)** — исходная реализация режима WB для получения TURN credentials.

> **Важно**: Для корректной работы этого клиента рекомендуется использовать серверную часть `proxy_v2_meta` из нашего форка [Yasich217/vk-turn-proxy](https://github.com/Yasich217/vk-turn-proxy) (база: [kiper292/vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy)).

## Сборка

```bash
# Требуется Go 1.25+ и Android NDK 29
$ git clone --recurse-submodules https://github.com/your-repo/wireguard-turn-android
$ cd wireguard-turn-android
$ ./gradlew assembleRelease
```

## Настройка

Вы можете включить прокси в редакторе туннеля. Настройки будут добавлены в секцию Peer вашей конфигурации:

```ini
[Peer]
PublicKey = <key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = false
#@wgt:IPPort = 1.2.3.4:56000
#@wgt:VKLink = https://vk.com/call/join/...
#@wgt:Mode = vk_link              # Режим авторизации: vk_link или wb
#@wgt:PeerType = proxy_v2_meta     # proxy_v2_meta | proxy_v2 | proxy_v1 | wireguard
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4           # Потоков на один кэш credentials

# Advanced settings (optional)
#@wgt:TurnIP = 155.212.199.166      # Переопределить IP TURN сервера
#@wgt:TurnPort = 19302              # Переопределить порт TURN сервера
#@wgt:WatchdogTimeout = 30          # Таймаут неактивности (сек, 0=отключен)
```

**Примечание:** Параметр `PeerType` определяет режим работы:
- `proxy_v2_meta` (по умолчанию) — DTLS с Session ID и дополнительной метой для серверных webhook/script hooks (сервер: [Yasich217/vk-turn-proxy](https://github.com/Yasich217/vk-turn-proxy))
- `proxy_v2` — DTLS с передачей Session ID для агрегации потоков
- `proxy_v1` — DTLS без Session ID handshake (сервер: [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy))
- `wireguard` — без DTLS, прямой relay (NoDTLS, для отладки или прямого подключения)

**Watchdog Timeout:** Параметр `WatchdogTimeout` активирует контроль неактивности для DTLS режима:
- `0` (по умолчанию) — watchdog отключен
- `≥5` — таймаут в секундах; если пакеты не получаются от TURN сервера в течение указанного времени, соединение переподключается
- Применяется только к режимам `proxy_v2_meta`, `proxy_v2` и `proxy_v1`

Для получения подробной технической информации см. [info/TURN_INTEGRATION_DETAILS.md](info/TURN_INTEGRATION_DETAILS.md).

## Donations / Поддержать разработчика

## Участие в проекте

Для перевода интерфейса используйте оригинальный [WireGuard Crowdin](https://crowdin.com/project/WireGuard). При обнаружении технических ошибок, связанных с интеграцией TURN, пожалуйста, создавайте Issue в этом репозитории.
