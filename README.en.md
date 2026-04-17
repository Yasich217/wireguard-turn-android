# WireGuard Android with VK TURN Proxy

This is a specialized fork of the official [WireGuard Android](https://git.zx2c4.com/wireguard-android) client with integrated support for **VK TURN Proxy**.

It encapsulates WireGuard traffic inside DTLS/TURN streams via VK Calls and WB Stream. This fork keeps the stock WireGuard UI, OTA updates, extended TURN status in the interface, and the additional metadata path used by `proxy_v2_meta`.

## Important Disclaimer

**This project is created solely for educational and research purposes.**

Unauthorized use of the VK Calls infrastructure (TURN servers) without explicit permission from the rights holder may violate the Terms of Service and VK platform rules. The project author is not responsible for any damage or policy violations resulting from the use of this software. This project serves as a demonstration of protocol integration technical feasibility and is not intended for the misuse of third-party service resources.

## Key Features

- **Native Integration**: The TURN client is integrated directly into `libwg-go.so` for maximum performance and minimal battery impact.
- **Two Authentication Modes**:
  - **VK Link** — Automated retrieval of TURN credentials via VK Calls anonymous tokens.
  - **WB** — Automated retrieval of TURN credentials via WB Stream API.
- **Protocol Modes**:
  - **proxy_v2_meta** — our default mode, with extra metadata and server-side webhook/script hooks.
  - **proxy_v2** — Session ID based DTLS mode from the fork.
  - **proxy_v1** — legacy DTLS mode for older servers.
  - **wireguard** — direct relay without DTLS.
- **Multi-Stream Load Balancing**: parallel DTLS streams, Session ID aggregation, and round-robin outbound balancing.
- **VK captcha popup**: automatic captcha solving with a WebView popup fallback when manual confirmation is required.
- **OTA and status UI**: debug/release OTA, notifications, and extended TURN runtime status/errors in the interface.
- **Custom DNS Resolver**: all HTTP and WebSocket requests go through a built-in DNS resolver with socket protection via VPN.
- **MTU Optimization**: automatic MTU adjustment to 1280 when using TURN to ensure encapsulated packets fit standard network limits.
- **Auto-Reconnect on Network Change**: automatic TURN restart when switching between WiFi and 4G/5G with debounce protection.
- **Fast Network Recovery**: DNS and HTTP connection reset on network change for quick reconnection.
- **Seamless Configuration**: TURN settings are stored directly inside standard WireGuard `.conf` files as special metadata comments (`#@wgt:`).

## Technical Credits

This project is built upon the foundations laid by:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — The core VPN application and user interface.
2. **[vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)** — the author of the original idea and inspiration for this project.
3. **[lionheart](https://github.com/jaykaiperson/lionheart)** — The original WB mode implementation for TURN credentials retrieval.

> **Important**: For correct client operation, it is recommended to use the `proxy_v2_meta` server-side implementation from our fork [Yasich217/vk-turn-proxy](https://github.com/Yasich217/vk-turn-proxy) (based on [kiper292/vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy)).

## Building

```bash
# Requires Go 1.25+ and Android NDK 29
$ git clone --recurse-submodules https://github.com/your-repo/wireguard-turn-android
$ cd wireguard-turn-android
$ ./gradlew assembleRelease
```

## Configuration

You can enable the proxy in the Tunnel Editor. The settings are appended to the Peer section of your configuration:

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
#@wgt:Mode = vk_link              # Auth mode: vk_link or wb
#@wgt:PeerType = proxy_v2_meta     # proxy_v2_meta | proxy_v2 | proxy_v1 | wireguard
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4           # Streams per credentials cache

# Advanced settings (optional)
#@wgt:TurnIP = 155.212.199.166      # Override TURN server IP
#@wgt:TurnPort = 19302              # Override TURN server port
#@wgt:WatchdogTimeout = 30          # Inactivity timeout (sec, 0=disabled)
```

**Note:** The `PeerType` parameter determines the operating mode:
- `proxy_v2_meta` (default) — DTLS with Session ID transmission plus additional metadata for server-side webhooks/scripts (server: [Yasich217/vk-turn-proxy](https://github.com/Yasich217/vk-turn-proxy))
- `proxy_v2` — DTLS with Session ID transmission for stream aggregation
- `proxy_v1` — DTLS without Session ID handshake (server: [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy))
- `wireguard` — no DTLS, direct relay (NoDTLS, for debugging or direct connection)

**Watchdog Timeout:** The `WatchdogTimeout` parameter enables inactivity monitoring for DTLS mode:
- `0` (default) — watchdog disabled
- `≥5` — timeout in seconds; if no packets are received from the TURN server within this time, the connection is re-established
- Applies only to `proxy_v2_meta`, `proxy_v2`, and `proxy_v1` modes

For more technical details, see [info/TURN_INTEGRATION_DETAILS.md](info/TURN_INTEGRATION_DETAILS.md).

## Donations

## Contributing

For UI translations, please refer to the original [WireGuard Crowdin](https://crowdin.com/project/WireGuard). For technical bugs related to the TURN integration, please open an issue in this repository.
