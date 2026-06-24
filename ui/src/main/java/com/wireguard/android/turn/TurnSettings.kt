/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import java.util.Locale

/**
 * Per-tunnel TURN proxy configuration.
 */
data class TurnSettings(
    val enabled: Boolean = false,
    val peer: String = "",
    val vkLink: String = DEFAULT_VK_CALL_LINK,
    val vkLinkOptions: List<String> = DEFAULT_VK_CALL_HASHES,
    val mode: String = "vk_link",
    val streams: Int = 4,
    val useUdp: Boolean = false,
    val localPort: Int = 9000,
    val turnIp: String = "",
    val turnPort: Int = 0,
    val peerType: String = "proxy_v2_meta",
    val streamsPerCred: Int = 4,
    val watchdogTimeout: Int = 0,
    val autoSwitchTurn: Boolean = true,
    val vkCredentialsProfile: String = "web_app",
    val vkCredentialsProfiles: List<String> = DEFAULT_VK_CREDENTIALS_PROFILES,
    val autoSwitchVkCredentials: Boolean = false,
    val streamStartDelayMs: Int = 1000,
    val startupTimeoutSec: Int = 75,
    val quotaBackoffSec: Int = 15,
    val captchaBackoffSec: Int = 120,
    val wrapKey: String = "",
) {
    fun toComments(): List<String> {
        val lines = mutableListOf(
            "",
            "# [Peer] TURN extensions",
            "#@wgt:EnableTURN = $enabled",
            "#@wgt:UseUDP = $useUdp",
            "#@wgt:IPPort = $peer",
            "#@wgt:VKLink = $vkLink",
            "#@wgt:VKCallHashes = ${vkLinkOptions.joinToString(",")}",
            "#@wgt:Mode = $mode",
            "#@wgt:StreamNum = $streams",
            "#@wgt:LocalPort = $localPort",
            "#@wgt:PeerType = $peerType",
            "#@wgt:StreamsPerCred = $streamsPerCred",
        )
        if (turnIp.isNotBlank()) lines.add("#@wgt:TurnIP = $turnIp")
        if (turnPort > 0) lines.add("#@wgt:TurnPort = $turnPort")
        if (watchdogTimeout > 0) lines.add("#@wgt:WatchdogTimeout = $watchdogTimeout")
        lines.add("#@wgt:VkCredProfile = $vkCredentialsProfile")
        lines.add("#@wgt:VkCredProfiles = ${vkCredentialsProfiles.joinToString(",")}")
        lines.add("#@wgt:AutoSwitchVKCreds = $autoSwitchVkCredentials")
        lines.add("#@wgt:StreamStartDelaySec = ${delaySecFromMs(streamStartDelayMs)}")
        lines.add("#@wgt:StartupTimeoutSec = $startupTimeoutSec")
        lines.add("#@wgt:QuotaBackoffSec = $quotaBackoffSec")
        lines.add("#@wgt:CaptchaBackoffSec = $captchaBackoffSec")
        if (wrapKey.isNotBlank()) lines.add("#@wgt:WrapKey = $wrapKey")
        if (peerType == "wireguard") lines.add("#@wgt:NoDTLS = true")
        lines.add("#@wgt:AutoSwitchTURN = $autoSwitchTurn")
        return lines
    }

    companion object {
        fun delaySecFromMs(delayMs: Int): Int {
            if (delayMs <= 0) return 0
            return ((delayMs + 999) / 1000).coerceIn(0, 5)
        }

        fun delayMsFromLegacyMs(delayMs: Int): Int = delaySecFromMs(delayMs) * 1000

        fun fromComments(comments: List<String>): TurnSettings? {
            var enabled = false
            var peer = ""
            var vkLink = DEFAULT_VK_CALL_LINK
            var vkLinkOptions = DEFAULT_VK_CALL_HASHES
            var mode = "vk_link"
            var streams = 4
            var useUdp = false
            var localPort = 9000
            var turnIp = ""
            var turnPort = 0
            var peerType: String? = null
            var noDtlsLegacy = false
            var streamsPerCred = 4
            var watchdogTimeout = 0
            var autoSwitchTurn = true
            var vkCredentialsProfile = "web_app"
            var vkCredentialsProfiles = DEFAULT_VK_CREDENTIALS_PROFILES
            var autoSwitchVkCredentials = false
            var streamStartDelayMs = 1000
            var startupTimeoutSec = 75
            var quotaBackoffSec = 15
            var captchaBackoffSec = 120
            var wrapKey = ""
            var foundAny = false

            for (line in comments) {
                if (!line.startsWith("#@wgt:")) continue
                foundAny = true
                val parts = line.substring(6).split("=", limit = 2)
                if (parts.size != 2) continue
                val key = parts[0].trim().lowercase(Locale.ENGLISH)
                val value = parts[1].trim()

                when (key) {
                    "enableturn" -> enabled = value.toBoolean()
                    "useudp" -> useUdp = value.toBoolean()
                    "ipport" -> peer = value
                    "vklink" -> vkLink = value
                    "vkcallhashes", "vkcallhashpool" -> vkLinkOptions = parseVkCallHashes(value)
                    "vklinks", "vklinkpool", "vkcalllinks" -> vkLinkOptions = parseVkLinkOptions(value)
                    "mode" -> mode = value
                    "streamnum" -> streams = value.toIntOrNull() ?: 4
                    "localport" -> localPort = value.toIntOrNull() ?: 9000
                    "turnip" -> turnIp = value
                    "turnport" -> turnPort = value.toIntOrNull() ?: 0
                    "peertype" -> peerType = value
                    "streamspercred" -> streamsPerCred = value.toIntOrNull() ?: 4
                    "watchdogtimeout" -> watchdogTimeout = value.toIntOrNull() ?: 0
                    "nodtls" -> noDtlsLegacy = value.toBoolean()
                    "autoswitchturn" -> autoSwitchTurn = value.toBoolean()
                    "vkcredprofile" -> vkCredentialsProfile = value
                    "vkcredprofiles", "vkcredentialsprofiles" -> vkCredentialsProfiles = parseVkCredentialProfiles(value)
                    "autoswitchvkcreds", "autoswitchvkcredentials" -> autoSwitchVkCredentials = value.toBoolean()
                    "streamstartdelaysec" -> streamStartDelayMs = (value.toIntOrNull() ?: 1) * 1000
                    "streamstartdelayms" -> streamStartDelayMs = delayMsFromLegacyMs(value.toIntOrNull() ?: 1000)
                    "startuptimeoutsec" -> startupTimeoutSec = value.toIntOrNull() ?: 75
                    "quotabackoffsec" -> quotaBackoffSec = value.toIntOrNull() ?: 15
                    "captchabackoffsec" -> captchaBackoffSec = value.toIntOrNull() ?: 120
                    "wrapkey" -> wrapKey = value
                }
            }

            if (peerType == null) {
                peerType = if (noDtlsLegacy) "wireguard" else "proxy_v2_meta"
            }

            return if (foundAny) {
                TurnSettings(
                    enabled = enabled,
                    peer = peer,
                    vkLink = vkLink,
                    vkLinkOptions = vkLinkOptions,
                    mode = mode,
                    streams = streams,
                    useUdp = useUdp,
                    localPort = localPort,
                    turnIp = turnIp,
                    turnPort = turnPort,
                    peerType = peerType,
                    streamsPerCred = streamsPerCred,
                    watchdogTimeout = watchdogTimeout,
                    autoSwitchTurn = autoSwitchTurn,
                    vkCredentialsProfile = vkCredentialsProfile,
                    vkCredentialsProfiles = vkCredentialsProfiles,
                    autoSwitchVkCredentials = autoSwitchVkCredentials,
                    streamStartDelayMs = streamStartDelayMs,
                    startupTimeoutSec = startupTimeoutSec,
                    quotaBackoffSec = quotaBackoffSec,
                    captchaBackoffSec = captchaBackoffSec,
                    wrapKey = wrapKey,
                )
            } else {
                null
            }
        }

        fun validate(settings: TurnSettings): TurnSettings {
            if (!settings.enabled) return settings

            require(settings.peer.isNotBlank()) { "TURN peer is empty" }
            if (settings.mode != "wb") {
                require(settings.vkLink.isNotBlank()) { "VK link is empty" }
                if (settings.autoSwitchVkCredentials) {
                    require(settings.vkLinkOptions.isNotEmpty()) { "VK call hashes list is empty" }
                    require(settings.vkCredentialsProfiles.isNotEmpty()) { "VK credentials profiles list is empty" }
                }
            }
            require(settings.streams in 1..100) { "Streams must be between 1 and 100" }
            require(settings.localPort in 1..65535) { "Local port must be between 1 and 65535" }
            require(settings.peerType in listOf("proxy_v2_meta", "proxy_v2", "proxy_v1", "wireguard")) {
                "Invalid peer type: ${settings.peerType}"
            }
            require(settings.streamsPerCred in 1..100) { "Streams per credentials must be between 1 and 100" }
            require(settings.vkCredentialsProfile in supportedVkCredentialProfiles()) {
                "Invalid VK credentials profile: ${settings.vkCredentialsProfile}"
            }
            if (settings.autoSwitchVkCredentials) {
                require(settings.vkCredentialsProfiles.all { it in supportedAutoSwitchVkCredentialProfiles() }) {
                    "Invalid VK credentials profiles: ${settings.vkCredentialsProfiles}"
                }
            }
            require(settings.streamStartDelayMs in 0..5000) { "Stream start delay must be 0..5 sec" }
            require(settings.startupTimeoutSec in 10..300) { "Startup timeout must be 10..300 sec" }
            require(settings.quotaBackoffSec in 1..600) { "Quota backoff must be 1..600 sec" }
            require(settings.captchaBackoffSec in 0..3600) { "Captcha backoff must be 0..3600 sec" }
            if (settings.wrapKey.isNotBlank()) {
                require(settings.wrapKey.matches(Regex("^[0-9a-fA-F]{64}$"))) {
                    "WRAP key must be 64 hex characters"
                }
                require(settings.peerType != "wireguard") { "WRAP requires a DTLS peer type" }
            }

            if (settings.turnPort != 0) {
                require(settings.turnPort in 1..65535) { "TURN port must be between 1 and 65535" }
            }
            if (settings.watchdogTimeout > 0) {
                require(settings.watchdogTimeout >= 5) {
                    "Watchdog timeout must be at least 5 seconds or 0 to disable"
                }
            }

            require(':' in settings.peer) { "TURN peer must be in host:port format" }
            return settings
        }

        const val DEFAULT_VK_CALL_LINK = "https://vk.com/call/join/AbVWoqNhisrbzjb9lmIbJhoKOmFW17wyNDdWl-hcnI0"

        val DEFAULT_VK_CALL_HASHES = listOf(
            "AbVWoqNhisrbzjb9lmIbJhoKOmFW17wyNDdWl-hcnI0",
            "ZJ83gYG45bKY18ABfqSmel0UO9owRrc9Tw5QZTPnTjU",
            "vrd2fAX1tzvsoHaPrW-93QNvxqk_MbQe86OtIASt-1M",
        )

        val DEFAULT_VK_CREDENTIALS_PROFILES = listOf(
            "web_app",
            "mvk_app",
            "official_android_app",
            "official_iphone_app",
        )

        fun normalizeVkCallHash(raw: String): String {
            val value = raw.trim()
            if (value.isEmpty()) return ""
            val afterPath = value.substringAfter("/call/join/", value)
            return afterPath
                .substringBefore('?')
                .substringBefore('#')
                .substringBefore('&')
                .trim()
        }

        fun parseVkCallHashes(raw: String): List<String> {
            val parsed = raw
                .split('\n', '\r', ',', ';', ' ', '\t')
                .map { normalizeVkCallHash(it) }
                .filter { it.isNotEmpty() }
                .distinct()
            return parsed.ifEmpty { DEFAULT_VK_CALL_HASHES }
        }

        fun parseVkLinkOptions(raw: String): List<String> = parseVkCallHashes(raw)

        fun parseVkCredentialProfiles(raw: String): List<String> {
            val supported = supportedAutoSwitchVkCredentialProfiles()
            val parsed = raw
                .split('\n', '\r', ',', ';', ' ', '\t')
                .map { it.trim().lowercase(Locale.ENGLISH) }
                .filter { it in supported }
                .distinct()
            return parsed.ifEmpty { DEFAULT_VK_CREDENTIALS_PROFILES }
        }

        fun supportedVkCredentialProfiles(): Set<String> = setOf(
            "web_app",
            "mvk_app",
            "web_video_app",
            "mvk_video_app",
            "vk_id_auth_app",
            "official_android_app",
            "official_iphone_app",
            "official_ipad_app",
            "official_windows_app",
            "official_windows_phone_app",
        )

        fun supportedAutoSwitchVkCredentialProfiles(): Set<String> = setOf(
            "web_app",
            "mvk_app",
            "web_video_app",
            "mvk_video_app",
            "vk_id_auth_app",
            "official_android_app",
            "official_iphone_app",
            "official_ipad_app",
            "official_windows_app",
        )
    }
}
