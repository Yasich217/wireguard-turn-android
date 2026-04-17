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
    val vkLink: String = "",
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
    val streamStartDelayMs: Int = 200,
    val startupTimeoutSec: Int = 75,
    val quotaBackoffSec: Int = 15,
) {
    fun toComments(): List<String> {
        val lines = mutableListOf(
            "",
            "# [Peer] TURN extensions",
            "#@wgt:EnableTURN = $enabled",
            "#@wgt:UseUDP = $useUdp",
            "#@wgt:IPPort = $peer",
            "#@wgt:VKLink = $vkLink",
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
        lines.add("#@wgt:StreamStartDelayMs = $streamStartDelayMs")
        lines.add("#@wgt:StartupTimeoutSec = $startupTimeoutSec")
        lines.add("#@wgt:QuotaBackoffSec = $quotaBackoffSec")
        if (peerType == "wireguard") lines.add("#@wgt:NoDTLS = true")
        lines.add("#@wgt:AutoSwitchTURN = $autoSwitchTurn")
        return lines
    }

    companion object {
        fun fromComments(comments: List<String>): TurnSettings? {
            var enabled = false
            var peer = ""
            var vkLink = ""
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
            var streamStartDelayMs = 200
            var startupTimeoutSec = 75
            var quotaBackoffSec = 15
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
                    "streamstartdelayms" -> streamStartDelayMs = value.toIntOrNull() ?: 200
                    "startuptimeoutsec" -> startupTimeoutSec = value.toIntOrNull() ?: 75
                    "quotabackoffsec" -> quotaBackoffSec = value.toIntOrNull() ?: 15
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
                    streamStartDelayMs = streamStartDelayMs,
                    startupTimeoutSec = startupTimeoutSec,
                    quotaBackoffSec = quotaBackoffSec,
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
            }
            require(settings.streams in 1..32) { "Streams must be between 1 and 32" }
            require(settings.localPort in 1..65535) { "Local port must be between 1 and 65535" }
            require(settings.peerType in listOf("proxy_v2_meta", "proxy_v2", "proxy_v1", "wireguard")) {
                "Invalid peer type: ${settings.peerType}"
            }
            require(settings.streamsPerCred in 1..32) { "Streams per credentials must be between 1 and 32" }
            require(settings.vkCredentialsProfile in supportedVkCredentialProfiles()) {
                "Invalid VK credentials profile: ${settings.vkCredentialsProfile}"
            }
            require(settings.streamStartDelayMs in 0..5000) { "Stream start delay must be 0..5000 ms" }
            require(settings.startupTimeoutSec in 10..300) { "Startup timeout must be 10..300 sec" }
            require(settings.quotaBackoffSec in 1..600) { "Quota backoff must be 1..600 sec" }

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

        fun supportedVkCredentialProfiles(): Set<String> = setOf(
            "web_app",
            "mvk_app",
            "web_video_app",
            "mvk_video_app",
            "vk_id_auth_app",
        )
    }
}
