/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.util.Log
import com.wireguard.android.backend.TurnBackend
import org.json.JSONObject
import java.io.File
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object VkCaptchaProfileStore {
    private const val TAG = "WireGuard/VkCaptchaProfile"
    private const val FILE_NAME = "vk_profile.json"

    fun loadIntoNative(context: Context) {
        val json = loadJson(context) ?: return
        runCatching { TurnBackend.wgTurnProxySetCaptchaProfile(json) }
            .onFailure { Log.w(TAG, "Failed to load VK captcha profile into native", it) }
    }

    fun saveFromRequestBody(context: Context, requestBody: String?, userAgent: String?): Boolean {
        val params = parseForm(requestBody.orEmpty())
        val existing = loadJson(context)
            ?.let { runCatching { JSONObject(it) }.getOrNull() }
        val browserFp = params["browser_fp"].orEmpty().trim()
            .ifBlank { existing?.optString("BrowserFp").orEmpty().trim() }
        val deviceJson = params["device"].orEmpty().trim()
            .ifBlank { existing?.optString("DeviceJSON").orEmpty().trim() }
        if (browserFp.isBlank() && deviceJson.isBlank()) return false

        val ua = userAgent.orEmpty().trim().ifBlank {
            extractUserAgent(deviceJson)
        }.ifBlank {
            existing?.optJSONObject("Profile")?.optString("UserAgent").orEmpty().trim()
        }
        if (ua.isBlank()) return false

        val profile = JSONObject()
            .put("UserAgent", ua)
            .put("SecChUa", "")
            .put("SecChUaMobile", if (ua.contains("Mobile", ignoreCase = true)) "?1" else "?0")
            .put("SecChUaPlatform", if (ua.contains("Android", ignoreCase = true)) "\"Android\"" else "\"Windows\"")
        val payload = JSONObject()
            .put("Profile", profile)
            .put("DeviceJSON", deviceJson)
            .put("BrowserFp", browserFp)
            .toString()

        return runCatching {
            profileFile(context).writeText(payload, StandardCharsets.UTF_8)
            TurnBackend.wgTurnProxySetCaptchaProfile(payload)
            Log.d(TAG, "Saved VK captcha browser profile browserFp=${browserFp.take(8)} ua=${ua.take(80)}")
            true
        }.getOrElse {
            Log.w(TAG, "Failed to save VK captcha browser profile", it)
            false
        }
    }

    private fun loadJson(context: Context): String? {
        return runCatching {
            profileFile(context).takeIf { it.isFile }?.readText(StandardCharsets.UTF_8)?.trim()?.takeIf { it.isNotBlank() }
        }.getOrElse {
            Log.w(TAG, "Failed to read VK captcha profile", it)
            null
        }
    }

    private fun profileFile(context: Context): File {
        return File(context.filesDir, FILE_NAME)
    }

    private fun parseForm(body: String): Map<String, String> {
        if (body.isBlank()) return emptyMap()
        return body.split('&')
            .mapNotNull { part ->
                val key = part.substringBefore('=', "").takeIf { it.isNotBlank() } ?: return@mapNotNull null
                val value = part.substringAfter('=', "")
                decode(key) to decode(value)
            }
            .toMap()
    }

    private fun decode(value: String): String {
        return runCatching { URLDecoder.decode(value, StandardCharsets.UTF_8.name()) }.getOrDefault(value)
    }

    private fun extractUserAgent(deviceJson: String): String {
        if (deviceJson.isBlank()) return ""
        return runCatching { JSONObject(deviceJson).optString("userAgent").trim() }.getOrDefault("")
    }
}
