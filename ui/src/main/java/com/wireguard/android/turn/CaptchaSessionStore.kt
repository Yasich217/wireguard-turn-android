/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.webkit.CookieManager
import android.webkit.WebStorage
import android.webkit.WebView
import com.wireguard.android.backend.TurnBackend
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

object CaptchaSessionStore {
    suspend fun clear(context: Context) {
        val appContext = context.applicationContext
        withContext(Dispatchers.Main.immediate) {
            suspendCancellableCoroutine { continuation ->
                CookieManager.getInstance().removeAllCookies {
                    CookieManager.getInstance().flush()
                    if (continuation.isActive) continuation.resume(Unit)
                }
            }
            WebStorage.getInstance().deleteAllData()
            runCatching {
                WebView(appContext).apply {
                    clearCache(true)
                    clearFormData()
                    clearHistory()
                    destroy()
                }
            }
        }
        VkCaptchaProfileStore.clear(appContext)
        CaptchaDebugTrace.clear(appContext)
        TurnBackend.wgTurnProxyClearSessions()
    }
}
