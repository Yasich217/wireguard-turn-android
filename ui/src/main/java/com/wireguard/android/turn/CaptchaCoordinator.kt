/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Log
import com.wireguard.android.Application
import com.wireguard.android.activity.CaptchaActivity
import java.lang.ref.WeakReference
import java.util.LinkedHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

object CaptchaCoordinator {
    private const val CAPTCHA_TIMEOUT_MS = 3 * 60 * 1000L

    private data class PendingCaptcha(
        val cacheId: Int,
        val redirectUri: String,
        val createdAtElapsed: Long,
        val future: CompletableFuture<String>,
        var activityVisible: Boolean = false,
        var autoOpenSuppressed: Boolean = false,
    )

    private val lock = Any()
    private val pending = LinkedHashMap<Int, PendingCaptcha>()
    @Volatile private var activeActivityRef: WeakReference<CaptchaActivity>? = null
    @Volatile private var terminalFailure = false
    @Volatile private var acceptingRequests = false

    fun beginAttempt(clearFailureState: Boolean = false) {
        Log.d(TAG, "beginAttempt clearFailureState=$clearFailureState")
        closeActiveActivity()
        val entries = synchronized(lock) {
            if (clearFailureState) {
                terminalFailure = false
            }
            acceptingRequests = true
            val copy = pending.values.toList()
            pending.clear()
            copy
        }
        entries.forEach { it.future.complete("") }
        notifyPendingStateChanged()
        updateNotifications(alert = false)
    }

    fun stopAttempt(clearFailureState: Boolean = false) {
        Log.d(TAG, "stopAttempt clearFailureState=$clearFailureState")
        closeActiveActivity()
        val entries = synchronized(lock) {
            if (clearFailureState) {
                terminalFailure = false
            }
            acceptingRequests = false
            val copy = pending.values.toList()
            pending.clear()
            copy
        }
        entries.forEach { it.future.complete("") }
        notifyPendingStateChanged()
        updateNotifications(alert = false)
    }

    fun blockForFailure() {
        Log.d(TAG, "blockForFailure")
        closeActiveActivity()
        val entries = synchronized(lock) {
            terminalFailure = true
            acceptingRequests = false
            val copy = pending.values.toList()
            pending.clear()
            copy
        }
        entries.forEach { it.future.complete("") }
        notifyPendingStateChanged()
        updateNotifications(alert = false)
    }

    fun resetFailureState() {
        synchronized(lock) {
            terminalFailure = false
        }
    }

    fun isPending(cacheId: Int): Boolean = synchronized(lock) {
        pending.containsKey(cacheId)
    }

    fun isTerminalFailureActive(): Boolean = terminalFailure

    private fun isVisibleActivityPresent(): Boolean {
        val activity = activeActivityRef?.get() ?: return false
        return !activity.isFinishing && !activity.isDestroyed
    }

    fun registerActivity(activity: CaptchaActivity) {
        activeActivityRef = WeakReference(activity)
    }

    fun unregisterActivity(activity: CaptchaActivity) {
        val current = activeActivityRef?.get()
        if (current === activity) {
            activeActivityRef = null
        }
    }

    fun request(context: Context, cacheId: Int, redirectUri: String): String {
        Log.d(
            TAG,
            "request cacheId=$cacheId redirectUri=${redirectUri.take(120)} acceptingRequests=$acceptingRequests terminalFailure=$terminalFailure pendingBefore=${pendingCount()}",
        )
        if (terminalFailure || (!acceptingRequests && !isVisibleActivityPresent())) {
            Log.w(TAG, "Ignoring captcha request for cache=$cacheId because acceptingRequests=$acceptingRequests terminalFailure=$terminalFailure")
            return ""
        }
        val wasEmpty = synchronized(lock) { pending.isEmpty() }
        val entry: PendingCaptcha? = synchronized(lock) {
            if (terminalFailure || !acceptingRequests) return@synchronized null
            pending[cacheId]?.let { return@synchronized it }
            val future = CompletableFuture<String>()
            val createdAtElapsed = SystemClock.elapsedRealtime()
            val newEntry = PendingCaptcha(cacheId, redirectUri, createdAtElapsed, future)
            pending[cacheId] = newEntry
            newEntry
        }
        if (entry == null) return ""

        val alert = wasEmpty || Application.getTurnProxyManager().shouldAlertCaptchaNotification()
        notifyPendingStateChanged()
        maybeShowOrNotify(context, entry, alert)
        Log.d(TAG, "request enqueued cacheId=$cacheId alert=$alert pendingAfter=${pendingCount()} activityVisible=${entry.activityVisible} autoOpenSuppressed=${entry.autoOpenSuppressed}")

        return try {
            entry.future.get(CAPTCHA_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: Throwable) {
            cancel(cacheId)
            ""
        }
    }

    fun hasPending(): Boolean = synchronized(lock) { pending.isNotEmpty() }

    fun pendingCount(): Int = synchronized(lock) { pending.size }

    fun openPendingFromUi(context: Context): Boolean {
        if (terminalFailure) return false
        val next = firstPending() ?: return false
        Log.d(TAG, "openPendingFromUi cacheId=${next.cacheId} pending=${pendingCount()}")
        synchronized(lock) {
            pending[next.cacheId]?.autoOpenSuppressed = false
        }
        startActivity(context, next.cacheId, next.redirectUri)
        updateNotifications(alert = false)
        return true
    }

    private fun firstPending(): PendingCaptcha? = synchronized(lock) { pending.values.firstOrNull() }

    private fun firstAutoOpenablePending(): PendingCaptcha? = synchronized(lock) {
        pending.values.firstOrNull { !it.autoOpenSuppressed }
    }

    fun markVisible(cacheId: Int) {
        synchronized(lock) {
            pending[cacheId]?.activityVisible = true
        }
        Log.d(TAG, "markVisible cacheId=$cacheId")
    }

    fun markHidden(cacheId: Int) {
        synchronized(lock) {
            pending[cacheId]?.activityVisible = false
        }
        Log.d(TAG, "markHidden cacheId=$cacheId")
    }

    fun dismiss(cacheId: Int) {
        synchronized(lock) {
            pending[cacheId]?.autoOpenSuppressed = true
        }
        Log.d(TAG, "dismiss cacheId=$cacheId")
    }

    fun complete(cacheId: Int, token: String) {
        Log.d(TAG, "complete cacheId=$cacheId tokenLength=${token.length} pendingBefore=${pendingCount()}")
        val entry = synchronized(lock) {
            pending.remove(cacheId)
        } ?: return
        entry.future.complete(token)
        notifyPendingStateChanged()
        updateNotifications(alert = false)
        maybeOpenNextIfForeground()
    }

    fun cancel(cacheId: Int) {
        Log.d(TAG, "cancel cacheId=$cacheId pendingBefore=${pendingCount()}")
        val entry = synchronized(lock) { pending.remove(cacheId) } ?: return
        entry.future.complete("")
        notifyPendingStateChanged()
        updateNotifications(alert = false)
        maybeOpenNextIfForeground()
    }

    fun clearAll() {
        val entries = synchronized(lock) {
            val copy = pending.values.toList()
            pending.clear()
            copy
        }
        entries.forEach { it.future.complete("") }
        notifyPendingStateChanged()
        updateNotifications(alert = false)
    }

    private fun closeActiveActivity() {
        val activity = activeActivityRef?.get() ?: return
        Application.get().mainExecutor.execute {
            if (!activity.isFinishing && !activity.isDestroyed) {
                activity.finish()
            }
        }
    }

    fun maybeOpenNextIfForeground() {
        if (terminalFailure) return
        if (!Application.isAppInForeground()) return
        val next = firstAutoOpenablePending() ?: return
        if (next.activityVisible) return
        startActivity(Application.get(), next.cacheId, next.redirectUri)
    }

    private fun maybeShowOrNotify(context: Context, entry: PendingCaptcha, alert: Boolean) {
        if (terminalFailure) return
        if (Application.isAppInForeground()) {
            if (!entry.activityVisible && !entry.autoOpenSuppressed) {
                startActivity(context, entry.cacheId, entry.redirectUri)
            }
        }
        updateNotifications(alert)
    }

    private fun updateNotifications(alert: Boolean) {
        if (terminalFailure) {
            TurnNotificationManager.clearCaptchaNotification(Application.get())
            return
        }
        val next = firstPending()
        if (next == null) {
            TurnNotificationManager.clearCaptchaNotification(Application.get())
            return
        }
        val count = pendingCount()
        TurnNotificationManager.updateCaptchaNotification(
            Application.get(),
            count,
            next.cacheId,
            next.redirectUri,
            alert,
        )
    }

    private fun notifyPendingStateChanged() {
        Application.getTurnProxyManager().onCaptchaPendingChanged(pendingCount())
    }

    private fun startActivity(context: Context, cacheId: Int, redirectUri: String) {
        Log.d(TAG, "startActivity cacheId=$cacheId redirectUri=${redirectUri.take(120)}")
        val intent = Intent(context, CaptchaActivity::class.java).apply {
            putExtra(CaptchaActivity.EXTRA_CACHE_ID, cacheId)
            putExtra(CaptchaActivity.EXTRA_REDIRECT_URI, redirectUri)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        context.startActivity(intent)
    }

    private const val TAG = "WireGuard/CaptchaCoordinator"
}
