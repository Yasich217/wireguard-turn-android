/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.preference

import android.content.Context
import android.util.AttributeSet
import android.util.Log
import android.widget.Toast
import androidx.preference.Preference
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.turn.CaptchaSessionStore
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.launch

class ClearTurnSessionsPreference(context: Context, attrs: AttributeSet?) : Preference(context, attrs) {
    override fun getTitle() = context.getString(R.string.clear_turn_sessions_title)

    override fun getSummary() = context.getString(R.string.clear_turn_sessions_summary)

    override fun onClick() {
        if (!isEnabled) return
        isEnabled = false
        notifyChanged()
        applicationScope.launch {
            val result = runCatching {
                Application.getTurnProxyManager().stopForSessionReset()
                CaptchaSessionStore.clear(context)
                Application.getTurnProxyManager().restartAfterSessionReset()
            }
            val message = if (result.isSuccess) {
                R.string.clear_turn_sessions_done
            } else {
                Log.e(TAG, "Failed to clear TURN sessions", result.exceptionOrNull())
                R.string.clear_turn_sessions_failed
            }
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
            isEnabled = true
            notifyChanged()
        }
    }

    private companion object {
        const val TAG = "WireGuard/ClearSessions"
    }
}
