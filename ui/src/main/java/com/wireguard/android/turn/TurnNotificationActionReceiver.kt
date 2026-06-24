/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.wireguard.android.Application
import kotlinx.coroutines.launch

class TurnNotificationActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_RETRY_TURN) return
        val tunnelName = intent.getStringExtra(EXTRA_TUNNEL_NAME) ?: return
        Application.getCoroutineScope().launch {
            Application.getTurnProxyManager().retryLastFailedTunnel(tunnelName)
        }
    }

    companion object {
        const val ACTION_RETRY_TURN = "com.wireguard.android.turn.ACTION_RETRY_TURN"
        const val EXTRA_TUNNEL_NAME = "turn_tunnel_name"
    }
}
