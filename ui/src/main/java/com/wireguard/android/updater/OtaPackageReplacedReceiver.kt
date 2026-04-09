package com.wireguard.android.updater

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class OtaPackageReplacedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }
        Log.i("WireGuard/OtaUpdater", "MY_PACKAGE_REPLACED received, posting OTA completion notification")
        OtaUpdater.onPackageReplaced(context)
    }
}
