/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.preference

import android.content.Context
import android.util.AttributeSet
import android.util.Log
import androidx.preference.Preference
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.R
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.LogSessionExporter
import com.wireguard.android.util.activity
import com.wireguard.android.util.lifecycleScope
import kotlinx.coroutines.launch

class LogExporterPreference(context: Context, attrs: AttributeSet?) : Preference(context, attrs) {
    private val exporter = LogSessionExporter(activity)
    private var lastExportPath: String? = null

    override fun getTitle() = context.getString(R.string.log_exporter_pref_title)

    override fun getSummary() = lastExportPath ?: context.getString(R.string.log_exporter_pref_summary)

    override fun onClick() {
        if (!isEnabled) return
        isEnabled = false
        notifyChanged()
        lifecycleScope.launch {
            runCatching { exporter.exportLastSession() }
                .onSuccess {
                    lastExportPath = it.fileName
                    Snackbar.make(
                        activity.findViewById(android.R.id.content),
                        context.getString(R.string.log_export_success, it.fileName),
                        Snackbar.LENGTH_LONG,
                    ).show()
                }
                .onFailure {
                    Log.e(TAG, "Failed to export logs", it)
                    Snackbar.make(
                        activity.findViewById(android.R.id.content),
                        context.getString(R.string.log_export_error, ErrorMessages[it]),
                        Snackbar.LENGTH_LONG,
                    ).show()
                }
            isEnabled = true
            notifyChanged()
        }
    }

    companion object {
        private const val TAG = "WireGuard/LogExporterPreference"
    }
}
