package com.wireguard.android.preference

import android.content.Context
import android.util.AttributeSet
import android.util.Log
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.preference.Preference
import com.wireguard.android.R
import com.wireguard.android.updater.OtaUpdater
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CancellationException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException

class ManualUpdatePreference(context: Context, attrs: AttributeSet?) : Preference(context, attrs) {
    private val tag = "WireGuard/ManualOta"
    private val stateListener: () -> Unit = {
        Handler(Looper.getMainLooper()).post {
            isEnabled = !OtaUpdater.isUpdateInProgress()
            notifyChanged()
        }
    }

    override fun getSummary() = OtaUpdater.getManualSummary(context)

    override fun getTitle() = context.getString(R.string.ota_manual_update_title)

    override fun onAttached() {
        super.onAttached()
        OtaUpdater.addManualListener(stateListener)
        stateListener()
        applicationScope.launch {
            withContext(Dispatchers.IO) {
                OtaUpdater.refreshManualSummary(context.applicationContext)
            }
            stateListener()
        }
    }

    override fun onDetached() {
        OtaUpdater.removeManualListener(stateListener)
        super.onDetached()
    }

    override fun onClick() {
        if (OtaUpdater.isUpdateInProgress()) {
            return
        }
        isEnabled = false
        notifyChanged()
        applicationScope.launch {
            val result = runCatching {
                OtaUpdater.triggerManualUpdate()
            }
            if (result.isSuccess) {
                val latest = context.getString(R.string.ota_latest_installed)
                if (result.getOrNull() == latest) {
                    OtaUpdater.setManualSummaryMessage(latest)
                }
                return@launch
            }
            if (result.isFailure) {
                val networkFriendly = context.getString(R.string.ota_network_error_user_friendly)
                val failure = result.exceptionOrNull()?.let {
                    val root = rootCause(it)
                    Log.e(tag, "Manual OTA update failed", it)
                    when (root) {
                        is UnknownHostException,
                        is ConnectException,
                        is SocketTimeoutException,
                        is SSLHandshakeException -> context.getString(R.string.ota_network_error_user_friendly)
                        is CancellationException -> context.getString(R.string.ota_request_canceled)
                        else -> context.getString(R.string.ota_failed_with_reason, root.message ?: ErrorMessages[root])
                    }
                }.orEmpty()
                if (failure.isNotBlank()) {
                    OtaUpdater.setManualSummaryMessage(failure)
                    if (failure != networkFriendly) {
                        Toast.makeText(context, failure, Toast.LENGTH_LONG).show()
                    }
                }
                isEnabled = true
                notifyChanged()
            }
        }
    }

    private fun rootCause(t: Throwable): Throwable {
        var current = t
        while (current.cause != null && current.cause !== current) {
            current = current.cause!!
        }
        val message = current.message.orEmpty()
        if (
            message.contains("android_getaddrinfo", ignoreCase = true) ||
            message.contains("EAI_", ignoreCase = true) ||
            message.contains("Name or service not known", ignoreCase = true)
        ) {
            return UnknownHostException(message)
        }
        return current
    }
}
