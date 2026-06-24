/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.wireguard.android.R
import com.wireguard.android.activity.CaptchaActivity

object TurnNotificationManager {
    private const val CAPTCHA_CHANNEL_ID = "turn_vk_captcha"
    private const val ERROR_CHANNEL_ID = "turn_error"
    private const val CAPTCHA_NOTIFICATION_ID = 0x7451
    private const val ERROR_NOTIFICATION_ID = 0x7452
    private const val CAPTCHA_PENDING_INTENT_REQ_CODE = 0x7453

    fun updateCaptchaNotification(
        context: Context,
        pendingCount: Int,
        cacheId: Int,
        redirectUri: String,
        alert: Boolean,
    ) {
        if (pendingCount <= 0) {
            clearCaptchaNotification(context)
            return
        }
        ensureChannels(context)
        val intent = Intent(context, CaptchaActivity::class.java).apply {
            putExtra(CaptchaActivity.EXTRA_CACHE_ID, cacheId)
            putExtra(CaptchaActivity.EXTRA_REDIRECT_URI, redirectUri)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            CAPTCHA_PENDING_INTENT_REQ_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val title = if (pendingCount == 1) {
            context.getString(R.string.turn_vk_captcha_notification_title_one)
        } else {
            context.getString(R.string.turn_vk_captcha_notification_title_many, pendingCount)
        }
        val text = if (pendingCount == 1) {
            context.getString(R.string.turn_vk_captcha_notification_text_one)
        } else {
            context.getString(R.string.turn_vk_captcha_notification_text_many)
        }

        val builder = NotificationCompat.Builder(context, CAPTCHA_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(pendingIntent)
            .setAutoCancel(false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setSilent(!alert)

        if (alert) {
            builder.setDefaults(NotificationCompat.DEFAULT_SOUND or NotificationCompat.DEFAULT_VIBRATE)
            builder.setOnlyAlertOnce(false)
        }

        NotificationManagerCompat.from(context).notify(CAPTCHA_NOTIFICATION_ID, builder.build())
    }

    fun showTurnFailureNotification(context: Context, tunnelName: String, details: String? = null) {
        ensureChannels(context)
        // Error state must be single-source-of-truth: hide any pending captcha prompt.
        clearCaptchaNotification(context)
        val intent = Intent(context, TurnNotificationActionReceiver::class.java).apply {
            action = TurnNotificationActionReceiver.ACTION_RETRY_TURN
            putExtra(TurnNotificationActionReceiver.EXTRA_TUNNEL_NAME, tunnelName)
        }
        val pendingIntent = PendingIntent.getBroadcast(
            context,
            tunnelName.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, ERROR_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(context.getString(R.string.turn_failure_notification_title))
            .setContentText(details?.takeIf { it.isNotBlank() } ?: context.getString(R.string.turn_failure_notification_text))
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    details?.takeIf { it.isNotBlank() } ?: context.getString(R.string.turn_failure_notification_text)
                )
            )
            .setContentIntent(pendingIntent)
            .setAutoCancel(false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setDefaults(NotificationCompat.DEFAULT_SOUND or NotificationCompat.DEFAULT_VIBRATE)
            .build()
        NotificationManagerCompat.from(context).notify(ERROR_NOTIFICATION_ID, notification)
    }

    fun clearCaptchaNotification(context: Context) {
        NotificationManagerCompat.from(context).cancel(CAPTCHA_NOTIFICATION_ID)
    }

    fun clearTurnFailureNotification(context: Context) {
        NotificationManagerCompat.from(context).cancel(ERROR_NOTIFICATION_ID)
    }

    private fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CAPTCHA_CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CAPTCHA_CHANNEL_ID,
                    context.getString(R.string.turn_captcha_channel_name),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ).apply {
                    description = context.getString(R.string.turn_captcha_channel_desc)
                },
            )
        }
        if (manager.getNotificationChannel(ERROR_CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    ERROR_CHANNEL_ID,
                    context.getString(R.string.turn_failure_channel_name),
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply {
                    description = context.getString(R.string.turn_failure_channel_desc)
                },
            )
        }
    }
}
