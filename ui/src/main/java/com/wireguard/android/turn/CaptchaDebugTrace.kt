/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import com.wireguard.android.BuildConfig
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.Executors

/** Small, bounded on-device trace shared by silent and visible captcha WebViews. */
object CaptchaDebugTrace {
    private const val FILE_NAME = "captcha-debug.log"
    private const val MAX_BYTES = 2L * 1024L * 1024L
    private const val RETAIN_BYTES = 1024 * 1024
    private const val MAX_MESSAGE_CHARS = 3000
    private val writer = Executors.newSingleThreadExecutor { task ->
        Thread(task, "captcha-debug-trace").apply { isDaemon = true }
    }

    fun append(context: Context, source: String, message: String?) {
        if (!BuildConfig.DEBUG || message.isNullOrBlank()) return
        val safeMessage = sanitize(message).take(MAX_MESSAGE_CHARS)
        if (safeMessage.isBlank()) return
        val appContext = context.applicationContext
        writer.execute {
            runCatching {
                val file = File(appContext.cacheDir, FILE_NAME)
                if (file.length() >= MAX_BYTES) retainTail(file)
                file.appendText("${System.currentTimeMillis()} [$source] $safeMessage\n")
            }
        }
    }

    fun clear(context: Context) {
        val appContext = context.applicationContext
        writer.execute {
            runCatching { File(appContext.cacheDir, FILE_NAME).delete() }
            runCatching {
                appContext.cacheDir.listFiles { file -> file.name.startsWith("captcha-") && file.extension == "png" }
                    ?.forEach(File::delete)
            }
        }
    }

    private fun sanitize(value: String): String = value
        .replace("\u0000", "")
        .replace("\r", "")
        .replace("\n", "\\n")
        .replace(Regex("session_token=[^&\\s]+"), "session_token=<redacted>")
        .replace(Regex("(\\\"success_token\\\"\\s*:\\s*\\\")[^\\\"]+"), "$1<redacted>")
        .replace(Regex("[A-Za-z0-9_-]{160,}"), "<redacted-long-token>")
        .trim()

    private fun retainTail(file: File) {
        RandomAccessFile(file, "rw").use { raf ->
            val keep = minOf(RETAIN_BYTES.toLong(), raf.length()).toInt()
            val tail = ByteArray(keep)
            raf.seek(raf.length() - keep)
            raf.readFully(tail)
            raf.setLength(0)
            raf.write(tail)
        }
    }
}
