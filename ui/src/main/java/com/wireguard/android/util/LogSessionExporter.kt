/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.activity.ComponentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.Locale

class LogSessionExporter(
    private val activity: ComponentActivity,
    private val downloadsFileSaver: DownloadsFileSaver = DownloadsFileSaver(activity),
) {
    suspend fun exportLastSession(): ExportResult = withContext(Dispatchers.IO) {
        val log = readApplicationLogcat(activity)
        val sessionMatch = SESSION_ID_REGEX.findAll(log).lastOrNull()
        val sessionId = sessionMatch?.groupValues?.getOrNull(1)?.lowercase(Locale.US) ?: "no-session"
        val sessionLog = sessionMatch?.range?.first?.let { log.substring(it) } ?: log
        if (sessionLog.isBlank()) {
            throw IOException("No application logs found")
        }

        val fileName = "wg-turn-$sessionId.log"
        val outputFile = downloadsFileSaver.save(fileName, null, true, "wg-turn")
            ?: throw IOException("Storage permission denied")
        try {
            outputFile.outputStream.use {
                it.write(sessionLog.toByteArray(StandardCharsets.UTF_8))
            }
        } catch (e: Throwable) {
            outputFile.delete()
            throw e
        }

        ExportResult(sessionId = sessionId, fileName = outputFile.fileName, lineCount = sessionLog.lineSequence().count())
    }

    data class ExportResult(
        val sessionId: String,
        val fileName: String,
        val lineCount: Int,
    )

    companion object {
        private val SESSION_ID_REGEX = Regex("""Session ID generated:\s*([0-9a-fA-F]+)""")
        private const val TAG = "WireGuard/LogSessionExporter"

        private fun readApplicationLogcat(context: Context): String {
            val uidCommand = mutableListOf("logcat", "-d", "-b", "all", "-v", "threadtime", "*:V")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                uidCommand.add(uidCommand.lastIndex, "--uid=${context.applicationInfo.uid}")
            }
            val uidLog = runLogcat(uidCommand).getOrElse { first ->
                Log.w(TAG, "logcat --uid failed, falling back to app-visible logcat", first)
                ""
            }
            val visibleLog = runLogcat(listOf("logcat", "-d", "-b", "all", "-v", "threadtime", "*:V")).getOrNull().orEmpty()
            return when {
                SESSION_ID_REGEX.containsMatchIn(visibleLog) -> visibleLog
                uidLog.isNotBlank() -> uidLog
                visibleLog.isNotBlank() -> visibleLog
                else -> throw IOException("logcat returned no application logs")
            }
        }

        private fun runLogcat(command: List<String>): Result<String> = runCatching {
            val process = ProcessBuilder(command).apply {
                environment()["LC_ALL"] = "C"
            }.start()
            val stdout = BufferedReader(InputStreamReader(process.inputStream, StandardCharsets.UTF_8)).use { it.readText() }
            val stderr = BufferedReader(InputStreamReader(process.errorStream, StandardCharsets.UTF_8)).use { it.readText() }
            val exit = process.waitFor()
            if (exit != 0) {
                throw IOException(stderr.ifBlank { "logcat exited with $exit" })
            }
            stdout
        }
    }
}
