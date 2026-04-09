package com.wireguard.android.updater

import android.app.PendingIntent
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.wireguard.android.Application
import com.wireguard.android.BuildConfig
import com.wireguard.android.activity.SettingsActivity
import com.wireguard.android.R
import com.wireguard.android.backend.WgQuickBackend
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.net.HttpURLConnection
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URL
import java.security.cert.CertificateFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CopyOnWriteArraySet

object OtaUpdater {
    private const val TAG = "WireGuard/OtaUpdater"
    private val MAX_APK_SIZE_BYTES: ULong = 250UL * 1024UL * 1024UL
    private const val ACTION_INSTALL_RESULT_PREFIX = "com.wireguard.android.ota.INSTALL_RESULT."
    private const val OTA_NOTIFICATION_CHANNEL_ID = "ota_updates"
    private const val OTA_NOTIFICATION_ID = 0x5747
    private const val MANUAL_MANIFEST_TIMEOUT_MS = 30_000L
    private const val MANUAL_MANIFEST_RETRY_DELAY_MS = 1_200L
    private const val APK_DOWNLOAD_CONNECT_TIMEOUT_MS = 60_000
    private const val APK_DOWNLOAD_READ_TIMEOUT_MS = 60_000

    private const val PREFS_NAME = "ota_updater"
    private const val KEY_CACHED_VERSION_CODE = "cached_version_code"
    private const val KEY_CACHED_VERSION_NAME = "cached_version_name"
    private const val KEY_CACHED_SHA256 = "cached_sha256"
    private const val KEY_CACHED_APK_PATH = "cached_apk_path"
    private const val KEY_CACHED_BUILD_TYPE = "cached_build_type"
    private const val KEY_PENDING_RELAUNCH = "pending_relaunch_after_update"
    private const val KEY_PENDING_LAUNCH_TARGET = "pending_launch_target"

    private val updaterScope = CoroutineScope(Job() + Dispatchers.IO)
    private val updateMutex = Mutex()

    @Volatile
    private var manualInProgress = false
    @Volatile
    private var manualProgressMessage: String? = null
    @Volatile
    private var manualSummaryMessage: String? = null
    @Volatile
    private var autoProgressMessage: String? = null
    @Volatile
    private var lastAutoNotifiedVersionCode: Long = -1L
    @Volatile
    private var autoPrefetchJob: Job? = null

    private enum class OtaNetworkMode {
        CURRENT,
        VPN_ONLY,
    }

    private enum class RelaunchTarget {
        MAIN,
        SETTINGS,
    }

    private fun autoOtaNetworkMode(): OtaNetworkMode {
        return if (Application.peekBackend() is WgQuickBackend) {
            OtaNetworkMode.CURRENT
        } else {
            OtaNetworkMode.VPN_ONLY
        }
    }

    private val manualListeners = CopyOnWriteArraySet<() -> Unit>()

    fun addManualListener(listener: () -> Unit) {
        manualListeners.add(listener)
    }

    fun removeManualListener(listener: () -> Unit) {
        manualListeners.remove(listener)
    }

    private fun notifyManualStateChanged() {
        manualListeners.forEach { l ->
            runCatching { l() }
        }
    }

    private fun setManualInProgress(value: Boolean) {
        manualInProgress = value
        if (value) {
            manualProgressMessage = null
            manualSummaryMessage = null
        } else {
            manualProgressMessage = null
        }
        notifyManualStateChanged()
    }

    fun clearManualSummaryMessage() {
        manualSummaryMessage = null
        notifyManualStateChanged()
    }

    fun setManualSummaryMessage(message: String) {
        manualSummaryMessage = message
        notifyManualStateChanged()
    }

    data class OtaManifest(
        val versionCode: Long?,
        val versionName: String,
        val apkUrl: String,
        val sha256: String,
    )

    private data class CachedApk(
        val versionCode: Long,
        val versionName: String,
        val sha256: String,
        val file: File,
        val buildType: String,
    )

    private data class ApkVersionInfo(
        val versionCode: Long,
        val versionName: String,
    )

    class InstallResultReceiver(
        private val manual: Boolean,
    ) : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (!intent.action.orEmpty().startsWith(ACTION_INSTALL_RESULT_PREFIX)) {
                return
            }
            val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
            val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
            when (status) {
                PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                    val userIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(Intent.EXTRA_INTENT)
                    }
                    val confirmText = context.getString(R.string.ota_stage_confirm_install)
                    autoProgressMessage = confirmText
                    if (manual) {
                        setManualInProgress(false)
                        setManualSummaryMessage(confirmText)
                    } else {
                        notifyManualStateChanged()
                    }
                    if (userIntent != null) {
                        userIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        val launched = runCatching { context.startActivity(userIntent) }.isSuccess
                        if (!launched) {
                            Log.w(TAG, "Failed to open installer dialog directly; posting notification action")
                        }
                        postInstallerActionNotification(context, confirmText, userIntent)
                    } else {
                        Log.w(TAG, "OTA pending user action but no intent provided")
                    }
                    return
                }

                PackageInstaller.STATUS_SUCCESS -> {
                    Log.i(TAG, "OTA install finished successfully")
                    setManualInProgress(false)
                }

                else -> {
                    Log.w(TAG, "OTA install status=$status message=$msg")
                    clearOtaNotification(context)
                    autoProgressMessage = null
                    setManualInProgress(false)
                    setPendingRelaunch(context, enabled = false)
                    if (manual) {
                        val details = if (status == PackageInstaller.STATUS_FAILURE_ABORTED) {
                            context.getString(R.string.ota_install_aborted)
                        } else {
                            context.getString(R.string.ota_install_failed_short)
                        }
                        showToast(context, details)
                    }
                }
            }

            runCatching {
                context.applicationContext.unregisterReceiver(this)
            }.onFailure {
                Log.d(TAG, "Install receiver already unregistered: ${it.message}")
            }
        }
    }

    fun triggerAutoUpdateAfterTunnel() {
        Log.d(TAG, "triggerAutoUpdateAfterTunnel: scheduled")
        autoPrefetchJob?.cancel()
        autoPrefetchJob = updaterScope.launch {
            val delaysMs = longArrayOf(0L, 4_000L, 10_000L, 20_000L, 35_000L)
            var lastFailure: Throwable? = null
            for ((index, delayMs) in delaysMs.withIndex()) {
                if (delayMs > 0L) {
                    delay(delayMs)
                }
                val result = runCatching { prefetchUpdateForNextLaunch() }
                if (result.isSuccess) {
                    return@launch
                }
                val failure = result.exceptionOrNull()
                lastFailure = failure
                if (failure == null || !isNetworkLikeFailure(failure)) {
                    autoProgressMessage = null
                    notifyManualStateChanged()
                    Log.d(TAG, "Auto OTA prefetch skipped/failed: ${failure?.message}")
                    return@launch
                }
                val attempt = index + 1
                val total = delaysMs.size
                Log.w(TAG, "Auto OTA prefetch attempt $attempt/$total failed with network error: ${failure.message}")
            }
            autoProgressMessage = null
            manualSummaryMessage = Application.get().getString(R.string.ota_network_error_user_friendly)
            notifyManualStateChanged()
            Log.d(TAG, "Auto OTA prefetch skipped/failed after retries: ${lastFailure?.message}")
        }
    }

    fun triggerInstallIfReadyOnStartup() {
        Log.d(TAG, "triggerInstallIfReadyOnStartup: scheduled")
        updaterScope.launch {
            runCatching {
                updateMutex.withLock {
                    installCachedIfNeeded(manual = false, progress = null)
                }
            }
                .onFailure { Log.d(TAG, "Startup OTA install skipped/failed: ${it.message}") }
        }
    }

    fun isManualUpdateInProgress(): Boolean = manualInProgress
    fun isUpdateInProgress(): Boolean = manualInProgress || autoProgressMessage != null

    fun getManualSummary(context: Context): String {
        if (manualInProgress) {
            return manualProgressMessage ?: context.getString(R.string.ota_manual_update_summary_checking)
        }
        autoProgressMessage?.let { return it }
        manualSummaryMessage?.let { return it }
        return context.getString(R.string.ota_manual_update_summary_default)
    }

    suspend fun refreshManualSummary(context: Context) {
        withContext(Dispatchers.IO) {
            if (manualInProgress || autoProgressMessage != null) {
                return@withContext
            }
            val cached = loadCachedApk(context)
            val currentVersion = currentVersionCode(context)
            manualSummaryMessage = when {
                cached != null && cached.versionCode > currentVersion && cached.file.isFile ->
                    context.getString(R.string.ota_manual_update_summary_ready, cached.versionName, cached.versionCode)
                else -> null
            }
        }
        notifyManualStateChanged()
    }

    suspend fun triggerManualUpdate(progress: ((String) -> Unit)? = null): String {
        if (manualInProgress) {
            return Application.get().getString(R.string.ota_check_in_progress)
        }
        setManualInProgress(true)
        return try {
            checkAndInstallManual(progress)
        } catch (t: Throwable) {
            setManualInProgress(false)
            throw t
        }
    }

    private suspend fun checkAndInstallManual(progress: ((String) -> Unit)?): String = withContext(Dispatchers.IO) {
        updateMutex.withLock {
            val context = Application.get().applicationContext
            val currentVersionCode = currentVersionCode(context)
            val currentVersionName = currentVersionName(context)
            Log.d(TAG, "Manual OTA check start: currentVersion=$currentVersionCode/$currentVersionName buildType=${BuildConfig.BUILD_TYPE}")

            emitProgress(progress, context.getString(R.string.ota_stage_checking))
            val manifest = try {
                fetchManifest(context, withNetworkRetry = true, networkMode = OtaNetworkMode.CURRENT)
            } catch (t: Throwable) {
                val cached = loadCachedApk(context)
                if (cached != null && cached.versionCode > currentVersionCode && cached.file.isFile) {
                    Log.w(TAG, "OTA metadata fetch failed, installing cached APK instead: ${t.message}")
                    withContext(Dispatchers.Main) {
                        manualSummaryMessage = context.getString(R.string.ota_manual_update_summary_ready, cached.versionName, cached.versionCode)
                        notifyManualStateChanged()
                    }
                    installFromCachedFile(
                        context,
                        OtaManifest(cached.versionCode, cached.versionName, "", cached.sha256),
                        cached.file,
                        manual = true,
                        progress = progress,
                    )
                    return@withLock context.getString(R.string.ota_update_started, cached.versionName)
                }
                throw t
            }
            if (!isUpdateAvailable(manifest, currentVersionCode, currentVersionName)) {
                Log.i(TAG, "Manual OTA: no update (manifest=${manifest.versionName}/${manifest.versionCode}, installed=$currentVersionName/$currentVersionCode)")
                withContext(Dispatchers.Main) {
                    manualSummaryMessage = context.getString(R.string.ota_latest_installed)
                    notifyManualStateChanged()
                }
                setManualInProgress(false)
                return@withLock context.getString(R.string.ota_latest_installed)
            }

            emitProgress(
                progress,
                if (manifest.versionCode != null) {
                    context.getString(R.string.ota_stage_manifest_loaded, manifest.versionName, manifest.versionCode)
                } else {
                    context.getString(R.string.ota_stage_manifest_loaded_name, manifest.versionName)
                },
            )
            val cached = loadCachedApk(context)
            val cachedMatches = cached != null && manifestMatchesCached(manifest, cached)
            val cachedApk = if (cachedMatches) {
                emitProgress(progress, context.getString(R.string.ota_stage_cached_ready, cached!!.versionName))
                cached
            } else {
                downloadManifestApkToCache(context, manifest, progress, networkMode = OtaNetworkMode.CURRENT)
            }
            val installManifest = manifest.copy(versionCode = cachedApk.versionCode, versionName = cachedApk.versionName)
            installFromCachedFile(context, installManifest, cachedApk.file, manual = true, progress = progress)
            context.getString(R.string.ota_update_started, installManifest.versionName)
        }
    }

    private suspend fun prefetchUpdateForNextLaunch() {
        updateMutex.withLock {
            val context = Application.get().applicationContext
            val currentVersionCode = currentVersionCode(context)
            val currentVersionName = currentVersionName(context)
            autoProgressMessage = context.getString(R.string.ota_stage_checking)
            notifyManualStateChanged()
            Log.d(TAG, "Auto OTA prefetch start: currentVersion=$currentVersionCode/$currentVersionName buildType=${BuildConfig.BUILD_TYPE}")
            val cached = loadCachedApk(context)
            if (cached != null && cached.versionCode > currentVersionCode && cached.file.isFile) {
                Log.i(TAG, "Auto OTA: cached update already available ${cached.versionName} (${cached.versionCode})")
                if (lastAutoNotifiedVersionCode != cached.versionCode) {
                    lastAutoNotifiedVersionCode = cached.versionCode
                    notifyOtaReady(context, cached.versionName, cached.versionCode)
                } else {
                    autoProgressMessage = null
                    notifyManualStateChanged()
                }
                return
            }
            val manifest = try {
                fetchManifest(context, networkMode = autoOtaNetworkMode())
            } catch (t: Throwable) {
                val fallback = loadCachedApk(context)
                if (fallback != null && fallback.versionCode > currentVersionCode && fallback.file.isFile) {
                    Log.w(TAG, "Auto OTA metadata fetch failed, installing cached APK instead: ${t.message}")
                    autoProgressMessage = context.getString(R.string.ota_stage_confirm_install)
                    notifyManualStateChanged()
                    installFromCachedFile(
                        context,
                        OtaManifest(fallback.versionCode, fallback.versionName, "", fallback.sha256),
                        fallback.file,
                        manual = false,
                        progress = null,
                    )
                    return@withLock
                }
                throw t
            }
            if (!isUpdateAvailable(manifest, currentVersionCode, currentVersionName)) {
                Log.i(TAG, "Auto OTA: no update (manifest=${manifest.versionName}/${manifest.versionCode}, installed=$currentVersionName/$currentVersionCode)")
                manualSummaryMessage = context.getString(R.string.ota_latest_installed)
                clearOtaNotification(context)
                return
            }
            Log.i(TAG, "Auto OTA: update found ${manifest.versionName} (${manifest.versionCode ?: -1L})")
            notifyOtaStatus(context, context.getString(R.string.ota_stage_downloading))
            try {
                val cachedApk = downloadManifestApkToCache(context, manifest, progress = null, networkMode = autoOtaNetworkMode())
                if (lastAutoNotifiedVersionCode != cachedApk.versionCode) {
                    lastAutoNotifiedVersionCode = cachedApk.versionCode
                    notifyOtaReady(context, cachedApk.versionName, cachedApk.versionCode)
                } else {
                    autoProgressMessage = null
                    notifyManualStateChanged()
                }
                Log.i(TAG, "Prefetched OTA APK for next launch: ${cachedApk.versionName} (${cachedApk.versionCode})")
            } catch (t: Throwable) {
                if (isNetworkLikeFailure(t)) {
                    autoProgressMessage = null
                    notifyManualStateChanged()
                    throw t
                }
                Log.w(TAG, "Auto OTA download interrupted/failed: ${t.message}")
                autoProgressMessage = null
                manualSummaryMessage = context.getString(R.string.ota_stage_download_interrupted)
                notifyManualStateChanged()
                postOtaNotification(
                    context = context,
                    title = context.getString(R.string.ota_notification_title),
                    text = context.getString(R.string.ota_stage_download_interrupted),
                    ongoing = false,
                )
            }
        }
    }

    private suspend fun installCachedIfNeeded(manual: Boolean, progress: ((String) -> Unit)?): String? {
        val context = Application.get().applicationContext
        val cached = loadCachedApk(context) ?: return null
        val currentVersionCode = currentVersionCode(context)
        if (cached.versionCode <= currentVersionCode || !cached.file.isFile) {
            completeInstalledUpdate(context)
            return null
        }
        if (manual) {
            emitProgress(progress, context.getString(R.string.ota_stage_cached_ready, cached.versionName))
        }
        val manifest = OtaManifest(
            versionCode = cached.versionCode,
            versionName = cached.versionName,
            apkUrl = "",
            sha256 = cached.sha256,
        )
        installFromCachedFile(context, manifest, cached.file, manual = manual, progress = progress)
        return context.getString(R.string.ota_update_started, cached.versionName)
    }

    private fun currentVersionCode(context: Context): Long {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(context.packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, 0)
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }

    private fun currentVersionName(context: Context): String {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(context.packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, 0)
        }
        return info.versionName.orEmpty()
    }

    private fun isUpdateAvailable(manifest: OtaManifest, currentVersionCode: Long, currentVersionName: String): Boolean {
        manifest.versionCode?.let { return it > currentVersionCode }
        return manifest.versionName.isNotBlank() && manifest.versionName != currentVersionName
    }

    private fun manifestMatchesCached(manifest: OtaManifest, cached: CachedApk): Boolean {
        val versionMatches = manifest.versionCode?.let { cached.versionCode == it } ?: (manifest.versionName == cached.versionName)
        return cached.buildType == BuildConfig.BUILD_TYPE &&
            versionMatches &&
            cached.sha256.equals(manifest.sha256, ignoreCase = true) &&
            cached.file.isFile
    }

    private fun metadataUrl(): String {
        return if (BuildConfig.BUILD_TYPE == "debug") {
            BuildConfig.OTA_DEBUG_META_URL
        } else {
            BuildConfig.OTA_RELEASE_META_URL
        }
    }

    private fun fetchManifest(
        context: Context,
        withNetworkRetry: Boolean = false,
        networkMode: OtaNetworkMode = OtaNetworkMode.CURRENT,
    ): OtaManifest {
        val maxAttempts = if (withNetworkRetry) 2 else 1
        val deadlineMs = if (withNetworkRetry) System.currentTimeMillis() + MANUAL_MANIFEST_TIMEOUT_MS else null
        var lastError: Throwable? = null

        for (attempt in 1..maxAttempts) {
            try {
                val connectTimeoutMs = if (withNetworkRetry) 5_000 else 10_000
                val readTimeoutMs = if (withNetworkRetry) 12_000 else 20_000
                return fetchManifestOnce(
                    context = context,
                    connectTimeoutMs = connectTimeoutMs,
                    readTimeoutMs = readTimeoutMs,
                    deadlineMs = deadlineMs,
                    networkMode = networkMode,
                )
            } catch (t: Throwable) {
                lastError = t
                if (!withNetworkRetry || attempt >= maxAttempts || !isNetworkLikeFailure(t)) {
                    throw t
                }
                val remaining = (deadlineMs ?: Long.MAX_VALUE) - System.currentTimeMillis()
                if (remaining <= MANUAL_MANIFEST_RETRY_DELAY_MS) {
                    break
                }
                Thread.sleep(MANUAL_MANIFEST_RETRY_DELAY_MS)
            }
        }

        throw lastError ?: SocketTimeoutException("OTA metadata fetch timed out")
    }

    private fun fetchManifestOnce(
        context: Context,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        deadlineMs: Long?,
        networkMode: OtaNetworkMode,
    ): OtaManifest {
        val conn = openOtaConnection(
            context = context,
            rawUrl = metadataUrl(),
            connectTimeoutMs = connectTimeoutMs,
            readTimeoutMs = readTimeoutMs,
            deadlineMs = deadlineMs,
            networkMode = networkMode,
        )
        if (conn.responseCode != HttpURLConnection.HTTP_OK) {
            throw IllegalStateException("OTA metadata status ${conn.responseCode}")
        }
        val body = conn.inputStream.use { it.readBytes() }
        val json = JSONObject(String(body))
        val apkUrl = json.optString("apk_url")
            .ifBlank { json.optString("url") }
            .ifBlank { json.optString("apkUrl") }
        require(apkUrl.isNotBlank()) {
            "OTA manifest is missing APK URL (expected apk_url/url/apkUrl): ${json.keys().asSequence().toList()}"
        }
        val versionName = json.optString("version_name")
            .ifBlank { json.optString("version") }
        return OtaManifest(
            versionCode = if (json.has("version_code") && !json.isNull("version_code")) json.getLong("version_code") else null,
            versionName = versionName,
            apkUrl = apkUrl,
            sha256 = json.getString("sha256").lowercase(Locale.ENGLISH),
        )
    }

    private suspend fun downloadManifestApkToCache(
        context: Context,
        manifest: OtaManifest,
        progress: ((String) -> Unit)?,
        networkMode: OtaNetworkMode,
    ): CachedApk {
        emitProgress(progress, context.getString(R.string.ota_stage_downloading))
        val conn = openOtaConnection(
            context = context,
            rawUrl = manifest.apkUrl,
            connectTimeoutMs = APK_DOWNLOAD_CONNECT_TIMEOUT_MS,
            readTimeoutMs = APK_DOWNLOAD_READ_TIMEOUT_MS,
            deadlineMs = null,
            networkMode = networkMode,
        )
        if (conn.responseCode != HttpURLConnection.HTTP_OK) {
            throw IllegalStateException("OTA APK status ${conn.responseCode}")
        }

        val target = cachedApkFile(context)
        val tmp = File(target.parentFile, "${target.name}.tmp")
        target.parentFile?.mkdirs()

        val digest = MessageDigest.getInstance("SHA-256")
        var total: ULong = 0UL
        val totalBytes = conn.contentLengthLong.takeIf { it > 0L }
        var lastReportedPercent = -1
        tmp.outputStream().use { out ->
            conn.inputStream.use { input ->
                val buf = ByteArray(32 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    total += n.toUInt()
                    if (total > MAX_APK_SIZE_BYTES) {
                        throw IllegalStateException("OTA APK is too large")
                    }
                    if (totalBytes != null) {
                        val percent = ((total.toDouble() * 100.0) / totalBytes.toDouble()).toInt().coerceIn(0, 100)
                        if (percent >= lastReportedPercent + 5 || percent == 100) {
                            lastReportedPercent = percent
                            emitDownloadProgress(context, progress, percent)
                        }
                    }
                    digest.update(buf, 0, n)
                    out.write(buf, 0, n)
                }
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        if (actual != manifest.sha256) {
            tmp.delete()
            throw IllegalStateException("OTA checksum mismatch")
        }
        if (target.isFile && !target.delete()) {
            Log.w(TAG, "Failed to delete previous cached APK: ${target.absolutePath}")
        }
        if (!tmp.renameTo(target)) {
            throw IllegalStateException("Failed to move cached APK into place")
        }
        val apkVersion = readApkVersionInfo(context, target)
        val resolvedVersionName = manifest.versionName.ifBlank { apkVersion.versionName }
        saveCachedApk(
            context,
            versionCode = apkVersion.versionCode,
            versionName = resolvedVersionName,
            sha256 = manifest.sha256,
            path = target.absolutePath,
            buildType = BuildConfig.BUILD_TYPE,
        )
        val cachedApk = CachedApk(
            versionCode = apkVersion.versionCode,
            versionName = resolvedVersionName,
            sha256 = manifest.sha256,
            file = target,
            buildType = BuildConfig.BUILD_TYPE,
        )
        emitProgress(progress, context.getString(R.string.ota_stage_downloaded_verified))
        if (progress == null && autoProgressMessage == null) {
            notifyOtaReady(context, cachedApk.versionName, cachedApk.versionCode)
        }
        return cachedApk
    }

    private fun readApkVersionInfo(context: Context, apkFile: File): ApkVersionInfo {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, android.content.pm.PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, 0)
        } ?: throw IllegalStateException("Failed to read OTA APK package info")
        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
        return ApkVersionInfo(
            versionCode = versionCode,
            versionName = info.versionName.orEmpty(),
        )
    }

    private suspend fun emitDownloadProgress(context: Context, progress: ((String) -> Unit)?, percent: Int) {
        val text = context.getString(R.string.ota_stage_downloading_percent, percent)
        withContext(Dispatchers.Main) {
            if (manualInProgress || progress != null) {
                manualProgressMessage = text
            } else {
                autoProgressMessage = text
            }
            notifyManualStateChanged()
            progress?.invoke(text)
        }
    }

    private fun openOtaConnection(
        context: Context,
        rawUrl: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        deadlineMs: Long?,
        networkMode: OtaNetworkMode,
    ): HttpURLConnection {
        val url = URL(rawUrl)
        val cm = Application.get().getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val candidates = when (networkMode) {
            OtaNetworkMode.CURRENT -> buildList {
                add(null)
                add(selectVpnNetwork(cm))
                add(selectPhysicalNetwork(cm))
            }.distinct()
            OtaNetworkMode.VPN_ONLY -> listOfNotNull(selectVpnNetwork(cm))
        }

        if (candidates.isEmpty()) {
            throw java.net.ConnectException("Required OTA network is unavailable: $networkMode")
        }
        Log.d(TAG, "OTA network candidates for $networkMode: ${
            candidates.joinToString { candidate ->
                candidate?.networkHandle?.toString() ?: "default"
            }
        }")
        var lastError: Throwable? = null
        for (network in candidates) {
            if (deadlineMs != null) {
                val remaining = deadlineMs - System.currentTimeMillis()
                if (remaining <= 0L) {
                    throw SocketTimeoutException("OTA metadata fetch timed out")
                }
            }
            val netLabel = network?.networkHandle?.toString() ?: "default"
            val raw = try {
                if (network != null) network.openConnection(url) else url.openConnection()
            } catch (t: Throwable) {
                lastError = t
                Log.w(TAG, "Failed to open OTA connection on network $netLabel: ${t.message}")
                continue
            }
            val connection = raw as? HttpURLConnection
            if (connection == null) {
                lastError = IllegalStateException("Unsupported URLConnection type: ${raw::class.java.name}")
                continue
            }
            connection.setRequestProperty("User-Agent", Application.USER_AGENT)
            val remainingMs = if (deadlineMs != null) (deadlineMs - System.currentTimeMillis()).coerceAtLeast(1L).toInt() else Int.MAX_VALUE
            connection.connectTimeout = minOf(connectTimeoutMs, remainingMs)
            connection.readTimeout = minOf(readTimeoutMs, remainingMs)

            if (connection is HttpsURLConnection) {
                if (BuildConfig.OTA_PINNED_CA_ENABLED) {
                    connection.sslSocketFactory = otaSslSocketFactory(context)
                }
                connection.hostnameVerifier = HostnameVerifier { _, session ->
                    HttpsURLConnection.getDefaultHostnameVerifier().verify(url.host, session)
                }
            }

            try {
                connection.connect()
                Log.d(TAG, "Opened OTA connection via network $netLabel to $rawUrl")
                return connection
            } catch (t: Throwable) {
                lastError = t
                connection.disconnect()
                if (!isNetworkLikeFailure(t)) {
                    throw t
                }
                Log.w(TAG, "OTA connect failed on network $netLabel: ${t.message}")
            }
        }

        throw lastError ?: IllegalStateException("Unable to open OTA connection")
    }

    private fun isNetworkLikeFailure(t: Throwable): Boolean {
        var current: Throwable? = t
        while (current != null) {
            val message = current.message.orEmpty()
            if (
                current is java.net.UnknownHostException ||
                current is java.net.ConnectException ||
                current is SocketException ||
                current is java.net.SocketTimeoutException ||
                current is javax.net.ssl.SSLHandshakeException ||
                message.contains("android_getaddrinfo", ignoreCase = true) ||
                message.contains("EAI_", ignoreCase = true) ||
                message.contains("Name or service not known", ignoreCase = true) ||
                message.contains("software caused connection abort", ignoreCase = true) ||
                message.contains("connection reset", ignoreCase = true) ||
                message.contains("broken pipe", ignoreCase = true)
            ) {
                return true
            }
            current = current.cause
        }
        return false
    }

    private fun otaSslSocketFactory(context: Context): SSLSocketFactory {
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val resName = BuildConfig.OTA_PINNED_CA_RES
        val resId = context.resources.getIdentifier(resName, "raw", context.packageName)
        require(resId != 0) { "OTA CA resource not found: $resName" }
        val certificates = context.resources.openRawResource(resId).use { input ->
            certificateFactory.generateCertificates(input).mapNotNull { it as? java.security.cert.X509Certificate }
        }
        require(certificates.isNotEmpty()) { "OTA CA bundle is empty" }

        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            certificates.forEachIndexed { index, certificate ->
                setCertificateEntry("ota-ca-$index", certificate)
            }
        }
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore)
        }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustManagerFactory.trustManagers, null)
        return sslContext.socketFactory
    }

    private fun selectVpnNetwork(cm: ConnectivityManager): Network? {
        val networks = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            network to caps
        }
        return networks.firstOrNull { it.second.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }?.first
    }

    private fun selectPhysicalNetwork(cm: ConnectivityManager): Network? {
        val activeNetwork = cm.activeNetwork
        if (activeNetwork != null) {
            val activeCaps = cm.getNetworkCapabilities(activeNetwork)
            if (
                activeCaps != null &&
                activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            ) {
                return activeNetwork
            }
        }
        val networks = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
            network to caps
        }
        return networks.firstOrNull { it.second.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }?.first
            ?: networks.firstOrNull { it.second.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) }?.first
            ?: networks.firstOrNull()?.first
    }

    private suspend fun installFromCachedFile(
        context: Context,
        manifest: OtaManifest,
        apkFile: File,
        manual: Boolean,
        progress: ((String) -> Unit)?,
    ) {
        if (!apkFile.isFile) {
            throw IllegalStateException("Cached OTA APK is missing")
        }
        val installer = context.packageManager.packageInstaller
        setPendingRelaunch(context, enabled = true, target = RelaunchTarget.SETTINGS)
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
        }
        val session = installer.openSession(installer.createSession(params))
        var shouldAbandon = true
        try {
            FileInputStream(apkFile).use { input ->
                session.openWrite("ota.apk", 0, apkFile.length()).use { out ->
                    val buf = ByteArray(32 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        out.write(buf, 0, n)
                    }
                    session.fsync(out)
                }
            }

            val action = ACTION_INSTALL_RESULT_PREFIX + UUID.randomUUID()
            val receiver = InstallResultReceiver(manual = manual)
            val filter = IntentFilter(action)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ContextCompat.registerReceiver(
                    context.applicationContext,
                    receiver,
                    filter,
                    ContextCompat.RECEIVER_NOT_EXPORTED,
                )
            } else {
                @Suppress("DEPRECATION")
                context.applicationContext.registerReceiver(receiver, filter)
            }
            val pending = PendingIntent.getBroadcast(
                context,
                0,
                Intent(action).setPackage(context.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            emitProgress(progress, context.getString(R.string.ota_stage_installing))
            session.commit(pending.intentSender)
            shouldAbandon = false
            if (manual) {
                Log.i(TAG, "Manual OTA install requested: ${manifest.versionName}")
            }
        } finally {
            if (shouldAbandon) {
                setPendingRelaunch(context, false)
                session.abandon()
            }
            session.close()
        }
    }

    private fun cachedApkFile(context: Context): File {
        return File(File(context.filesDir, "ota-cache"), "wg-turn-${BuildConfig.BUILD_TYPE}.apk")
    }

    private fun saveCachedApk(
        context: Context,
        versionCode: Long,
        versionName: String,
        sha256: String,
        path: String,
        buildType: String,
    ) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_CACHED_VERSION_CODE, versionCode)
            .putString(KEY_CACHED_VERSION_NAME, versionName)
            .putString(KEY_CACHED_SHA256, sha256)
            .putString(KEY_CACHED_APK_PATH, path)
            .putString(KEY_CACHED_BUILD_TYPE, buildType)
            .apply()
    }

    private fun loadCachedApk(context: Context): CachedApk? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val buildType = prefs.getString(KEY_CACHED_BUILD_TYPE, null) ?: return null
        if (buildType != BuildConfig.BUILD_TYPE) {
            return null
        }
        val versionCode = prefs.getLong(KEY_CACHED_VERSION_CODE, 0L)
        val versionName = prefs.getString(KEY_CACHED_VERSION_NAME, "").orEmpty()
        val sha256 = prefs.getString(KEY_CACHED_SHA256, "").orEmpty()
        val path = prefs.getString(KEY_CACHED_APK_PATH, "").orEmpty()
        if (versionCode <= 0 || path.isBlank() || sha256.isBlank()) {
            return null
        }
        return CachedApk(
            versionCode = versionCode,
            versionName = versionName,
            sha256 = sha256,
            file = File(path),
            buildType = buildType,
        )
    }

    private fun clearCachedApk(context: Context) {
        loadCachedApk(context)?.file?.delete()
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .remove(KEY_CACHED_VERSION_CODE)
            .remove(KEY_CACHED_VERSION_NAME)
            .remove(KEY_CACHED_SHA256)
            .remove(KEY_CACHED_APK_PATH)
            .remove(KEY_CACHED_BUILD_TYPE)
            .apply()
    }

    private suspend fun emitProgress(progress: ((String) -> Unit)?, message: String) {
        withContext(Dispatchers.Main) {
            manualProgressMessage = message
            notifyManualStateChanged()
            progress?.invoke(message)
        }
    }

    private fun showToast(context: Context, message: String) {
        updaterScope.launch(Dispatchers.Main) {
            Toast.makeText(context.applicationContext, message, Toast.LENGTH_LONG).show()
        }
    }

    private fun notifyOtaStatus(context: Context, status: String) {
        autoProgressMessage = status
        notifyManualStateChanged()
        postOtaNotification(
            context = context,
            title = context.getString(R.string.ota_notification_title),
            text = status,
            ongoing = true,
        )
    }

    private fun notifyOtaReady(context: Context, versionName: String, versionCode: Long) {
        manualSummaryMessage = context.getString(R.string.ota_manual_update_summary_ready, versionName, versionCode)
        manualProgressMessage = null
        autoProgressMessage = null
        notifyManualStateChanged()
        postOtaNotification(
            context = context,
            title = context.getString(R.string.ota_notification_title),
            text = context.getString(R.string.ota_notification_ready_next_launch, versionName, versionCode),
            ongoing = false,
        )
    }

    private fun clearOtaNotification(context: Context) {
        autoProgressMessage = null
        notifyManualStateChanged()
        NotificationManagerCompat.from(context).cancel(OTA_NOTIFICATION_ID)
    }

    private fun postInstallerActionNotification(context: Context, text: String, installerIntent: Intent) {
        val pendingIntent = PendingIntent.getActivity(
            context,
            1003,
            installerIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        postOtaNotification(
            context = context,
            title = context.getString(R.string.ota_notification_title),
            text = text,
            ongoing = true,
            contentIntent = pendingIntent,
        )
    }

    private fun postOtaNotification(
        context: Context,
        title: String,
        text: String,
        ongoing: Boolean,
        contentIntent: PendingIntent? = null,
    ) {
        ensureNotificationChannel(context)
        val pendingIntent = contentIntent ?: PendingIntent.getActivity(
            context,
            0,
            Intent(context, SettingsActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, OTA_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setOngoing(ongoing)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
        NotificationManagerCompat.from(context).notify(OTA_NOTIFICATION_ID, notification)
    }

    private fun postInstalledUpdateNotification(context: Context, target: RelaunchTarget) {
        val launchIntent = buildLaunchIntent(context, target) ?: return
        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pendingIntent = PendingIntent.getActivity(
            context,
            1001,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        postOtaNotification(
            context = context,
            title = context.getString(R.string.ota_notification_title),
            text = context.getString(R.string.ota_notification_installed_open),
            ongoing = false,
            contentIntent = pendingIntent,
        )
    }

    private fun completeInstalledUpdate(context: Context) {
        clearCachedApk(context)
        lastAutoNotifiedVersionCode = -1L
        manualProgressMessage = null
        autoProgressMessage = null
        NotificationManagerCompat.from(context).cancel(OTA_NOTIFICATION_ID)
        notifyManualStateChanged()
    }

    private fun setPendingRelaunch(context: Context, enabled: Boolean, target: RelaunchTarget = RelaunchTarget.MAIN) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().apply {
            putBoolean(KEY_PENDING_RELAUNCH, enabled)
            if (enabled) {
                putString(KEY_PENDING_LAUNCH_TARGET, target.name)
            } else {
                remove(KEY_PENDING_LAUNCH_TARGET)
            }
        }.apply()
    }

    private fun pendingRelaunchTarget(context: Context): RelaunchTarget {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return runCatching {
            RelaunchTarget.valueOf(
                prefs.getString(KEY_PENDING_LAUNCH_TARGET, RelaunchTarget.MAIN.name) ?: RelaunchTarget.MAIN.name
            )
        }.getOrDefault(RelaunchTarget.MAIN)
    }

    fun onPackageReplaced(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_PENDING_RELAUNCH, false)) {
            return
        }
        // Clear cached APK/notifications early so the new version doesn't re-offer the same update,
        // even if the package-replaced broadcast is delayed by the OS.
        completeInstalledUpdate(context)
        val target = runCatching {
            RelaunchTarget.valueOf(
                prefs.getString(KEY_PENDING_LAUNCH_TARGET, RelaunchTarget.MAIN.name) ?: RelaunchTarget.MAIN.name
            )
        }.getOrDefault(RelaunchTarget.MAIN)
        prefs.edit()
            .putBoolean(KEY_PENDING_RELAUNCH, false)
            .remove(KEY_PENDING_LAUNCH_TARGET)
            .apply()
        postInstalledUpdateNotification(context, target)
    }

    private fun buildLaunchIntent(context: Context, target: RelaunchTarget): Intent? {
        return when (target) {
            RelaunchTarget.MAIN -> context.packageManager.getLaunchIntentForPackage(context.packageName)
            RelaunchTarget.SETTINGS -> Intent(context, SettingsActivity::class.java)
        }
    }

    private fun ensureNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            OTA_NOTIFICATION_CHANNEL_ID,
            context.getString(R.string.ota_notification_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = context.getString(R.string.ota_notification_channel_description)
        }
        manager.createNotificationChannel(channel)
    }
}
