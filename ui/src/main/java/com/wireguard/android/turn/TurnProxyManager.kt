/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import com.wireguard.android.Application
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.WgQuickBackend
import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.turn.CaptchaCoordinator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.collectLatest
import java.net.Inet4Address
import java.util.concurrent.TimeUnit

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 *
 * Uses PhysicalNetworkMonitor to track stable internet connections and 
 * triggers restarts when the underlying network or IP changes.
 */
class TurnProxyManager(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)
    
    // State
    private var activeTunnelName: String? = null
    private var activeSettings: TurnSettings? = null
    private var activePublicKey: String = ""
    private var activeKeepaliveSec: Int = 0
    private var lastFailedTunnelName: String? = null
    @Volatile private var userInitiatedStop: Boolean = false
    @Volatile private var lastSuccessfulStartElapsedMs: Long = 0L
    @Volatile private var lastKernelHelperCheckElapsedMs: Long = 0L
    
    // Network tracking
    private val networkMonitor = PhysicalNetworkMonitor(context)
    @Volatile private var lastKnownNetwork: Network? = null
    
    init {
        networkMonitor.start()
        TurnBackend.setVpnServiceRevokedListener {
            scope.launch {
                onVpnServiceRevoked()
            }
        }
        
        scope.launch {
            networkMonitor.bestNetwork.collectLatest { network ->
                if (network != null) {
                    handleNetworkChange(network)
                }
            }
        }
    }

    /**
     * Central handler for network changes from PhysicalNetworkMonitor.
     * The monitor already provides debounced stable networks.
     */
    private suspend fun handleNetworkChange(network: Network) {
        if (userInitiatedStop || activeTunnelName == null) return
        if (lastFailedTunnelName != null) {
            Log.d(TAG, "Ignoring network change because TURN start is in failed state for $lastFailedTunnelName")
            return
        }

        val startElapsed = lastSuccessfulStartElapsedMs
        if (startElapsed > 0L) {
            val sinceStart = SystemClock.elapsedRealtime() - startElapsed
            if (sinceStart < NETWORK_RESTART_GRACE_MS) {
                lastKnownNetwork = network
                Log.d(TAG, "Ignoring network change during warmup window (${sinceStart}ms)")
                return
            }
        }

        // 1. Initial baseline setting
        if (lastKnownNetwork == null) {
            Log.d(TAG, "Setting initial network baseline: $network")
            lastKnownNetwork = network
            return
        }

        // 2. Stability check
        if (lastKnownNetwork == network) {
            Log.d(TAG, "Network state stable for $network")
            return
        }

        // 3. Real change confirmed
        Log.d(TAG, "Network change confirmed: $network. Restarting TURN.")
        lastKnownNetwork = network
        performRestartSequence()
    }

    private suspend fun performRestartSequence() {
        if (userInitiatedStop || activeTunnelName == null) return
        if (lastFailedTunnelName != null) {
            Log.d(TAG, "Skipping TURN restart because start is in failed state for $lastFailedTunnelName")
            return
        }

        val name = activeTunnelName ?: return
        val instance = instances.getOrPut(name) { Instance() }
        instance.runtimeStatus = instance.runtimeStatus.copy(
            modeInfo = context.getString(com.wireguard.android.R.string.turn_mode_retrying_proxy),
            clientPublicIp = "",
            relayIps = emptyList(),
            lastSyncUnix = 0L,
        )

        Log.d(TAG, "Stopping TURN proxy for restart...")
        TurnBackend.wgTurnProxyStop()
        
        // Critical: Notify Go backend to clear internal socket states/DNS cache
        Log.d(TAG, "Notifying Go layer of network change...")
        TurnBackend.wgNotifyNetworkChange()
        
        delay(500) // Give Go minimal time to react

        val settings = activeSettings ?: return

        var attempts = 0
        while (currentCoroutineContext().isActive && !userInitiatedStop) {
            attempts++
            Log.d(TAG, "Starting TURN for $name (Attempt $attempts)")
            
            val success = startForTunnelInternal(name, settings, activePublicKey, activeKeepaliveSec)
            if (success) {
                Log.d(TAG, "TURN restarted successfully on attempt $attempts")
                return // Exit loop on success
            }

            // Exponential backoff logic
            val delayMs = when {
                attempts <= 2 -> 2000L
                attempts <= 5 -> 5000L
                else -> 15000L
            }
            Log.w(TAG, "Restart failed, retrying in ${delayMs}ms...")
            delay(delayMs)
        }
    }

    private suspend fun onVpnServiceRevoked() {
        val tunnelName = activeTunnelName ?: return
        Log.w(TAG, "VpnService revoked for $tunnelName; clearing TURN state")
        stopForTunnel(tunnelName, clearRuntimeStatus = true)
    }

    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
        @Volatile var runtimeStatus: TurnRuntimeStatus = TurnRuntimeStatus(),
        @Volatile var statusPollingJob: Job? = null,
    )

    data class TurnRuntimeStatus(
        val modeInfo: String = "",
        val clientPublicIp: String = "",
        val relayIps: List<String> = emptyList(),
        val lastSyncUnix: Long = 0L,
        val activeStreams: Int = 0,
        val expectedStreams: Int = 0,
        val pendingCaptchaCount: Int = 0,
        val errorCount: Int = 0,
        val lastError: String = "",
    )

    private val instances = ConcurrentHashMap<String, Instance>()
    // Mutex to serialize start/stop operations and prevent race conditions between
    // onTunnelEstablished and handleNetworkChange
    private val operationMutex = kotlinx.coroutines.sync.Mutex()

    /**
     * Called from TurnManager when the tunnel is established.
     */
    suspend fun onTunnelEstablished(
        tunnelName: String,
        turnSettings: TurnSettings?,
        publicKey: String,
        keepaliveSec: Int,
        reconnecting: Boolean = false,
    ): Boolean {
        Log.d(TAG, "onTunnelEstablished called for tunnel: $tunnelName")
        val instance = instances.getOrPut(tunnelName) { Instance() }
        if (
            instance.running &&
            activeTunnelName == tunnelName &&
            activeSettings == turnSettings &&
            activePublicKey == publicKey &&
            activeKeepaliveSec == keepaliveSec.coerceAtLeast(0)
        ) {
            Log.d(TAG, "TURN already running with identical parameters for $tunnelName, skipping restart")
            return true
        }

        // Reset state for new session
        activeTunnelName = tunnelName
        activeSettings = turnSettings
        activePublicKey = publicKey
        activeKeepaliveSec = keepaliveSec.coerceAtLeast(0)
        userInitiatedStop = false
        
        // Initialize network baseline for the new session
        lastKnownNetwork = networkMonitor.currentNetwork
        Log.d(TAG, "Initial network for tunnel session: $lastKnownNetwork")

        if (turnSettings == null || !turnSettings.enabled) {
            Log.d(TAG, "TURN not enabled, skipping")
            return true
        }

        TurnNotificationManager.clearTurnFailureNotification(context)
        CaptchaCoordinator.beginAttempt(clearFailureState = true)
        resetRuntimeForNewAttempt(
            tunnelName,
            context.getString(
                if (reconnecting) {
                    com.wireguard.android.R.string.turn_mode_retrying_proxy
                } else {
                    com.wireguard.android.R.string.turn_mode_starting_proxy
                },
            ),
        )
        val success = startForTunnelInternal(tunnelName, turnSettings, publicKey, activeKeepaliveSec)

        // After initial start, allow network changes to trigger restarts
        // We delay slightly to ensure we don't catch the immediate network fluctuation caused by VPN itself
        scope.launch {
            delay(2000)
            Log.d(TAG, "Initialization phase complete, network monitoring active")
        }

        return success
    }

    suspend fun startForTunnel(tunnelName: String, settings: TurnSettings): Boolean {
        TurnNotificationManager.clearTurnFailureNotification(context)
        CaptchaCoordinator.beginAttempt(clearFailureState = true)
        resetRuntimeForNewAttempt(
            tunnelName,
            context.getString(com.wireguard.android.R.string.turn_mode_starting_proxy),
        )
        return startForTunnelInternal(tunnelName, settings, activePublicKey, activeKeepaliveSec)
    }
    
    private suspend fun startForTunnelInternal(tunnelName: String, settings: TurnSettings, publicKey: String, keepaliveSec: Int): Boolean =
        withContext(Dispatchers.IO) {
            operationMutex.lock()
            try {
                if (!currentCoroutineContext().isActive) {
                    Log.d(TAG, "startForTunnelInternal cancelled before execution")
                    return@withContext false
                }

                val instance = instances.getOrPut(tunnelName) { Instance() }

                Log.d(TAG, "Stopping any existing TURN proxy...")
                TurnBackend.wgTurnProxyStop()
                // Give Go runtime a moment to fully clean up goroutines
                delay(200)

                val backend = Application.getBackend()
                val kernelMode = backend is WgQuickBackend
                TurnBackend.wgSetKernelModeSocketRouting(kernelMode)
                if (kernelMode) {
                    val helperReady = ensureKernelSocketProtection()
                    if (!helperReady) {
                        Log.e(TAG, "Kernel TURN socket protection is not ready")
                        return@withContext false
                    }
                } else {
                    // Go backend requires VpnService to be registered in JNI for socket protection.
                    val jniReady = waitForJniRegistration()
                    if (!jniReady) {
                        Log.e(TAG, "TIMEOUT waiting for JNI registration!")
                        return@withContext false
                    }
                }

                // If network is still null, try one quick re-poll from monitor
                if (lastKnownNetwork == null) {
                    lastKnownNetwork = networkMonitor.currentNetwork
                    if (lastKnownNetwork == null) {
                        Log.w(TAG, "Network still null, waiting 500ms for PhysicalNetworkMonitor...")
                        delay(500)
                        lastKnownNetwork = networkMonitor.currentNetwork
                    }
                }

                val networkHandle = lastKnownNetwork?.getNetworkHandle() ?: 0L
                val networkType = getNetworkTypeString(lastKnownNetwork)
                Log.d(TAG, "Starting TURN proxy for $tunnelName with network: $lastKnownNetwork (type=$networkType, handle=$networkHandle)")

                if (!isLocalPortAvailable(settings.localPort)) {
                    val msg = "TURN local port ${settings.localPort} is already in use"
                    Log.e(TAG, msg)
                    appendLogLine(tunnelName, msg)
                    lastFailedTunnelName = tunnelName
                    TurnNotificationManager.showTurnFailureNotification(context, tunnelName, msg)
                    recordRuntimeError(tunnelName, msg)
                    return@withContext false
                }

                val ret = TurnBackend.wgTurnProxyStart(
                    settings.peer, settings.vkLink, settings.mode, settings.streams,
                    if (settings.useUdp) 1 else 0,
                    "127.0.0.1:${settings.localPort}",
                    settings.turnIp,
                    settings.turnPort,
                    settings.peerType,
                    settings.streamsPerCred,
                    settings.watchdogTimeout,
                    settings.vkCredentialsProfile,
                    settings.streamStartDelayMs,
                    settings.startupTimeoutSec,
                    settings.quotaBackoffSec,
                    networkHandle,
                    publicKey,
                    keepaliveSec
                )

                val listenAddr = "127.0.0.1:${settings.localPort}"
                if (userInitiatedStop || activeTunnelName != tunnelName) {
                    val msg = "TURN start result ignored for \"$tunnelName\" because stop/switch was requested during startup"
                    Log.w(TAG, msg)
                    appendLogLine(tunnelName, msg)
                    TurnBackend.wgTurnProxyStop()
                    instance.running = false
                    return@withContext false
                }
                if (ret == 0) {
                    instance.running = true
                    lastFailedTunnelName = null
                    TurnNotificationManager.clearTurnFailureNotification(context)
                    lastSuccessfulStartElapsedMs = SystemClock.elapsedRealtime()
                    instance.runtimeStatus = instance.runtimeStatus.copy(
                        modeInfo = context.getString(com.wireguard.android.R.string.turn_mode_active),
                        expectedStreams = settings.streams.coerceAtLeast(0),
                        pendingCaptchaCount = 0,
                        errorCount = 0,
                        lastError = "",
                    )
                    val msg = "TURN started for tunnel \"$tunnelName\" listening on $listenAddr"
                    Log.d(TAG, msg)
                    appendLogLine(tunnelName, msg)
                    startStatusPolling(tunnelName)
                    true
                } else {
                    val runtimeError = getRuntimeLastError()
                    val msg = runtimeError?.takeIf { it.isNotBlank() }?.let {
                        "Failed to start TURN proxy: $it"
                    } ?: "Failed to start TURN proxy (error $ret)"
                    Log.e(TAG, msg)
                    appendLogLine(tunnelName, msg)
                    lastFailedTunnelName = tunnelName
                    // Explicitly stop native proxy to cancel any in-flight credential/captcha work.
                    TurnBackend.wgTurnProxyStop()
                    CaptchaCoordinator.blockForFailure()
                    TurnNotificationManager.showTurnFailureNotification(context, tunnelName, msg)
                    recordRuntimeError(tunnelName, msg)
                    false
                }
            } finally {
                operationMutex.unlock()
            }
        }

    suspend fun stopForTunnel(tunnelName: String, clearRuntimeStatus: Boolean = false) =
        withContext(Dispatchers.IO) {
            val callerTrace = Throwable().stackTrace
                .drop(1)
                .take(6)
                .joinToString(" <- ") { "${it.className}.${it.methodName}:${it.lineNumber}" }
            Log.w(TAG, "stopForTunnel requested for $tunnelName by $callerTrace")
            userInitiatedStop = true
            lastSuccessfulStartElapsedMs = 0L
            activeTunnelName = null
            activeSettings = null
            activePublicKey = ""
            activeKeepaliveSec = 0
            lastFailedTunnelName = null
            lastKnownNetwork = null

            // Cancel the native startup path immediately; do not wait for the serialized
            // start mutex first, otherwise a user toggle to OFF can sit behind a long VK/TURN
            // startup attempt and feel hung.
            TurnBackend.wgTurnProxyStop()

            operationMutex.lock()
            try {
                val instance = instances[tunnelName] ?: return@withContext
                instance.statusPollingJob?.cancel()
                instance.statusPollingJob = null
                if (clearRuntimeStatus) {
                    instance.runtimeStatus = TurnRuntimeStatus()
                } else {
                    val previous = instance.runtimeStatus
                    val expected = previous.expectedStreams
                    val active = previous.activeStreams.coerceAtLeast(0)
                    val stoppedMode = if (expected > 0) {
                        context.getString(
                            com.wireguard.android.R.string.turn_mode_stopped_streams,
                            active.coerceAtMost(expected),
                            expected,
                        )
                    } else {
                        context.getString(com.wireguard.android.R.string.turn_mode_stopped_error)
                    }
                    instance.runtimeStatus = previous.copy(
                        modeInfo = stoppedMode,
                        pendingCaptchaCount = 0,
                    )
                }
                instance.running = false
                TurnNotificationManager.clearTurnFailureNotification(context)
                CaptchaCoordinator.stopAttempt(clearFailureState = true)
                val msg = "TURN stopped for tunnel \"$tunnelName\""
                Log.d(TAG, msg)
                appendLogLine(tunnelName, msg)
            } finally {
                operationMutex.unlock()
            }
        }

    fun markUsingDirectConnection(tunnelName: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        instance.runtimeStatus = instance.runtimeStatus.copy(
            modeInfo = context.getString(com.wireguard.android.R.string.turn_mode_direct),
        )
    }

    fun setRuntimeStatusModeInfo(tunnelName: String, modeInfo: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        instance.runtimeStatus = instance.runtimeStatus.copy(modeInfo = modeInfo)
    }

    private suspend fun waitForJniRegistration(): Boolean {
        var attempt = 0
        while (currentCoroutineContext().isActive && attempt < JNI_WAIT_ATTEMPTS) {
            attempt++
            val ready = TurnBackend.waitForVpnServiceRegistered(JNI_WAIT_STEP_MS)
            if (ready) {
                if (attempt > 1) {
                    Log.i(TAG, "JNI registration became ready on retry #$attempt")
                }
                return true
            }

            // If the latch timed out but VpnService already exists, re-register it to JNI.
            try {
                val service = TurnBackend.getVpnServiceFuture().get(0, TimeUnit.MILLISECONDS)
                Log.w(TAG, "JNI latch timeout, re-registering existing VpnService (attempt $attempt)")
                TurnBackend.onVpnServiceCreated(service)
            } catch (_: Throwable) {
                Log.w(TAG, "JNI not ready yet and VpnService future is not completed (attempt $attempt)")
            }
            delay(JNI_RETRY_BACKOFF_MS)
        }
        return false
    }

    private suspend fun ensureKernelSocketProtection(): Boolean {
        if (TurnBackend.waitForVpnServiceRegistered(1)) {
            Log.d(TAG, "Kernel TURN helper VpnService already registered in JNI")
            return true
        }

        val prepareIntent = GoBackend.VpnService.prepare(context)
        if (prepareIntent != null) {
            Log.e(TAG, "Kernel TURN helper VpnService permission is missing")
            return false
        }

        return try {
            Log.d(TAG, "Starting helper VpnService for kernel TURN socket protection")
            val intent = Intent(context, GoBackend.VpnService::class.java).apply {
                putExtra("com.wireguard.android.backend.GoBackend.kernel_helper", true)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ContextCompat.startForegroundService(context, intent)
            } else {
                context.startService(intent)
            }
            waitForJniRegistration()
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to start helper VpnService for kernel TURN", e)
            false
        }
    }

    fun isRunning(tunnelName: String): Boolean {
        return instances[tunnelName]?.running == true
    }

    fun getLog(tunnelName: String): String {
        return instances[tunnelName]?.log?.toString() ?: ""
    }

    fun clearLog(tunnelName: String) {
        instances[tunnelName]?.log?.setLength(0)
    }

    fun getRuntimeStatus(tunnelName: String): TurnRuntimeStatus {
        return instances[tunnelName]?.runtimeStatus ?: TurnRuntimeStatus()
    }

    fun appendLogLine(tunnelName: String, line: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val builder = instance.log
        synchronized(builder) {
            if (builder.isNotEmpty()) {
                builder.append('\n')
            }
            builder.append(line)
            if (builder.length > MAX_LOG_CHARS) builder.delete(0, builder.length - MAX_LOG_CHARS)
        }
    }

    private fun startStatusPolling(tunnelName: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        instance.statusPollingJob?.cancel()
        instance.statusPollingJob = scope.launch {
            while (isActive && instance.running) {
                try {
                    val json = TurnBackend.wgTurnProxyGetRuntimeStatusJson()
                    if (!json.isNullOrBlank()) {
                        val obj = org.json.JSONObject(json)
                        val previous = instance.runtimeStatus
                        val activeStreams = if (obj.has("active_streams")) {
                            obj.optInt("active_streams", previous.activeStreams)
                        } else {
                            previous.activeStreams
                        }
                        val relayIps = mutableListOf<String>()
                        val relayArray = obj.optJSONArray("relay_ips")
                        if (activeStreams > 0) {
                            if (relayArray != null) {
                                for (i in 0 until relayArray.length()) {
                                    relayIps.add(relayArray.optString(i))
                                }
                            } else {
                                relayIps.addAll(previous.relayIps)
                            }
                        }
                        val expectedStreams = (activeSettings?.streams ?: previous.expectedStreams).coerceAtLeast(0)
                        val rawModeInfo = if (obj.has("mode_info")) {
                            obj.optString("mode_info", previous.modeInfo)
                        } else {
                            previous.modeInfo
                        }
                        val pendingCaptchaCount = CaptchaCoordinator.pendingCount()
                        val jsonLastError = if (obj.has("last_error")) obj.optString("last_error") else ""
                        val lastErrorCandidate = jsonLastError.ifBlank { previous.lastError }
                        val isFullyActive = expectedStreams > 0 &&
                            activeStreams >= expectedStreams &&
                            pendingCaptchaCount <= 0
                        val lastError = if (isFullyActive) "" else lastErrorCandidate
                        val errorCount = when {
                            isFullyActive -> 0
                            obj.has("error_count") -> obj.optInt("error_count", previous.errorCount)
                            else -> previous.errorCount
                        }
                        if (isFullyActive && (previous.errorCount > 0 || previous.lastError.isNotBlank())) {
                            // When TURN recovers, clear any stale "failed" state and notifications.
                            TurnNotificationManager.clearTurnFailureNotification(context)
                        }
                        val modeInfo = if (activeStreams > 0) {
                            val remainingStreams = (expectedStreams - activeStreams).coerceAtLeast(0)
                            if (expectedStreams > 0 && remainingStreams > 0) {
                                if (pendingCaptchaCount > 0) {
                                    context.getString(
                                        com.wireguard.android.R.string.turn_mode_active_streams_partial_captcha,
                                        activeStreams,
                                        expectedStreams,
                                        remainingStreams,
                                    )
                                } else if (isQuotaError(lastError)) {
                                    context.getString(
                                        com.wireguard.android.R.string.turn_mode_active_streams_partial_quota,
                                        activeStreams,
                                        expectedStreams,
                                        remainingStreams,
                                    )
                                } else {
                                    context.getString(
                                        com.wireguard.android.R.string.turn_mode_active_streams_partial_credentials,
                                        activeStreams,
                                        expectedStreams,
                                        remainingStreams,
                                    )
                                }
                            } else if (expectedStreams > 0) {
                                context.getString(
                                    com.wireguard.android.R.string.turn_mode_active_streams_full,
                                    activeStreams,
                                    expectedStreams,
                                )
                            } else {
                                context.getString(com.wireguard.android.R.string.turn_mode_active_streams, activeStreams)
                            }
                        } else if (pendingCaptchaCount > 0) {
                            context.getString(
                                com.wireguard.android.R.string.turn_mode_waiting_captcha_tap,
                                pendingCaptchaCount,
                            )
                        } else {
                            localizeModeInfo(rawModeInfo).ifBlank { previous.modeInfo }
                        }
                        val clientPublicIp = if (activeStreams > 0) {
                            obj.optString("client_public_ip").ifBlank { previous.clientPublicIp }
                        } else {
                            ""
                        }
                        instance.runtimeStatus = TurnRuntimeStatus(
                            modeInfo = modeInfo,
                            clientPublicIp = clientPublicIp,
                            relayIps = relayIps,
                            lastSyncUnix = if (activeStreams > 0 && obj.has("last_sync_unix")) obj.optLong("last_sync_unix", previous.lastSyncUnix) else 0L,
                            activeStreams = activeStreams,
                            expectedStreams = expectedStreams,
                            pendingCaptchaCount = pendingCaptchaCount,
                            errorCount = errorCount,
                            lastError = lastError,
                        )
                    }
                } catch (_: Throwable) {
                }
                maybeEnsureKernelHelperAlive()
                delay(1000)
            }
        }
    }

    private fun maybeEnsureKernelHelperAlive() {
        if (Application.peekBackend() !is WgQuickBackend) {
            lastKernelHelperCheckElapsedMs = 0L
            return
        }
        val now = SystemClock.elapsedRealtime()
        if (now - lastKernelHelperCheckElapsedMs < KERNEL_HELPER_CHECK_INTERVAL_MS) return
        lastKernelHelperCheckElapsedMs = now
        scope.launch {
            if (!TurnBackend.waitForVpnServiceRegistered(1)) {
                ensureKernelSocketProtection()
            }
        }
    }

    fun recordRuntimeError(tunnelName: String, message: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val previous = instance.runtimeStatus
        val expected = previous.expectedStreams
        val active = previous.activeStreams.coerceAtLeast(0)
        val mode = if (expected > 0) {
            context.getString(
                com.wireguard.android.R.string.turn_mode_stopped_streams,
                active.coerceAtMost(expected),
                expected,
            )
        } else {
            context.getString(com.wireguard.android.R.string.turn_mode_stopped_error)
        }
        instance.runtimeStatus = instance.runtimeStatus.copy(
            modeInfo = mode,
            pendingCaptchaCount = CaptchaCoordinator.pendingCount(),
            errorCount = instance.runtimeStatus.errorCount + 1,
            lastError = message,
            clientPublicIp = "",
            relayIps = emptyList(),
            lastSyncUnix = 0L,
        )
    }

    private fun isQuotaError(message: String): Boolean {
        val normalized = message.lowercase()
        return normalized.contains("allocation quota reached") ||
            normalized.contains("error 486") ||
            normalized.contains("486:")
    }

    private fun getRuntimeLastError(): String? {
        return try {
            val json = TurnBackend.wgTurnProxyGetRuntimeStatusJson()
            if (json.isNullOrBlank()) return null
            org.json.JSONObject(json).optString("last_error").trim().ifBlank { null }
        } catch (_: Throwable) {
            null
        }
    }

    private fun isLocalPortAvailable(port: Int): Boolean {
        return try {
            ServerSocket().use { tcp ->
                tcp.reuseAddress = false
                tcp.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            }
            DatagramSocket(null).use { udp ->
                udp.reuseAddress = false
                udp.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            }
            true
        } catch (_: Throwable) {
            false
        }
    }

    suspend fun retryLastFailedTunnel(tunnelName: String): Boolean {
        val settings = activeSettings ?: return false
        if (activeTunnelName != tunnelName) return false
        userInitiatedStop = false
        TurnNotificationManager.clearTurnFailureNotification(context)
        lastFailedTunnelName = null
        CaptchaCoordinator.beginAttempt(clearFailureState = true)
        resetRuntimeForNewAttempt(
            tunnelName,
            context.getString(com.wireguard.android.R.string.turn_mode_retrying_proxy),
        )
        return startForTunnelInternal(tunnelName, settings, activePublicKey, activeKeepaliveSec)
    }

    private fun resetRuntimeForNewAttempt(tunnelName: String, modeInfo: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val expected = activeSettings?.streams?.coerceAtLeast(0) ?: instance.runtimeStatus.expectedStreams
        instance.runtimeStatus = instance.runtimeStatus.copy(
            modeInfo = modeInfo,
            expectedStreams = expected,
            pendingCaptchaCount = CaptchaCoordinator.pendingCount(),
            errorCount = 0,
            lastError = "",
            clientPublicIp = "",
            relayIps = emptyList(),
            lastSyncUnix = 0L,
        )
    }

    fun shouldAlertCaptchaNotification(): Boolean {
        val tunnelName = activeTunnelName ?: return false
        val settings = activeSettings ?: return false
        val instance = instances[tunnelName] ?: return false
        val expected = settings.streams.coerceAtLeast(0)
        if (expected <= 0) return false
        val active = instance.runtimeStatus.activeStreams.coerceAtLeast(0)
        val remaining = (expected - active).coerceAtLeast(0)
        if (remaining <= 0) return false
        val streamsPerCred = settings.streamsPerCred.coerceAtLeast(1)
        return active == 0 || remaining <= streamsPerCred
    }

    fun onCaptchaPendingChanged(pendingCount: Int) {
        val tunnelName = activeTunnelName ?: return
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val normalized = pendingCount.coerceAtLeast(0)
        val previous = instance.runtimeStatus
        val modeInfo = when {
            normalized > 0 -> context.getString(
                com.wireguard.android.R.string.turn_mode_waiting_captcha_tap,
                normalized,
            )
            previous.pendingCaptchaCount > 0 && !instance.running &&
                previous.modeInfo == context.getString(com.wireguard.android.R.string.turn_mode_retrying_proxy) ->
                context.getString(com.wireguard.android.R.string.turn_mode_retrying_proxy)
            previous.pendingCaptchaCount > 0 && !instance.running ->
                context.getString(com.wireguard.android.R.string.turn_mode_starting_proxy)
            else -> previous.modeInfo
        }
        instance.runtimeStatus = previous.copy(
            modeInfo = modeInfo,
            pendingCaptchaCount = normalized,
        )
    }

    /**
     * Returns a string representation of the network type (wifi, cellular, lan, unknown).
     */
    private fun getNetworkTypeString(network: Network?): String {
        if (network == null) return "unknown"

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(network)

        return when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "lan"
            else -> "unknown"
        }
    }

    private fun localizeModeInfo(modeInfo: String): String {
        val normalized = modeInfo.trim()
        val lower = normalized.lowercase()
        return when {
            normalized.startsWith("TURN active", ignoreCase = true) ->
                context.getString(com.wireguard.android.R.string.turn_mode_active)
            (lower.contains("resolving") && lower.contains("public") && lower.contains("ip")) ->
                context.getString(com.wireguard.android.R.string.turn_mode_resolving_public_ip)
            lower.contains("public ip resolved") || lower.contains("public ip: resolved") ->
                context.getString(com.wireguard.android.R.string.turn_mode_public_ip_resolved)
            lower.contains("public ip unavailable") || lower.contains("public ip: unavailable") ->
                context.getString(com.wireguard.android.R.string.turn_mode_public_ip_unavailable)
            else -> modeInfo
        }
    }

    companion object {
        private const val TAG = "WireGuard/TurnProxyManager"
        private const val MAX_LOG_CHARS = 128 * 1024
        private const val JNI_WAIT_ATTEMPTS = 6
        private const val JNI_WAIT_STEP_MS = 1000L
        private const val JNI_RETRY_BACKOFF_MS = 200L
        private const val NETWORK_RESTART_GRACE_MS = 10_000L
        private const val KERNEL_HELPER_CHECK_INTERVAL_MS = 5_000L
    }
}
