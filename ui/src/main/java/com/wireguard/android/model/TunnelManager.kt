/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.model

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.SystemClock
import android.util.Log
import android.widget.Toast
import androidx.databinding.BaseObservable
import androidx.databinding.Bindable
import com.wireguard.android.Application
import com.wireguard.android.Application.Companion.get
import com.wireguard.android.Application.Companion.getBackend
import com.wireguard.android.Application.Companion.getTunnelManager
import com.wireguard.android.Application.Companion.getTurnProxyManager
import com.wireguard.android.BR
import com.wireguard.android.R
import com.wireguard.android.backend.Statistics
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.configStore.ConfigStore
import com.wireguard.android.databinding.ObservableSortedKeyedArrayList
import com.wireguard.android.turn.TurnConfigProcessor
import com.wireguard.android.turn.TurnSettings
import com.wireguard.android.turn.TurnSettingsStore
import com.wireguard.android.updater.OtaUpdater
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.UserKnobs
import com.wireguard.android.util.applicationScope
import com.wireguard.config.Config
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Maintains and mediates changes to the set of available WireGuard tunnels,
 */
class TunnelManager(
    private val configStore: ConfigStore,
    private val turnSettingsStore: TurnSettingsStore,
) : BaseObservable() {
    private val tunnels = CompletableDeferred<ObservableSortedKeyedArrayList<String, ObservableTunnel>>()
    private val context: Context = get()
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val tunnelMap: ObservableSortedKeyedArrayList<String, ObservableTunnel> = ObservableSortedKeyedArrayList(TunnelComparator)
    private val otaHandshakeWatchers = mutableMapOf<String, Job>()
    private val turnReevaluationWatchers = mutableMapOf<String, Job>()
    private val turnAutoState = mutableMapOf<String, TurnAutoState>()
    private var haveLoaded = false
    @Volatile private var lastUnderlyingNetworkHandle: Long = -1L
    @Volatile private var underlyingNetworkRefreshJob: Job? = null

    private data class TurnAutoState(
        val lastNetworkHandle: Long = -1L,
        val lastCheckElapsedMs: Long = 0L,
    )

    private val underlyingNetworkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = scheduleUnderlyingNetworkRefresh()
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = scheduleUnderlyingNetworkRefresh()
        override fun onLost(network: Network) = scheduleUnderlyingNetworkRefresh()
    }

    private suspend fun addToList(name: String, config: Config?, state: Tunnel.State): ObservableTunnel = withContext(Dispatchers.Main.immediate) {
        val tunnel = ObservableTunnel(this@TunnelManager, name, config, state)
        val turnSettings = withContext(Dispatchers.IO) {
            var loaded = turnSettingsStore.load(name)
            if (loaded == null && config != null) {
                loaded = TurnConfigProcessor.extractTurnSettings(config)
                if (loaded != null) {
                    turnSettingsStore.save(name, loaded)
                }
            }
            loaded
        }
        tunnel.onTurnSettingsChanged(turnSettings)
        tunnelMap.add(tunnel)
        tunnel
    }

    suspend fun getTunnels(): ObservableSortedKeyedArrayList<String, ObservableTunnel> = tunnels.await()

    suspend fun create(
        name: String,
        config: Config?,
        turnSettings: TurnSettings? = null,
    ): ObservableTunnel = withContext(Dispatchers.Main.immediate) {
        if (Tunnel.isNameInvalid(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_invalid_name))
        if (tunnelMap.containsKey(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_already_exists, name))
        
        val configWithTurn = TurnConfigProcessor.injectTurnSettings(config!!, turnSettings)
        val savedConfig = withContext(Dispatchers.IO) { configStore.create(name, configWithTurn) }
        withContext(Dispatchers.IO) { turnSettingsStore.save(name, turnSettings) }
        addToList(name, savedConfig, Tunnel.State.DOWN)
    }

    suspend fun delete(tunnel: ObservableTunnel) = withContext(Dispatchers.Main.immediate) {
        val originalState = tunnel.state
        val wasLastUsed = tunnel == lastUsedTunnel
        // Make sure nothing touches the tunnel.
        if (wasLastUsed)
            lastUsedTunnel = null
        tunnelMap.remove(tunnel)
        try {
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
            try {
                withContext(Dispatchers.IO) {
                    configStore.delete(tunnel.name)
                    turnSettingsStore.delete(tunnel.name)
                }
            } catch (e: Throwable) {
                if (originalState == Tunnel.State.UP)
                    withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.UP, tunnel.config) }
                throw e
            }
        } catch (e: Throwable) {
            // Failure, put the tunnel back.
            tunnelMap.add(tunnel)
            if (wasLastUsed)
                lastUsedTunnel = tunnel
            throw e
        }
    }

    @get:Bindable
    var lastUsedTunnel: ObservableTunnel? = null
        private set(value) {
            if (value == field) return
            field = value
            notifyPropertyChanged(BR.lastUsedTunnel)
            applicationScope.launch { UserKnobs.setLastUsedTunnel(value?.name) }
        }

    suspend fun getTunnelConfig(tunnel: ObservableTunnel): Config = withContext(Dispatchers.Main.immediate) {
        val config = withContext(Dispatchers.IO) { configStore.load(tunnel.name) }
        val extractedTurn = TurnConfigProcessor.extractTurnSettings(config)
        if (extractedTurn != null) {
            withContext(Dispatchers.IO) {
                turnSettingsStore.save(tunnel.name, extractedTurn)
            }
            tunnel.onTurnSettingsChanged(extractedTurn)
        }
        tunnel.onConfigChanged(config)!!
    }

    fun onCreate() {
        runCatching {
            connectivityManager.registerNetworkCallback(
                android.net.NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                underlyingNetworkCallback,
            )
        }.onFailure {
            Log.w(TAG, "Unable to register non-VPN network callback", it)
        }
        lastUnderlyingNetworkHandle = selectUnderlyingNetwork(connectivityManager)?.networkHandle ?: 0L
        applicationScope.launch {
            try {
                val present = withContext(Dispatchers.IO) { configStore.enumerate() }
                onTunnelsLoaded(present)
                applicationScope.launch {
                    try {
                        val running = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
                        onBackendRunningTunnelsLoaded(running.toSet())
                    } catch (e: Throwable) {
                        Log.e(TAG, Log.getStackTraceString(e))
                    }
                }
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    private suspend fun onTunnelsLoaded(present: Iterable<String>) {
        for (name in present)
            addToList(name, null, Tunnel.State.DOWN)
        applicationScope.launch(Dispatchers.IO) {
            val lastUsedName = UserKnobs.lastUsedTunnel.first()
            withContext(Dispatchers.Main.immediate) {
                if (lastUsedName != null)
                    lastUsedTunnel = tunnelMap[lastUsedName]
                haveLoaded = true
                tunnels.complete(tunnelMap)
            }
            restoreState(false)
        }
    }

    private suspend fun onBackendRunningTunnelsLoaded(running: Set<String>) {
        if (running.isEmpty()) return
        for (tunnel in tunnelMap) {
            tunnel.onStateChanged(if (running.contains(tunnel.name)) Tunnel.State.UP else Tunnel.State.DOWN)
        }
        reconcileTurnForRunningTunnels(running)
        applicationScope.launch {
            try {
                saveState()
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    private suspend fun reconcileTurnForRunningTunnels(running: Set<String>) {
        if (running.isEmpty()) return
        for (tunnel in tunnelMap) {
            if (!running.contains(tunnel.name)) continue
            val config = withContext(Dispatchers.IO) { configStore.load(tunnel.name) }
            tunnel.onConfigChanged(config)
            val turn = tunnel.turnSettings ?: TurnConfigProcessor.extractTurnSettings(config)?.also {
                withContext(Dispatchers.IO) { turnSettingsStore.save(tunnel.name, it) }
                tunnel.onTurnSettingsChanged(it)
            } ?: continue
            if (!turn.enabled) continue
            val publicKey = try {
                config.`interface`.keyPair.publicKey.toBase64()
            } catch (_: Throwable) {
                ""
            }
            val keepaliveSec = try {
                config.peers.firstOrNull()?.persistentKeepalive?.orElse(0) ?: 0
            } catch (_: Throwable) {
                0
            }
            val started = withContext(Dispatchers.IO) {
                getTurnProxyManager().onTunnelEstablished(tunnel.name, turn, publicKey, keepaliveSec)
            }
            if (!started) {
                Log.w(TAG, "TURN reconciliation failed for already-running tunnel ${tunnel.name}")
            } else {
                Log.i(TAG, "TURN reconciled for already-running tunnel ${tunnel.name}")
                scheduleAutoOtaAfterFirstHandshake(tunnel)
            }
        }
    }

    private fun refreshTunnelStates() {
        applicationScope.launch {
            try {
                val running = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
                for (tunnel in tunnelMap)
                    tunnel.onStateChanged(if (running.contains(tunnel.name)) Tunnel.State.UP else Tunnel.State.DOWN)
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    /**
     * Syncs tunnel UP/DOWN states from the backend without initiating any new connections.
     *
     * This is useful for "external" transitions (e.g. when the system revokes our VPN because
     * another VPN app/build took over), so UI switches don't get stuck showing stale state.
     */
    fun syncTunnelStatesFromBackend(reason: String = "external") {
        Log.w(TAG, "Syncing tunnel states from backend ($reason)")
        refreshTunnelStates()
    }

    suspend fun restoreState(force: Boolean) {
        if (!haveLoaded || (!force && !UserKnobs.restoreOnBoot.first()))
            return
        val previouslyRunning = UserKnobs.runningTunnels.first()
        if (previouslyRunning.isEmpty()) return
        withContext(Dispatchers.IO) {
            try {
                tunnelMap.filter { previouslyRunning.contains(it.name) }.map { async(Dispatchers.IO + SupervisorJob()) { setTunnelState(it, Tunnel.State.UP, forceTurnStart = true) } }
                    .awaitAll()
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    suspend fun saveState() {
        UserKnobs.setRunningTunnels(tunnelMap.filter { it.state == Tunnel.State.UP }.map { it.name }.toSet())
    }

    suspend fun setTunnelConfig(
        tunnel: ObservableTunnel,
        config: Config,
        turnSettings: TurnSettings? = null,
    ): Config = withContext(Dispatchers.Main.immediate) {
        val originalState = tunnel.state
        if (originalState == Tunnel.State.UP) {
            setTunnelState(tunnel, Tunnel.State.DOWN)
        }
        
        val configWithTurn = TurnConfigProcessor.injectTurnSettings(config, turnSettings)
        val result = tunnel.onConfigChanged(
            withContext(Dispatchers.IO) {
                configStore.save(tunnel.name, configWithTurn)
                configWithTurn
            },
        )!!
            .also {
                withContext(Dispatchers.IO) {
                    turnSettingsStore.save(tunnel.name, turnSettings)
                    tunnel.onTurnSettingsChanged(turnSettingsStore.load(tunnel.name))
                }
            }
        
        if (originalState == Tunnel.State.UP) {
            setTunnelState(tunnel, Tunnel.State.UP)
        }
        
        result
    }

    suspend fun setTunnelName(tunnel: ObservableTunnel, name: String): String = withContext(Dispatchers.Main.immediate) {
        if (Tunnel.isNameInvalid(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_invalid_name))
        if (tunnelMap.containsKey(name)) {
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_already_exists, name))
        }
        val originalState = tunnel.state
        val wasLastUsed = tunnel == lastUsedTunnel
        // Make sure nothing touches the tunnel.
        if (wasLastUsed)
            lastUsedTunnel = null
        tunnelMap.remove(tunnel)
        var throwable: Throwable? = null
        var newName: String? = null
        try {
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
            withContext(Dispatchers.IO) {
                configStore.rename(tunnel.name, name)
                turnSettingsStore.rename(tunnel.name, name)
            }
            newName = tunnel.onNameChanged(name)
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.UP, tunnel.config) }
        } catch (e: Throwable) {
            throwable = e
            // On failure, we don't know what state the tunnel might be in. Fix that.
            getTunnelState(tunnel)
        }
        // Add the tunnel back to the manager, under whatever name it thinks it has.
        tunnelMap.add(tunnel)
        if (wasLastUsed)
            lastUsedTunnel = tunnel
        if (throwable != null)
            throw throwable
        newName!!
    }

    suspend fun setTunnelState(tunnel: ObservableTunnel, state: Tunnel.State): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        setTunnelState(tunnel, state, forceTurnStart = false)
    }

    suspend fun setTunnelState(tunnel: ObservableTunnel, state: Tunnel.State, forceTurnStart: Boolean): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        if (state == Tunnel.State.DOWN || state == Tunnel.State.TOGGLE) {
            val trace = Throwable().stackTrace
                .drop(1)
                .take(20)
                .joinToString(" <- ") { "${it.className}.${it.methodName}:${it.lineNumber}" }
            Log.w(TAG, "setTunnelState request for ${tunnel.name}: requested=$state current=${tunnel.state} forceTurnStart=$forceTurnStart via $trace")
        }
        if (state == tunnel.state) {
            if (state != Tunnel.State.UP) {
                cancelAutoOtaWatcher(tunnel.name)
                cancelTurnAutoWatcher(tunnel.name)
                turnAutoState.remove(tunnel.name)
            }
            return@withContext state
        }
        
        // If we are already UP and someone (like AlwaysOnCallback) requests UP again,
        // double check with backend if it is really running.
        if (state == Tunnel.State.UP && tunnel.state == Tunnel.State.UP) {
            val runningNames = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
            if (runningNames.contains(tunnel.name)) {
                Log.d(TAG, "Skip redundant UP call for ${tunnel.name}, already running")
                return@withContext state
            }
        }

        var newState = tunnel.state
        var throwable: Throwable? = null
        try {
            var configToUse = tunnel.getConfigAsync()
            val turn = tunnel.turnSettings
            val turnEnabled = turn != null && turn.enabled
            var useTurnForThisStart = false
            
            // Determine if TURN should be started after tunnel is established
            // This happens when explicitly requesting UP, or TOGGLE from DOWN state
            val shouldStartTurn = state == Tunnel.State.UP || (state == Tunnel.State.TOGGLE && tunnel.state == Tunnel.State.DOWN)
            
            // Stop TURN when tunnel goes DOWN
            val shouldStopTurn = state == Tunnel.State.DOWN || (state == Tunnel.State.TOGGLE && tunnel.state == Tunnel.State.UP)

            if (turnEnabled) {
                if (shouldStartTurn) {
                    getTurnProxyManager().setRuntimeStatusModeInfo(
                        tunnel.name,
                        context.getString(R.string.turn_mode_checking_network),
                    )
                    useTurnForThisStart = if (forceTurnStart) {
                        true
                    } else if (turn.autoSwitchTurn) {
                        shouldUseTurnByAutoSwitch(turn)
                    } else {
                        true
                    }
                    if (useTurnForThisStart) {
                        getTurnProxyManager().setRuntimeStatusModeInfo(
                            tunnel.name,
                            context.getString(R.string.turn_mode_starting_proxy),
                        )
                        configToUse = TurnConfigProcessor.modifyConfigForActiveTurn(configToUse, turn)
                    } else {
                        Log.i(TAG, "TURN auto-switch: using direct WG path for ${tunnel.name}")
                        getTurnProxyManager().markUsingDirectConnection(tunnel.name)
                    }
                } else if (shouldStopTurn) {
                    Log.w(TAG, "Stopping TURN because tunnel state transition requested stop for ${tunnel.name}: requested=$state current=${tunnel.state}")
                    cancelAutoOtaWatcher(tunnel.name)
                    cancelTurnAutoWatcher(tunnel.name)
                    turnAutoState.remove(tunnel.name)
                    withContext(Dispatchers.IO) {
                        getTurnProxyManager().stopForTunnel(tunnel.name)
                    }
                }
            }

            newState = withContext(Dispatchers.IO) { getBackend().setState(tunnel, state, configToUse) }

            // Reflect backend state immediately so UI/switch bindings don't keep seeing the
            // old DOWN state while TURN bootstrap is still resolving VK/TURN/DTLS.
            tunnel.onStateChanged(newState)
            saveState()

            // NEW: Start TURN AFTER tunnel is established
            // This ensures VpnService.protect() will work for TURN sockets
            if (shouldStartTurn && newState == Tunnel.State.UP) {
                if (turnEnabled && useTurnForThisStart) {
                    Log.d(TAG, "Tunnel established, starting TURN proxy...")
                    val publicKey = try {
                        configToUse.`interface`.keyPair.publicKey.toBase64()
                    } catch (_: Throwable) {
                        ""
                    }
                    val keepaliveSec = try {
                        configToUse.peers.firstOrNull()?.persistentKeepalive?.orElse(0) ?: 0
                    } catch (_: Throwable) {
                        0
                    }
                    val turnStarted = withContext(Dispatchers.IO) {
                        getTurnProxyManager().onTunnelEstablished(tunnel.name, turn, publicKey, keepaliveSec)
                    }
                    if (!turnStarted) {
                        Log.w(TAG, "TURN proxy start returned false, leaving tunnel UP for ${tunnel.name}")
                    }
                } else {
                    Log.i(TAG, "TURN startup skipped for tunnel ${tunnel.name}")
                    if (turnEnabled) getTurnProxyManager().markUsingDirectConnection(tunnel.name)
                }
                scheduleAutoOtaAfterFirstHandshake(tunnel)
                if (turnEnabled && turn.autoSwitchTurn) {
                    scheduleTurnAutoReevaluation(tunnel, immediate = false)
                }
            } else if (newState != Tunnel.State.UP) {
                cancelAutoOtaWatcher(tunnel.name)
                cancelTurnAutoWatcher(tunnel.name)
            }

            if (newState == Tunnel.State.UP) {
                lastUsedTunnel = tunnel
            }
        } catch (e: Throwable) {
            throwable = e
        }
        tunnel.onStateChanged(newState)
        saveState()
        if (throwable != null)
            throw throwable
        newState
    }

    class IntentReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent?) {
            applicationScope.launch {
                val manager = getTunnelManager()
                if (intent == null) return@launch
                val action = intent.action ?: return@launch
                if ("com.wireguard.android.action.REFRESH_TUNNEL_STATES" == action) {
                    manager.refreshTunnelStates()
                    return@launch
                }
                if (!UserKnobs.allowRemoteControlIntents.first())
                    return@launch
                val state = when (action) {
                    "com.wireguard.android.action.SET_TUNNEL_UP" -> Tunnel.State.UP
                    "com.wireguard.android.action.SET_TUNNEL_DOWN" -> Tunnel.State.DOWN
                    else -> return@launch
                }
                val tunnelName = intent.getStringExtra("tunnel") ?: return@launch
                val tunnels = manager.getTunnels()
                val tunnel = tunnels[tunnelName] ?: return@launch
                try {
                    manager.setTunnelState(tunnel, state)
                } catch (e: Throwable) {
                    Toast.makeText(context, ErrorMessages[e], Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun cancelAutoOtaWatcher(tunnelName: String) {
        otaHandshakeWatchers.remove(tunnelName)?.cancel()
    }

    private fun cancelTurnAutoWatcher(tunnelName: String) {
        turnReevaluationWatchers.remove(tunnelName)?.cancel()
    }

    private fun scheduleAutoOtaAfterFirstHandshake(tunnel: ObservableTunnel) {
        cancelAutoOtaWatcher(tunnel.name)
        val job = applicationScope.launch(Dispatchers.IO) {
            repeat(AUTO_OTA_HANDSHAKE_MAX_POLLS) { attempt ->
                if (tunnel.state != Tunnel.State.UP) {
                    return@launch
                }
                try {
                    val stats = getTunnelStatistics(tunnel)
                    if (hasAnyHandshake(stats)) {
                        Log.i(TAG, "WG handshake detected for ${tunnel.name}, triggering auto OTA check")
                        val turn = tunnel.turnSettings
                        if (turn != null && turn.enabled && turn.autoSwitchTurn) {
                            scheduleTurnAutoReevaluation(tunnel, immediate = false)
                        }
                        OtaUpdater.triggerAutoUpdateAfterTunnel()
                        return@launch
                    }
                } catch (e: Throwable) {
                    Log.d(TAG, "Waiting for first WG handshake for ${tunnel.name}: ${e.message}")
                }
                if (attempt + 1 < AUTO_OTA_HANDSHAKE_MAX_POLLS) {
                    delay(AUTO_OTA_HANDSHAKE_POLL_MS)
                }
            }
            Log.d(TAG, "Auto OTA check skipped for ${tunnel.name}: no WG handshake observed in time")
        }
        otaHandshakeWatchers[tunnel.name] = job
        job.invokeOnCompletion {
            otaHandshakeWatchers.remove(tunnel.name, job)
        }
    }

    private fun scheduleUnderlyingNetworkRefresh() {
        underlyingNetworkRefreshJob?.cancel()
        underlyingNetworkRefreshJob = applicationScope.launch(Dispatchers.IO) {
            delay(1500)
            val networkHandle = selectUnderlyingNetwork(connectivityManager)?.networkHandle ?: 0L
            if (networkHandle == lastUnderlyingNetworkHandle) {
                return@launch
            }
            lastUnderlyingNetworkHandle = networkHandle
            tunnelMap.toList().forEach { tunnel ->
                val turn = tunnel.turnSettings
                if (tunnel.state == Tunnel.State.UP && turn != null && turn.enabled && turn.autoSwitchTurn) {
                    scheduleTurnAutoReevaluation(tunnel, immediate = true)
                }
            }
        }
    }

    private fun scheduleTurnAutoReevaluation(tunnel: ObservableTunnel, immediate: Boolean) {
        cancelTurnAutoWatcher(tunnel.name)
        val job = applicationScope.launch(Dispatchers.IO) {
            if (!immediate) {
                delay(TURN_AUTO_REEVALUATE_DELAY_MS)
            }
            try {
                maybeReevaluateTurnForTunnel(tunnel, immediate)
            } catch (e: Throwable) {
                Log.e(TAG, "TURN auto-reevaluation failed for ${tunnel.name}", e)
            }
        }
        turnReevaluationWatchers[tunnel.name] = job
        job.invokeOnCompletion {
            turnReevaluationWatchers.remove(tunnel.name, job)
        }
    }

    private suspend fun maybeReevaluateTurnForTunnel(tunnel: ObservableTunnel, immediate: Boolean) {
        val turn = tunnel.turnSettings ?: return
        if (tunnel.state != Tunnel.State.UP || !turn.enabled || !turn.autoSwitchTurn) return

        val networkHandle = selectUnderlyingNetwork(connectivityManager)?.networkHandle ?: 0L
        val now = SystemClock.elapsedRealtime()
        val previous = turnAutoState[tunnel.name]
        val networkChanged = previous == null || previous.lastNetworkHandle != networkHandle
        if (!immediate && !networkChanged && previous != null && now - previous.lastCheckElapsedMs < TURN_AUTO_REEVALUATE_INTERVAL_MS) {
            return
        }
        turnAutoState[tunnel.name] = TurnAutoState(
            lastNetworkHandle = networkHandle,
            lastCheckElapsedMs = now,
        )

        val shouldUseTurn = shouldUseTurnByAutoSwitch(turn)
        val currentlyUsingTurn = getTurnProxyManager().isRunning(tunnel.name)
        if (shouldUseTurn == currentlyUsingTurn) {
            if (!shouldUseTurn) {
                getTurnProxyManager().markUsingDirectConnection(tunnel.name)
            }
            return
        }

        val reason = if (networkChanged) "underlying network changed" else "scheduled reevaluation"
        Log.i(TAG, "TURN auto-switch reevaluation for ${tunnel.name}: shouldUseTurn=$shouldUseTurn current=$currentlyUsingTurn ($reason)")
        reconfigureRunningTunnelTurnMode(tunnel, turn, shouldUseTurn)
    }

    private suspend fun reconfigureRunningTunnelTurnMode(tunnel: ObservableTunnel, turn: TurnSettings, useTurn: Boolean) {
        withContext(Dispatchers.Main.immediate) {
            if (tunnel.state != Tunnel.State.UP) return@withContext

            getTurnProxyManager().setRuntimeStatusModeInfo(
                tunnel.name,
                context.getString(R.string.turn_mode_checking_network),
            )

            val baseConfig = tunnel.getConfigAsync()
            val configToUse = if (useTurn) {
                TurnConfigProcessor.modifyConfigForActiveTurn(baseConfig, turn)
            } else {
                baseConfig
            }

            Log.w(TAG, "Reconfiguring TURN mode for ${tunnel.name}: useTurn=$useTurn, stopping current TURN instance first")

            withContext(Dispatchers.IO) {
                getTurnProxyManager().stopForTunnel(tunnel.name)
            }

            val newState = withContext(Dispatchers.IO) {
                getBackend().setState(tunnel, Tunnel.State.UP, configToUse)
            }
            tunnel.onStateChanged(newState)

            if (newState == Tunnel.State.UP) {
                if (useTurn) {
                    val publicKey = try {
                        baseConfig.`interface`.keyPair.publicKey.toBase64()
                    } catch (_: Throwable) {
                        ""
                    }
                    val keepaliveSec = try {
                        baseConfig.peers.firstOrNull()?.persistentKeepalive?.orElse(0) ?: 0
                    } catch (_: Throwable) {
                        0
                    }
                    val started = withContext(Dispatchers.IO) {
                        getTurnProxyManager().onTunnelEstablished(tunnel.name, turn, publicKey, keepaliveSec)
                    }
                    if (!started) {
                        Log.w(TAG, "TURN reconfiguration failed for ${tunnel.name}, restoring direct path")
                        withContext(Dispatchers.IO) {
                            getBackend().setState(tunnel, Tunnel.State.UP, baseConfig)
                            getTurnProxyManager().stopForTunnel(tunnel.name)
                        }
                        tunnel.onStateChanged(Tunnel.State.UP)
                        getTurnProxyManager().markUsingDirectConnection(tunnel.name)
                    }
                } else {
                    getTurnProxyManager().markUsingDirectConnection(tunnel.name)
                }
                scheduleAutoOtaAfterFirstHandshake(tunnel)
                saveState()
            }
        }
    }

    private fun hasAnyHandshake(stats: Statistics): Boolean {
        return stats.peers().any { key ->
            val peer = stats.peer(key) ?: return@any false
            peer.latestHandshakeEpochMillis > 0L
        }
    }

    suspend fun getTunnelState(tunnel: ObservableTunnel): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        tunnel.onStateChanged(withContext(Dispatchers.IO) { getBackend().getState(tunnel) })
    }

    suspend fun getTunnelStatistics(tunnel: ObservableTunnel): Statistics = withContext(Dispatchers.Main.immediate) {
        tunnel.onStatisticsChanged(withContext(Dispatchers.IO) { getBackend().getStatistics(tunnel) })!!
    }

    private suspend fun shouldUseTurnByAutoSwitch(turn: TurnSettings): Boolean = withContext(Dispatchers.IO) {
        val globalReachable = probeUrl(PROBE_GLOBAL_URL)
        if (globalReachable) {
            Log.i(TAG, "TURN auto-switch: global internet reachable, TURN disabled for this connect")
            return@withContext false
        }
        val whitelistReachable = probeUrl(PROBE_WHITELIST_URL)
        if (whitelistReachable) {
            Log.i(TAG, "TURN auto-switch: whitelist-only network detected, TURN enabled")
            return@withContext true
        }
        // If checks are inconclusive (common on unstable/filtered networks), prefer TURN to avoid
        // breaking connectivity when direct WG path is blocked.
        Log.w(TAG, "TURN auto-switch: probes inconclusive, defaulting to TURN enabled for this connect")
        true
    }

    private fun probeUrl(url: String): Boolean {
        val network = selectUnderlyingNetwork(connectivityManager)
        if (network != null) {
            return probeUrlOnNetwork(network, url)
        }
        return probeUrlDirect(url)
    }

    private fun probeUrlOnNetwork(network: Network, url: String): Boolean {
        return try {
            val conn = network.openConnection(URL(url)) as HttpURLConnection
            conn.apply {
                instanceFollowRedirects = true
                connectTimeout = 5000
                readTimeout = 5000
                requestMethod = "GET"
                setRequestProperty("User-Agent", Application.USER_AGENT)
            }
            conn.connect()
            val code = conn.responseCode
            code in 200..399
        } catch (_: Throwable) {
            false
        }
    }

    private fun probeUrlDirect(url: String): Boolean {
        return try {
            val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = true
                connectTimeout = 5000
                readTimeout = 5000
                requestMethod = "GET"
                setRequestProperty("User-Agent", Application.USER_AGENT)
            }
            conn.connect()
            val code = conn.responseCode
            code in 200..399
        } catch (_: Throwable) {
            false
        }
    }

    private fun selectUnderlyingNetwork(cm: ConnectivityManager): Network? {
        val active = cm.activeNetwork?.takeIf { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@takeIf false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        if (active != null) return active

        val all = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
            network to caps
        }
        return all.firstOrNull { (_, caps) -> caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) }?.first
            ?: all.firstOrNull()?.first
    }

    companion object {
        private const val TAG = "WireGuard/TunnelManager"
        private const val PROBE_GLOBAL_URL = "https://connectivitycheck.gstatic.com/generate_204"
        // Use a VK endpoint as the whitelist probe, since TURN requires VK reachability anyway.
        private const val PROBE_WHITELIST_URL = "https://login.vk.ru"
        private const val AUTO_OTA_HANDSHAKE_POLL_MS = 2000L
        private const val AUTO_OTA_HANDSHAKE_MAX_POLLS = 15
        private const val TURN_AUTO_REEVALUATE_DELAY_MS = 2500L
        private const val TURN_AUTO_REEVALUATE_INTERVAL_MS = 10 * 60 * 1000L
    }
}
