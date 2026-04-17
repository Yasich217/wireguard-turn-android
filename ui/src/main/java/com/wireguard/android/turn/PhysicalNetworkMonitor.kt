/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import java.util.concurrent.ConcurrentHashMap

/**
 * Monitors physical networks (WiFi, Cellular) and provides the "best" available one.
 * Ignores VPN interfaces to avoid tracking our own tunnel and prefers the
 * currently active non-VPN network when one exists.
 */
class PhysicalNetworkMonitor(context: Context) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    private val _bestNetwork = MutableStateFlow<Network?>(null)
    
    /**
     * Flow of the best available physical network.
     * Includes a 1500ms debounce to filter out rapid transitions and flickering.
     */
    val bestNetwork = _bestNetwork.asStateFlow()
        .debounce(1500)
        .distinctUntilChanged()

    /**
     * Synchronously get the current best network without debounce.
     */
    val currentNetwork: Network?
        get() = _bestNetwork.value

    private val networks = ConcurrentHashMap<Network, NetworkCapabilities>()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // Ignore VPNs to avoid feedback loops with our own tunnel
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
            
            // We only care about networks with internet
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                networks.remove(network)
            } else {
                networks[network] = caps
            }
            update()
        }

        override fun onLost(network: Network) {
            networks.remove(network)
            update()
        }
    }

    private fun update() {
        val active = cm.activeNetwork?.takeIf { network ->
            val caps = networks[network] ?: cm.getNetworkCapabilities(network) ?: return@takeIf false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        if (active != null) {
            _bestNetwork.value = active
            return
        }

        val validated = networks.entries.firstOrNull { entry ->
            entry.value.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }?.key
        _bestNetwork.value = validated ?: networks.keys.firstOrNull()
    }

    fun start() {
        // Initial state: identify current best physical network before registering callback
        // We look through all networks because activeNetwork might be the VPN itself
        cm.allNetworks.forEach { network ->
            val caps = cm.getNetworkCapabilities(network)
            if (caps != null && 
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && 
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                networks[network] = caps
            }
        }
        update()

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(request, callback)
    }

    fun stop() {
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            // Ignore
        }
        networks.clear()
        _bestNetwork.value = null
    }
}
