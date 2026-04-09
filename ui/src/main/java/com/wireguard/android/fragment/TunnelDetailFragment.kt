/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.view.MenuProvider
import androidx.fragment.app.commit
import androidx.fragment.app.FragmentTransaction
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.databinding.TunnelDetailFragmentBinding
import com.wireguard.android.databinding.TunnelDetailPeerBinding
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.turn.CaptchaCoordinator
import com.wireguard.android.util.QuantityFormatter
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Fragment that shows details about a specific tunnel.
 */
class TunnelDetailFragment : BaseFragment(), MenuProvider {
    private var binding: TunnelDetailFragmentBinding? = null
    private var lastState = Tunnel.State.TOGGLE
    private var timerActive = true

    override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
        menuInflater.inflate(R.menu.tunnel_detail, menu)
    }

    override fun onMenuItemSelected(menuItem: MenuItem): Boolean {
        return when (menuItem.itemId) {
            R.id.menu_action_edit -> {
                val activity = activity ?: return true
                val containerId = if (activity.findViewById<View?>(R.id.detail_container) != null) {
                    R.id.detail_container
                } else {
                    R.id.list_detail_container
                }
                activity.supportFragmentManager.commit {
                    replace(containerId, TunnelEditorFragment())
                    setTransition(androidx.fragment.app.FragmentTransaction.TRANSIT_FRAGMENT_FADE)
                    addToBackStack(null)
                }
                true
            }
            else -> false
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        binding = TunnelDetailFragmentBinding.inflate(inflater, container, false)
        binding?.executePendingBindings()
        return binding?.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        requireActivity().addMenuProvider(this, viewLifecycleOwner, Lifecycle.State.RESUMED)
    }

    override fun onDestroyView() {
        binding = null
        super.onDestroyView()
    }

    override fun onResume() {
        super.onResume()
        timerActive = true
        lifecycleScope.launch {
            while (timerActive) {
                updateStats()
                delay(1000)
            }
        }
    }

    override fun onSelectedTunnelChanged(oldTunnel: ObservableTunnel?, newTunnel: ObservableTunnel?) {
        val binding = binding ?: return
        binding.tunnel = newTunnel
        if (newTunnel == null) {
            binding.config = null
        } else {
            lifecycleScope.launch {
                try {
                    binding.config = newTunnel.getConfigAsync()
                } catch (_: Throwable) {
                    binding.config = null
                }
            }
        }
        lastState = Tunnel.State.TOGGLE
        lifecycleScope.launch { updateStats() }
    }

    override fun onStop() {
        timerActive = false
        super.onStop()
    }

    override fun onViewStateRestored(savedInstanceState: Bundle?) {
        binding ?: return
        binding!!.fragment = this
        onSelectedTunnelChanged(null, selectedTunnel)
        super.onViewStateRestored(savedInstanceState)
    }

    private suspend fun updateStats() {
        val binding = binding ?: return
        val tunnel = binding.tunnel ?: return
        if (!isResumed) return
        val state = tunnel.state
        val status = Application.getTurnProxyManager().getRuntimeStatus(tunnel.name)
        if (state != Tunnel.State.UP && lastState == state &&
            status.modeInfo.isBlank() &&
            status.clientPublicIp.isBlank() &&
            status.relayIps.isEmpty() &&
            status.errorCount == 0
        ) return
        lastState = state
        try {
            if (state == Tunnel.State.UP) {
                val statistics = tunnel.getStatisticsAsync()
                for (i in 0 until binding.peersLayout.childCount) {
                    val peer: TunnelDetailPeerBinding = DataBindingUtil.getBinding(binding.peersLayout.getChildAt(i))
                        ?: continue
                    val publicKey = peer.item!!.publicKey
                    val peerStats = statistics.peer(publicKey)
                    if (peerStats == null || (peerStats.rxBytes == 0L && peerStats.txBytes == 0L)) {
                        peer.transferLabel.visibility = View.GONE
                        peer.transferText.visibility = View.GONE
                    } else {
                        peer.transferText.text = getString(
                            R.string.transfer_rx_tx,
                            QuantityFormatter.formatBytes(peerStats.rxBytes),
                            QuantityFormatter.formatBytes(peerStats.txBytes)
                        )
                        peer.transferLabel.visibility = View.VISIBLE
                        peer.transferText.visibility = View.VISIBLE
                    }
                    if (peerStats == null || peerStats.latestHandshakeEpochMillis == 0L) {
                        peer.latestHandshakeLabel.visibility = View.GONE
                        peer.latestHandshakeText.visibility = View.GONE
                    } else {
                        peer.latestHandshakeText.text = QuantityFormatter.formatEpochAgo(peerStats.latestHandshakeEpochMillis)
                        peer.latestHandshakeLabel.visibility = View.VISIBLE
                        peer.latestHandshakeText.visibility = View.VISIBLE
                    }
                }
            }
            updateTurnRuntime(binding, tunnel, state)
        } catch (e: Throwable) {
            for (i in 0 until binding.peersLayout.childCount) {
                val peer: TunnelDetailPeerBinding = DataBindingUtil.getBinding(binding.peersLayout.getChildAt(i))
                    ?: continue
                peer.transferLabel.visibility = View.GONE
                peer.transferText.visibility = View.GONE
                peer.latestHandshakeLabel.visibility = View.GONE
                peer.latestHandshakeText.visibility = View.GONE
            }
            updateTurnRuntime(binding, tunnel, state)
        }
    }

    private fun updateTurnRuntime(binding: TunnelDetailFragmentBinding, tunnel: ObservableTunnel, state: Tunnel.State) {
        if (tunnel.turnSettings?.enabled != true) {
            hideTurnRuntime(binding)
            return
        }

        val status = Application.getTurnProxyManager().getRuntimeStatus(tunnel.name)
        val isTurnRunning = Application.getTurnProxyManager().isRunning(tunnel.name)
        val isTunnelUp = state == Tunnel.State.UP
        val isStartFailure = status.lastError.contains("Failed to start TURN proxy", ignoreCase = true)
        val modeText = when {
            status.pendingCaptchaCount > 0 && status.modeInfo.isNotBlank() ->
                // Show a clear action hint, but only while the tunnel is actually enabled.
                if (isTunnelUp) "${status.modeInfo}\n\n${getString(R.string.turn_mode_tap_to_solve_hint)}" else status.modeInfo
            // Retry is meaningful only when TURN is stopped (startup failure), not for quota/partial-stream errors.
            (!isTurnRunning && isTunnelUp && isStartFailure && status.errorCount > 0 && status.modeInfo.isNotBlank()) ->
                "${status.modeInfo}\n\n${getString(R.string.turn_mode_tap_to_retry_hint)}"
            else -> status.modeInfo
        }
        setTurnField(binding.turnRuntimeModeLabel, binding.turnRuntimeModeText, modeText)
        val canOpenCaptcha = status.pendingCaptchaCount > 0 && isTunnelUp
        val canRetryTurn = !canOpenCaptcha && !isTurnRunning && isTunnelUp && isStartFailure && status.errorCount > 0
        val modeAction = when {
            canOpenCaptcha -> View.OnClickListener {
                CaptchaCoordinator.openPendingFromUi(requireContext())
            }
            canRetryTurn -> View.OnClickListener {
                lifecycleScope.launch {
                    Application.getTurnProxyManager().retryLastFailedTunnel(tunnel.name)
                }
            }
            else -> null
        }
        binding.turnRuntimeModeText.isClickable = modeAction != null
        binding.turnRuntimeModeText.isFocusable = modeAction != null
        binding.turnRuntimeModeText.setOnClickListener(
            modeAction
        )
        val isFullyActive = isTunnelUp &&
            isTurnRunning &&
            status.expectedStreams > 0 &&
            status.activeStreams >= status.expectedStreams &&
            status.pendingCaptchaCount <= 0
        val errorText = when {
            isFullyActive -> ""
            status.errorCount <= 0 -> ""
            status.lastError.isBlank() -> status.errorCount.toString()
            else -> getString(R.string.turn_runtime_error_details, status.errorCount, status.lastError)
        }
        setTurnField(binding.turnRuntimeErrorsLabel, binding.turnRuntimeErrorsText, errorText)
        val showNetworkDetails = state == Tunnel.State.UP && status.activeStreams > 0
        setTurnField(binding.turnRuntimeClientIpLabel, binding.turnRuntimeClientIpText, if (showNetworkDetails) status.clientPublicIp else "")
        setTurnField(binding.turnRuntimeRelayIpLabel, binding.turnRuntimeRelayIpText, if (showNetworkDetails) status.relayIps.joinToString(", ") else "")
        val lastSync = if (state == Tunnel.State.UP && status.lastSyncUnix > 0) {
            QuantityFormatter.formatEpochAgo(status.lastSyncUnix * 1000L)
        } else {
            ""
        }
        setTurnField(binding.turnRuntimeLastSyncLabel, binding.turnRuntimeLastSyncText, lastSync)
    }

    private fun hideTurnRuntime(binding: TunnelDetailFragmentBinding) {
        setTurnField(binding.turnRuntimeModeLabel, binding.turnRuntimeModeText, "")
        setTurnField(binding.turnRuntimeErrorsLabel, binding.turnRuntimeErrorsText, "")
        setTurnField(binding.turnRuntimeClientIpLabel, binding.turnRuntimeClientIpText, "")
        setTurnField(binding.turnRuntimeRelayIpLabel, binding.turnRuntimeRelayIpText, "")
        setTurnField(binding.turnRuntimeLastSyncLabel, binding.turnRuntimeLastSyncText, "")
    }

    private fun setTurnField(label: View, valueView: TextView, value: String) {
        if (value.isBlank()) {
            label.visibility = View.GONE
            valueView.visibility = View.GONE
            valueView.text = ""
            return
        }
        valueView.text = value
        label.visibility = View.VISIBLE
        valueView.visibility = View.VISIBLE
    }
}
