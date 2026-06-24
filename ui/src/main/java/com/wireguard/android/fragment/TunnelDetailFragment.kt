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
import com.wireguard.android.turn.TurnSettings
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
                updateStats(refreshPeerStats = true)
                delay(STATS_REFRESH_MS)
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
        lifecycleScope.launch { updateStats(refreshPeerStats = true) }
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

    private suspend fun updateStats(refreshPeerStats: Boolean = false) {
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
            if (state == Tunnel.State.UP && refreshPeerStats) {
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
        val turn = tunnel.turnSettings
        if (turn?.enabled != true) {
            hideTurnSection(binding)
            return
        }
        showTurnSection(binding)

        val status = Application.getTurnProxyManager().getRuntimeStatus(tunnel.name)
        binding.turnVkLinkText.text = TurnSettings.normalizeVkCallHash(turn.vkLink)
        binding.turnOptionsText.text = buildTurnOptionsSummary(turn, status)
        val isTurnRunning = Application.getTurnProxyManager().isRunning(tunnel.name)
        val isTunnelUp = state == Tunnel.State.UP
        val isStartFailure = status.lastError.contains("Failed to start TURN proxy", ignoreCase = true)
        val isCaptchaWait = isCaptchaWaitError(status.lastError)
        val streamsText = when {
            status.expectedStreams > 0 -> "${status.activeStreams}/${status.expectedStreams}"
            status.activeStreams > 0 -> status.activeStreams.toString()
            else -> ""
        }
        setTurnField(binding.turnRuntimeModeLabel, binding.turnRuntimeModeText, streamsText)
        val remainingStreams = (status.expectedStreams - status.activeStreams).coerceAtLeast(0)
        val connectionText = when {
            status.pendingCaptchaCount > 0 && status.modeInfo.isNotBlank() ->
                // Show a clear action hint, but only while the tunnel is actually enabled.
                if (isTunnelUp) {
                    "${getString(R.string.turn_runtime_captcha_pending, remainingStreams.coerceAtLeast(status.pendingCaptchaCount))}\n\n${getString(R.string.turn_mode_tap_to_solve_hint)}"
                } else {
                    getString(R.string.turn_runtime_captcha_pending, remainingStreams.coerceAtLeast(status.pendingCaptchaCount))
                }
            // Retry is meaningful only when TURN is stopped (startup failure), not for quota/partial-stream errors.
            (!isTurnRunning && isTunnelUp && isStartFailure && status.errorCount > 0 && status.modeInfo.isNotBlank()) ->
                "${status.modeInfo}\n\n${getString(R.string.turn_mode_tap_to_retry_hint)}"
            status.activeStreams > 0 && isCaptchaWait ->
                getString(R.string.turn_runtime_captcha_retry, remainingStreams)
            status.activeStreams > 0 && isQuotaError(status.lastError) ->
                getString(R.string.turn_runtime_quota, remainingStreams)
            status.activeStreams > 0 && isVKCredentialsRetryWaitError(status.lastError) ->
                getString(R.string.turn_runtime_credentials_retry, remainingStreams)
            status.activeStreams > 0 && remainingStreams > 0 ->
                getString(R.string.turn_runtime_connecting_streams, remainingStreams)
            status.activeStreams > 0 ->
                getString(R.string.turn_runtime_connection_working)
            else -> status.modeInfo
        }
        setTurnField(binding.turnRuntimeErrorsLabel, binding.turnRuntimeErrorsText, connectionText)
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
        binding.turnRuntimeErrorsText.isClickable = modeAction != null
        binding.turnRuntimeErrorsText.isFocusable = modeAction != null
        binding.turnRuntimeErrorsText.setOnClickListener(
            modeAction
        )
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

    private fun isQuotaError(message: String): Boolean {
        val normalized = message.lowercase()
        return normalized.contains("allocation quota reached") ||
            normalized.contains("error 486") ||
            normalized.contains("486:")
    }

    private fun isVKCredentialsRetryWaitError(message: String): Boolean {
        val normalized = message.lowercase()
        return normalized.contains("vk_profile_retry_wait") ||
            normalized.contains("rate limit reached") ||
            normalized.contains("error_code:29")
    }

    private fun hideTurnRuntime(binding: TunnelDetailFragmentBinding) {
        binding.turnOptionsText.text = ""
        setTurnField(binding.turnRuntimeModeLabel, binding.turnRuntimeModeText, "")
        setTurnField(binding.turnRuntimeErrorsLabel, binding.turnRuntimeErrorsText, "")
        setTurnField(binding.turnRuntimeClientIpLabel, binding.turnRuntimeClientIpText, "")
        setTurnField(binding.turnRuntimeRelayIpLabel, binding.turnRuntimeRelayIpText, "")
        setTurnField(binding.turnRuntimeLastSyncLabel, binding.turnRuntimeLastSyncText, "")
    }

    private fun hideTurnSection(binding: TunnelDetailFragmentBinding) {
        binding.turnTitle.visibility = View.GONE
        binding.turnPeerLabel.visibility = View.GONE
        binding.turnPeerText.visibility = View.GONE
        binding.turnModeLabel.visibility = View.GONE
        binding.turnModeText.visibility = View.GONE
        binding.turnVkLinkLabel.visibility = View.GONE
        binding.turnVkLinkText.visibility = View.GONE
        binding.turnOptionsLabel.visibility = View.GONE
        binding.turnOptionsText.visibility = View.GONE
        hideTurnRuntime(binding)
    }

    private fun showTurnSection(binding: TunnelDetailFragmentBinding) {
        binding.turnTitle.visibility = View.VISIBLE
        binding.turnPeerLabel.visibility = View.VISIBLE
        binding.turnPeerText.visibility = View.VISIBLE
        binding.turnModeLabel.visibility = View.VISIBLE
        binding.turnModeText.visibility = View.VISIBLE
        binding.turnVkLinkLabel.visibility = View.VISIBLE
        binding.turnVkLinkText.visibility = View.VISIBLE
        binding.turnOptionsLabel.visibility = View.VISIBLE
        binding.turnOptionsText.visibility = View.VISIBLE
        binding.turnRuntimeModeLabel.visibility = View.GONE
        binding.turnRuntimeModeText.visibility = View.GONE
        binding.turnRuntimeErrorsLabel.visibility = View.GONE
        binding.turnRuntimeErrorsText.visibility = View.GONE
        binding.turnRuntimeClientIpLabel.visibility = View.GONE
        binding.turnRuntimeClientIpText.visibility = View.GONE
        binding.turnRuntimeRelayIpLabel.visibility = View.GONE
        binding.turnRuntimeRelayIpText.visibility = View.GONE
        binding.turnRuntimeLastSyncLabel.visibility = View.GONE
        binding.turnRuntimeLastSyncText.visibility = View.GONE
    }

    private fun buildTurnOptionsSummary(turn: TurnSettings, status: com.wireguard.android.turn.TurnProxyManager.TurnRuntimeStatus): String {
        val transport = if (turn.useUdp) "UDP" else "TCP"
        val watchdog = if (turn.watchdogTimeout > 0) "${turn.watchdogTimeout}s" else "off"
        val autoSwitch = if (turn.autoSwitchTurn) "on" else "off"
        val activeProfiles = status.vkCredentialsProfiles
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
        val cred = if (turn.autoSwitchVkCredentials && activeProfiles.size > 1) {
            activeProfiles.joinToString(",")
        } else {
            turn.vkCredentialsProfile
        }
        val primary = "$transport, streams=${turn.streams}, local=${turn.localPort}, spc=${turn.streamsPerCred}, wd=$watchdog, cred=$cred"
        val autoCreds = if (turn.autoSwitchVkCredentials) "on" else "off"
        val advanced = "startDelay=${TurnSettings.delaySecFromMs(turn.streamStartDelayMs)}s, startup=${turn.startupTimeoutSec}s, quotaBackoff=${turn.quotaBackoffSec}s, captchaBackoff=${turn.captchaBackoffSec}s, autoSwitch=$autoSwitch, autoCreds=$autoCreds"
        return "$primary | $advanced"
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

    companion object {
        private const val STATS_REFRESH_MS = 1_000L

        private fun isCaptchaWaitError(message: String): Boolean {
            val normalized = message.lowercase()
            return normalized.contains("captcha_wait_required") ||
                normalized.contains("captcha cache") ||
                normalized.contains("captcha limit")
        }
    }
}
