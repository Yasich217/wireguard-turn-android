/*
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Bundle
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.wireguard.android.turn.CaptchaCoordinator

class CaptchaActivity : AppCompatActivity() {
    private var previousNetwork: Network? = null
    private var didBindNetwork = false
    private var cacheId: Int = -1
    private var redirectUri: String = ""
    private var webView: WebView? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        bindToPhysicalNetwork()
        CaptchaCoordinator.registerActivity(this)
        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.userAgentString = USER_AGENT
            if (WebViewFeature.isFeatureSupported(WebViewFeature.ALGORITHMIC_DARKENING)) {
                WebSettingsCompat.setAlgorithmicDarkeningAllowed(settings, true)
            }
            addJavascriptInterface(CaptchaBridge(), "AndroidCaptcha")
            webChromeClient = WebChromeClient()
            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    view?.evaluateJavascript(INTERCEPT_SCRIPT, null)
                }

                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    return false
                }
            }
        }
        setContentView(webView)
        applyIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (CaptchaCoordinator.isTerminalFailureActive()) {
            finish()
            return
        }
        if (cacheId >= 0 && !CaptchaCoordinator.isPending(cacheId)) {
            finish()
        }
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onBackPressed() {
        val view = webView
        if (view != null && view.canGoBack()) {
            view.goBack()
            return
        }
        if (cacheId >= 0) {
            CaptchaCoordinator.dismiss(cacheId)
        }
        finish()
    }

    private inner class CaptchaBridge {
        @JavascriptInterface
        fun onResult(successToken: String) {
            runOnUiThread {
                CaptchaCoordinator.complete(cacheId, successToken)
                finish()
            }
        }
    }

    private fun bindToPhysicalNetwork() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            previousNetwork = cm.boundNetworkForProcess
            val network = selectBestPhysicalNetwork(cm)
            if (network == null) {
                Log.w(TAG, "No non-VPN physical network available for captcha WebView")
                return
            }
            cm.bindProcessToNetwork(network)
            didBindNetwork = true
            Log.d(TAG, "Captcha WebView bound to ${describeNetwork(cm, network)}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to bind process to physical network", e)
        }
    }

    private fun restoreNetworkBinding() {
        if (!didBindNetwork) return
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.bindProcessToNetwork(previousNetwork)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restore previous network binding", e)
        }
    }

    override fun onDestroy() {
        if (cacheId >= 0) {
            CaptchaCoordinator.markHidden(cacheId)
        }
        CaptchaCoordinator.unregisterActivity(this)
        restoreNetworkBinding()
        webView?.destroy()
        webView = null
        super.onDestroy()
    }

    private fun applyIntent(intent: Intent) {
        val nextCacheId = intent.getIntExtra(EXTRA_CACHE_ID, -1)
        val nextRedirectUri = intent.getStringExtra(EXTRA_REDIRECT_URI).orEmpty()
        if (nextCacheId < 0 || nextRedirectUri.isBlank()) {
            if (cacheId >= 0) {
                CaptchaCoordinator.cancel(cacheId)
            }
            finish()
            return
        }

        // Repeated tap on notification must not create a stack of stale captcha pages.
        if (cacheId == nextCacheId && redirectUri == nextRedirectUri) {
            CaptchaCoordinator.markVisible(cacheId)
            return
        }

        if (cacheId >= 0 && cacheId != nextCacheId) {
            CaptchaCoordinator.cancel(cacheId)
        }

        cacheId = nextCacheId
        redirectUri = nextRedirectUri

        if (CaptchaCoordinator.isTerminalFailureActive()) {
            finish()
            return
        }
        if (!CaptchaCoordinator.isPending(cacheId)) {
            finish()
            return
        }

        CaptchaCoordinator.markVisible(cacheId)
        webView?.loadUrl(redirectUri)
    }

    @Suppress("DEPRECATION")
    private fun selectBestPhysicalNetwork(cm: ConnectivityManager): Network? {
        val candidates = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
            network to caps
        }
        if (candidates.isEmpty()) return null
        val activeNetwork = cm.activeNetwork
        return candidates.maxByOrNull { (network, caps) ->
            var score = 0
            if (network == activeNetwork) score += 100
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 50
            when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> score += 30
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> score += 20
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> score += 10
            }
            score
        }?.first
    }

    private fun describeNetwork(cm: ConnectivityManager, network: Network): String {
        val caps = cm.getNetworkCapabilities(network)
        val props = cm.getLinkProperties(network)
        val transports = buildList {
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) add("wifi")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) add("cellular")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) add("ethernet")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) add("vpn")
        }.joinToString(",").ifBlank { "unknown" }
        val dns = props?.dnsServers?.joinToString(",") { it.hostAddress.orEmpty() }.orEmpty()
        return "handle=${network.networkHandle} transports=$transports validated=${caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true} dns=[$dns]"
    }

    companion object {
        private const val TAG = "WireGuard/CaptchaActivity"
        const val EXTRA_CACHE_ID = "cache_id"
        const val EXTRA_REDIRECT_URI = "redirect_uri"
        private const val CAPTCHA_TIMEOUT_SECONDS = 180L
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"

        private val INTERCEPT_SCRIPT = """
            (function() {
                var origOpen = XMLHttpRequest.prototype.open;
                var origSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.open = function() {
                    this._captchaUrl = arguments[1];
                    return origOpen.apply(this, arguments);
                };
                XMLHttpRequest.prototype.send = function() {
                    var xhr = this;
                    if (xhr._captchaUrl && xhr._captchaUrl.indexOf('captchaNotRobot.check') !== -1) {
                        xhr.addEventListener('load', function() {
                            try {
                                var data = JSON.parse(xhr.responseText);
                                if (data.response && data.response.success_token) {
                                    AndroidCaptcha.onResult(data.response.success_token);
                                }
                            } catch (e) {}
                        });
                    }
                    return origSend.apply(this, arguments);
                };

                var origFetch = window.fetch;
                if (origFetch) {
                    window.fetch = function() {
                        var url = arguments[0];
                        if (typeof url === 'object' && url.url) url = url.url;
                        var p = origFetch.apply(this, arguments);
                        if (typeof url === 'string' && url.indexOf('captchaNotRobot.check') !== -1) {
                            p.then(function(response) { return response.clone().json(); })
                             .then(function(data) {
                                 if (data.response && data.response.success_token) {
                                     AndroidCaptcha.onResult(data.response.success_token);
                                 }
                             })
                             .catch(function() {});
                        }
                        return p;
                    };
                }
            })();
        """.trimIndent()

        fun solveCaptcha(context: Context, cacheId: Int, redirectUri: String): String {
            return CaptchaCoordinator.request(context, cacheId, redirectUri)
        }
    }
}
