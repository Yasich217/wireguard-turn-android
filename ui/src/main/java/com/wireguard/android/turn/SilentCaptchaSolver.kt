/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.display.DisplayManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.ContextThemeWrapper
import android.view.Display
import android.view.WindowManager
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import com.wireguard.android.BuildConfig
import com.wireguard.android.R
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

object SilentCaptchaSolver {
    data class Result(
        val token: String = "",
        val terminal: Boolean = false,
        val reason: String = "",
    )

    private val serialLock = Any()
    private val mainHandler = Handler(Looper.getMainLooper())

    fun solve(context: Context, cacheId: Int, redirectUri: String, timeoutMs: Long = CAPTCHA_TIMEOUT_MS): Result {
        if (redirectUri.isBlank()) return Result(reason = "empty_redirect_uri")
        if (Looper.myLooper() == Looper.getMainLooper()) {
            Log.w(TAG, "Refusing to block main thread for cacheId=$cacheId")
            return Result(reason = "main_thread")
        }
        synchronized(serialLock) {
            return solveLocked(context.applicationContext, cacheId, redirectUri, timeoutMs)
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun solveLocked(context: Context, cacheId: Int, redirectUri: String, timeoutMs: Long): Result {
        val latch = CountDownLatch(1)
        val completed = AtomicBoolean(false)
        val result = AtomicReference(Result(reason = "timeout"))
        val webViewRef = AtomicReference<WebView?>()
        val previousNetwork = AtomicReference<Network?>()
        val didBindNetwork = AtomicBoolean(false)

        fun cleanup() {
            val view = webViewRef.getAndSet(null)
            if (view != null) {
                try {
                    view.stopLoading()
                    view.destroy()
                } catch (e: Throwable) {
                    Log.w(TAG, "cleanup WebView failed: ${e.message}")
                }
            }
            if (didBindNetwork.get()) {
                try {
                    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                    cm.bindProcessToNetwork(previousNetwork.get())
                    Log.d(TAG, "Restored previous process network after cacheId=$cacheId")
                } catch (e: Throwable) {
                    Log.w(TAG, "Failed to restore previous process network: ${e.message}")
                }
            }
        }

        fun finish(next: Result) {
            if (!completed.compareAndSet(false, true)) return
            result.set(next)
            mainHandler.post { cleanup() }
            latch.countDown()
        }

        mainHandler.post {
            try {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                previousNetwork.set(cm.boundNetworkForProcess)
                val network = selectBestPhysicalNetwork(cm)
                if (network != null) {
                    cm.bindProcessToNetwork(network)
                    didBindNetwork.set(true)
                    Log.d(TAG, "Bound silent captcha to ${describeNetwork(cm, network)} cacheId=$cacheId")
                } else {
                    Log.w(TAG, "No non-VPN physical network for silent captcha cacheId=$cacheId")
                }

                if (BuildConfig.DEBUG) {
                    WebView.setWebContentsDebuggingEnabled(true)
                }
                val webView = WebView(createWebViewContext(context))
                webViewRef.set(webView)
                webView.settings.javaScriptEnabled = true
                webView.settings.domStorageEnabled = true
                webView.settings.userAgentString = USER_AGENT
                webView.addJavascriptInterface(Bridge(context, cacheId, ::finish), "AndroidCaptcha")
                webView.webChromeClient = object : WebChromeClient() {
                    override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                        if (consoleMessage != null) {
                            Log.d(
                                TAG,
                                "[console:${consoleMessage.messageLevel()}] ${consoleMessage.message()} @${consoleMessage.sourceId()}:${consoleMessage.lineNumber()}",
                            )
                        }
                        return super.onConsoleMessage(consoleMessage)
                    }
                }
                webView.webViewClient = object : WebViewClient() {
                    override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                        super.onPageStarted(view, url, favicon)
                        Log.d(TAG, "[pageStarted] cacheId=$cacheId url=${url.orEmpty().take(240)}")
                    }

                    override fun onPageFinished(view: WebView?, url: String?) {
                        super.onPageFinished(view, url)
                        Log.d(TAG, "[pageFinished] cacheId=$cacheId url=${url.orEmpty().take(240)} title=${view?.title}")
                        installScripts(view, cacheId, "finished")
                    }

                    override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: WebResourceError?) {
                        super.onReceivedError(view, request, error)
                        if (request?.isForMainFrame == true) {
                            Log.w(TAG, "[receivedError] cacheId=$cacheId code=${error?.errorCode} desc=${error?.description} url=${request.url}")
                        }
                    }

                    override fun onReceivedHttpError(view: WebView?, request: WebResourceRequest?, errorResponse: WebResourceResponse?) {
                        super.onReceivedHttpError(view, request, errorResponse)
                        if (request?.isForMainFrame == true) {
                            Log.w(TAG, "[httpError] cacheId=$cacheId status=${errorResponse?.statusCode} reason=${errorResponse?.reasonPhrase} url=${request.url}")
                        }
                    }

                    override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
                        val url = request?.url?.toString().orEmpty()
                        if (request?.isForMainFrame == true || url.contains("captchaNotRobot")) {
                            Log.d(TAG, "[request] cacheId=$cacheId method=${request?.method} main=${request?.isForMainFrame} url=${url.take(240)}")
                        }
                        return super.shouldInterceptRequest(view, request)
                    }
                }
                Log.d(TAG, "Loading silent captcha cacheId=$cacheId redirectUri=${redirectUri.take(240)}")
                webView.loadUrl(redirectUri)
                listOf(350L, 900L, 1700L, 2800L, 4200L, 6500L).forEach { delay ->
                    mainHandler.postDelayed({
                        if (!completed.get()) installScripts(webViewRef.get(), cacheId, "timer-$delay")
                    }, delay)
                }
            } catch (e: Throwable) {
                Log.w(TAG, "Silent captcha setup failed cacheId=$cacheId: ${e.javaClass.simpleName}: ${e.message}")
                finish(Result(reason = "setup_failed:${e.javaClass.simpleName}"))
            }
        }

        if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            if (completed.compareAndSet(false, true)) {
                Log.w(TAG, "Silent captcha timed out cacheId=$cacheId timeoutMs=$timeoutMs")
                result.set(Result(reason = "timeout"))
                mainHandler.post { cleanup() }
            }
        }
        val final = result.get()
        Log.d(TAG, "Silent captcha result cacheId=$cacheId tokenLength=${final.token.length} terminal=${final.terminal} reason=${final.reason}")
        return final
    }

    private fun installScripts(view: WebView?, cacheId: Int, reason: String) {
        view ?: return
        view.evaluateJavascript(INTERCEPT_AND_CLICK_SCRIPT) { result ->
            Log.d(TAG, "[script:$reason] cacheId=$cacheId result=${result?.take(300)}")
        }
    }

    private class Bridge(
        private val context: Context,
        private val cacheId: Int,
        private val finish: (Result) -> Unit,
    ) {
        @JavascriptInterface
        fun onResult(successToken: String?) {
            val token = successToken.orEmpty()
            Log.d(TAG, "[bridge:result] cacheId=$cacheId tokenLength=${token.length}")
            finish(Result(token = token, reason = "success"))
        }

        @JavascriptInterface
        fun onLimitExceeded(detail: String?) {
            Log.w(TAG, "[bridge:limit] cacheId=$cacheId detail=${detail.orEmpty().take(500)}")
            finish(Result(terminal = true, reason = "limit:${detail.orEmpty()}"))
        }

        @JavascriptInterface
        fun log(message: String?) {
            if (message.isNullOrBlank()) return
            Log.d(TAG, "[js] cacheId=$cacheId ${message.replace("\n", "\\n").take(3000)}")
        }

        @JavascriptInterface
        fun onCaptchaTelemetry(requestBody: String?, userAgent: String?) {
            VkCaptchaProfileStore.saveFromRequestBody(context, requestBody, userAgent)
        }
    }

    private fun createWebViewContext(context: Context): Context {
        val display = (context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager)
            .getDisplay(Display.DEFAULT_DISPLAY)
        val displayContext = context.createDisplayContext(display)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            displayContext.createWindowContext(WindowManager.LayoutParams.TYPE_APPLICATION, null)
        } else {
            ContextThemeWrapper(displayContext, R.style.AppTheme)
        }
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

    private val INTERCEPT_AND_CLICK_SCRIPT = """
        (function() {
            if (window.__androidSilentCaptchaInstalled) {
                if (window.__androidSilentCaptchaScheduleClick) {
                    window.__androidSilentCaptchaScheduleClick('reinstall', 250);
                }
                return 'already-installed';
            }
            window.__androidSilentCaptchaInstalled = true;
            window.__androidSilentCaptchaClickAttempts = 0;
            window.__androidSilentCaptchaComponentDoneOk = false;
            window.__androidSilentCaptchaTerminal = false;
            function sendLog(message) {
                try { AndroidCaptcha.log(String(message)); } catch (e) {}
            }
            function truncate(text, limit) {
                if (!text) return '';
                text = String(text);
                return text.length > limit ? text.slice(0, limit) + '...(truncated)' : text;
            }
            function bodyText() {
                try { return ((document.body && document.body.innerText) || '').trim(); } catch (e) { return ''; }
            }
            function inspect(reason) {
                var text = truncate(bodyText().replace(/\s+/g, ' '), 1200);
                sendLog('[inspect:' + reason + '] title=' + truncate(document.title || '', 200) +
                    ' url=' + truncate(location.href || '', 400) +
                    ' checkboxes=' + document.querySelectorAll('input[type="checkbox"], [role="checkbox"]').length +
                    ' text=' + text);
                if (text.indexOf('Лимит попыток исчерпан') !== -1) {
                    try { AndroidCaptcha.onLimitExceeded('dom_text_limit'); } catch (e) {}
                }
            }
            function scheduleClick(reason, delay) {
                setTimeout(function() {
                    if (window.__androidSilentCaptchaTerminal) return;
                    if (!window.__androidSilentCaptchaComponentDoneOk) {
                        sendLog('[auto-click-wait] reason=' + reason + ' componentDone=false');
                        scheduleClick(reason + '-component-wait', 350);
                        return;
                    }
                    clickCheckboxOnce(reason);
                }, delay || 0);
            }
            function clickCheckboxOnce(reason) {
                if (window.__androidSilentCaptchaTerminal) return false;
                if (window.__androidSilentCaptchaClicked) return false;
                var node = document.querySelector('input[type="checkbox"], [role="checkbox"]');
                if (!node) return false;
                window.__androidSilentCaptchaClicked = true;
                window.__androidSilentCaptchaClickAttempts = (window.__androidSilentCaptchaClickAttempts || 0) + 1;
                try {
                    var rect = node.getBoundingClientRect ? node.getBoundingClientRect() : { left: 10, top: 10, width: 20, height: 20 };
                    var x = Math.max(1, Math.floor((rect.left || 10) + Math.max(10, rect.width || 20) / 2));
                    var y = Math.max(1, Math.floor((rect.top || 10) + Math.max(10, rect.height || 20) / 2));
                    sendLog('[auto-click] reason=' + reason + ' tag=' + node.tagName + ' role=' + (node.getAttribute('role') || '') + ' x=' + x + ' y=' + y);
                    ['pointerdown', 'mousedown', 'mouseup', 'click'].forEach(function(type) {
                        node.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window, clientX: x, clientY: y }));
                    });
                    if (typeof node.click === 'function') node.click();
                    setTimeout(function() { inspect('after-click'); }, 600);
                    return true;
                } catch (e) {
                    sendLog('[auto-click-error] ' + e);
                    window.__androidSilentCaptchaClicked = false;
                    return false;
                }
            }
            window.__androidSilentCaptchaClick = clickCheckboxOnce;
            window.__androidSilentCaptchaScheduleClick = scheduleClick;

            function processCaptchaResponse(url, body) {
                if (!url || String(url).indexOf('captchaNotRobot.') === -1) return;
                var data = null;
                try { data = JSON.parse(body || '{}'); } catch (e) { sendLog('[response-parse-error] ' + e); return; }
                var response = data && data.response;
                if (!response) return;
                if (String(url).indexOf('captchaNotRobot.componentDone') !== -1 && response.status === 'OK') {
                    window.__androidSilentCaptchaComponentDoneOk = true;
                    scheduleClick('component-done', 150);
                    return;
                }
                if (String(url).indexOf('captchaNotRobot.check') === -1) return;
                if (response.success_token) {
                    AndroidCaptcha.onResult(response.success_token);
                    return;
                }
                if (response.status === 'ERROR_LIMIT') {
                    window.__androidSilentCaptchaTerminal = true;
                    AndroidCaptcha.onLimitExceeded('status_ERROR_LIMIT');
                    return;
                }
                if (response.status === 'ERROR') {
                    window.__androidSilentCaptchaTerminal = true;
                    sendLog('[check-error-terminal] attempts=' + (window.__androidSilentCaptchaClickAttempts || 0));
                    AndroidCaptcha.onLimitExceeded('status_ERROR_checkbox_rejected');
                    return;
                }
            }

            var origOpen = XMLHttpRequest.prototype.open;
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function() {
                this._captchaUrl = arguments[1];
                return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                var xhr = this;
                var requestBody = arguments.length ? arguments[0] : null;
                try {
                if (xhr._captchaUrl && String(xhr._captchaUrl).indexOf('captchaNotRobot.') !== -1) {
                    sendLog('[xhr-send] url=' + truncate(xhr._captchaUrl || '', 500) + ' body=' + truncate(requestBody || '', 2000));
                    if (String(xhr._captchaUrl).indexOf('captchaNotRobot.componentDone') !== -1 ||
                        String(xhr._captchaUrl).indexOf('captchaNotRobot.check') !== -1) {
                        try { AndroidCaptcha.onCaptchaTelemetry(String(requestBody || ''), String(navigator.userAgent || '')); } catch (e) {}
                    }
                }
                } catch (e) {}
                xhr.addEventListener('load', function() {
                    try {
                        var body = '';
                        try {
                            body = xhr.responseText || '';
                        } catch (responseTextError) {
                            body = xhr.response ? JSON.stringify(xhr.response) : '';
                        }
                        sendLog('[xhr] url=' + truncate(xhr._captchaUrl || '', 500) + ' status=' + xhr.status + ' body=' + truncate(body, 2000));
                        processCaptchaResponse(xhr._captchaUrl, body);
                    } catch (e) {
                        sendLog('[xhr-parse-error] ' + e);
                    }
                });
                return origSend.apply(this, arguments);
            };

            var origFetch = window.fetch;
            if (origFetch) {
                window.fetch = function() {
                    var url = arguments[0];
                    if (typeof url === 'object' && url.url) url = url.url;
                    var options = arguments.length > 1 ? arguments[1] : null;
                    try {
                        if (typeof url === 'string' && url.indexOf('captchaNotRobot.') !== -1) {
                            sendLog('[fetch-send] url=' + truncate(url || '', 500) + ' body=' + truncate(options && options.body || '', 2000));
                            if (url.indexOf('captchaNotRobot.componentDone') !== -1 ||
                                url.indexOf('captchaNotRobot.check') !== -1) {
                                try { AndroidCaptcha.onCaptchaTelemetry(String(options && options.body || ''), String(navigator.userAgent || '')); } catch (e) {}
                            }
                        }
                    } catch (e) {}
                    var p = origFetch.apply(this, arguments);
                    p.then(function(response) {
                        return response.clone().text().then(function(text) {
                            sendLog('[fetch] url=' + truncate(url || '', 500) + ' status=' + response.status + ' body=' + truncate(text, 2000));
                            processCaptchaResponse(url, text);
                        });
                    }).catch(function(error) {
                        sendLog('[fetch-error] url=' + truncate(url || '', 500) + ' error=' + error);
                    });
                    return p;
                };
            }

            if (window.MutationObserver && document.documentElement) {
                var snapshotTimer = null;
                new MutationObserver(function() {
                    if (snapshotTimer) clearTimeout(snapshotTimer);
                    snapshotTimer = setTimeout(function() {
                        if (window.__androidSilentCaptchaTerminal) return;
                        inspect('mutation');
                        scheduleClick('mutation', 0);
                    }, 250);
                }).observe(document.documentElement, { subtree: true, childList: true, characterData: true });
            }

            inspect('install');
            scheduleClick('install-500', 500);
            scheduleClick('install-1200', 1200);
            setTimeout(function() { inspect('delayed-2500'); scheduleClick('delayed-2500', 0); }, 2500);
            return 'installed';
        })();
    """.trimIndent()

    private const val CAPTCHA_TIMEOUT_MS = 45_000L
    private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"
    private const val TAG = "WireGuard/SilentCaptcha"
}
