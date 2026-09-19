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
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.webkit.JavascriptInterface
import android.webkit.ConsoleMessage
import android.webkit.WebResourceError
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.addCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.wireguard.android.BuildConfig
import com.wireguard.android.turn.CaptchaCoordinator
import com.wireguard.android.turn.CaptchaDebugTrace
import com.wireguard.android.turn.SilentCaptchaSolver
import com.wireguard.android.turn.VkCaptchaProfileStore
import java.io.File
import java.io.FileOutputStream

class CaptchaActivity : AppCompatActivity() {
    private var previousNetwork: Network? = null
    private var didBindNetwork = false
    private var cacheId: Int = -1
    private var redirectUri: String = ""
    private var webView: WebView? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var inspectionGeneration = 0
    private var requestLogCount = 0
    private var limitHandled = false
    private var lastFinishedUrl = ""
    private var lastFinishedElapsedMs = 0L

    private fun logWebView(message: String?) {
        if (!BuildConfig.DEBUG || message.isNullOrBlank()) return
        val normalized = message
            .replace("\u0000", "")
            .replace("\r", "")
            .replace("\n", "\\n")
            .trim()
        if (normalized.isBlank()) return
        val maxLen = 3000
        val safeMessage = if (normalized.length > maxLen) {
            normalized.take(maxLen) + "...(truncated)"
        } else {
            normalized
        }
        CaptchaDebugTrace.append(this, "visible", safeMessage)
        Log.d(TAG, "WebView: $safeMessage")
    }

    private fun logWebViewLong(prefix: String, value: String?, chunkSize: Int = 900) {
        if (value.isNullOrBlank()) return
        val normalized = value
            .replace("\u0000", "")
            .replace("\r", "")
            .trim()
        val total = (normalized.length + chunkSize - 1) / chunkSize
        for (i in 0 until total) {
            val part = normalized.substring(i * chunkSize, minOf((i + 1) * chunkSize, normalized.length))
                .replace("\n", "\\n")
            logWebView("$prefix[${i + 1}/$total]=$part")
        }
    }

    private fun captureWebView(view: WebView?, reason: String) {
        if (!BuildConfig.DEBUG) return
        if (view == null) return
        val width = view.width
        val height = view.height
        if (width <= 0 || height <= 0) {
            logWebView("[screenshot:$reason] skipped: size=${width}x${height} url=${view.url}")
            return
        }
        try {
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            view.draw(canvas)
            val file = File(cacheDir, "captcha-${System.currentTimeMillis()}-$reason.png")
            FileOutputStream(file).use { out ->
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            }
            cacheDir.listFiles { candidate ->
                candidate.name.startsWith("captcha-") && candidate.extension == "png"
            }?.sortedByDescending(File::lastModified)?.drop(MAX_DEBUG_SCREENSHOTS)?.forEach(File::delete)
            logWebView("[screenshot:$reason] saved=${file.absolutePath} size=${width}x${height} url=${view.url}")
        } catch (e: Throwable) {
            logWebView("[screenshot:$reason:error] ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun handleCaptchaLimit(source: String, detail: String?) {
        if (limitHandled) return
        limitHandled = true
        logWebView("[limit:$source] ${detail.orEmpty()}")
        if (cacheId >= 0) {
            CaptchaCoordinator.cancel(cacheId)
        }
        finish()
    }

    private fun inspectPage(view: WebView?, reason: String) {
        if (!BuildConfig.DEBUG || view == null) return
        logWebView("[inspect:$reason] url=${view.url} title=${view.title}")
        view.evaluateJavascript(
            """
                (function() {
                    try {
                        var bodyText = document.body ? document.body.innerText : '';
                        var checkboxCount = document.querySelectorAll('input[type="checkbox"], [role="checkbox"]').length;
                        var iframeSrcs = Array.from(document.querySelectorAll('iframe')).map(function(frame) { return frame.src || frame.getAttribute('src') || ''; }).filter(Boolean);
                        var buttons = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"]')).map(function(node) {
                            return (node.tagName + ':' + (node.id || '') + ':' + (node.name || '') + ':' + (node.value || node.textContent || '')).trim();
                        }).filter(Boolean);
                        var hints = [
                            'checkboxes=' + checkboxCount,
                            'iframes=' + iframeSrcs.length,
                            'buttons=' + buttons.length,
                            'body=' + bodyText.slice(0, 1000).replace(/\\s+/g, ' ').trim(),
                        ];
                        if (iframeSrcs.length) {
                            hints.push('iframeSrcs=' + iframeSrcs.slice(0, 5).join(' | '));
                        }
                        if (buttons.length) {
                            hints.push('buttonsSample=' + buttons.slice(0, 10).join(' | '));
                        }
                        return hints.join('\\n');
                    } catch (e) {
                        return '[inspect-error] ' + e;
                    }
                })();
            """.trimIndent(),
        ) { result ->
            logWebView("[inspect:$reason:result] $result")
        }
        mainHandler.postDelayed({
            view.evaluateJavascript(
                """
                    (function() {
                        try {
                            return [
                                'title=' + document.title,
                                'url=' + location.href,
                                'readyState=' + document.readyState,
                                'text=' + (document.body ? document.body.innerText : '').slice(0, 1200).replace(/\\s+/g, ' ').trim(),
                            ].join('\\n');
                        } catch (e) {
                            return '[delayed-inspect-error] ' + e;
                        }
                    })();
                """.trimIndent(),
            ) { result ->
                logWebView("[inspect:$reason:delayed] $result")
            }
        }, 1500L)
    }

    private fun startInspectionLoop(view: WebView?, reason: String) {
        if (!BuildConfig.DEBUG || view == null) return
        val generation = ++inspectionGeneration
        fun tick(step: Int) {
            if (generation != inspectionGeneration) return
            if (step > 8) return
            view.evaluateJavascript(
                """
                    (function() {
                        try {
                            var bodyText = document.body ? document.body.innerText : '';
                            var checkboxCount = document.querySelectorAll('input[type="checkbox"], [role="checkbox"]').length;
                            var iframeCount = document.querySelectorAll('iframe').length;
                            return [
                                'step=$step',
                                'title=' + document.title,
                                'url=' + location.href,
                                'readyState=' + document.readyState,
                                'checkboxes=' + checkboxCount,
                                'iframes=' + iframeCount,
                                'body=' + bodyText.slice(0, 1500).replace(/\\s+/g, ' ').trim(),
                            ].join('\\n');
                        } catch (e) {
                            return '[loop-error] ' + e;
                        }
                    })();
                """.trimIndent(),
            ) { result ->
                logWebView("[loop:$reason:$step] $result")
            }
            if (step == 1 || step == 4 || step == 8) {
                view.post { captureWebView(view, "loop-$reason-$step") }
            }
            mainHandler.postDelayed({
                tick(step + 1)
            }, 1000L)
        }
        tick(1)
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        onBackPressedDispatcher.addCallback(this) { handleBack() }
        val createMessage = "onCreate intent=${intent?.action} cacheId=${intent.getIntExtra(EXTRA_CACHE_ID, -1)} redirectUri=${intent.getStringExtra(EXTRA_REDIRECT_URI).orEmpty()}"
        Log.d(TAG, createMessage)
        logWebView(createMessage)
        bindToPhysicalNetwork()
        CaptchaCoordinator.registerActivity(this)
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true)
            logWebView("WebView debugging enabled")
        }
        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            // Keep UA realistic and device-matching; also align Go-side captcha fingerprint with it.
            val defaultUa = settings.userAgentString
            logWebViewLong("[ua:default]", defaultUa)
            settings.userAgentString = USER_AGENT
            logWebViewLong("[ua:forced]", settings.userAgentString)
            if (WebViewFeature.isFeatureSupported(WebViewFeature.ALGORITHMIC_DARKENING)) {
                // VK supplies its own CAPTCHA palette. Algorithmic darkening turns parts of
                // the slider/checkbox text dark-on-dark and also causes a black startup flash.
                WebSettingsCompat.setAlgorithmicDarkeningAllowed(settings, false)
            }
            setBackgroundColor(Color.WHITE)
            addJavascriptInterface(CaptchaBridge(), "AndroidCaptcha")
            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                    if (consoleMessage != null) {
                        logWebView(
                            "[console:${consoleMessage.messageLevel()}] " +
                                "${consoleMessage.message()} @" +
                                "${consoleMessage.sourceId()}:${consoleMessage.lineNumber()}",
                        )
                    }
                    return super.onConsoleMessage(consoleMessage)
                }
            }
            webViewClient = object : WebViewClient() {
                override fun onPageCommitVisible(view: WebView?, url: String?) {
                    super.onPageCommitVisible(view, url)
                    Log.d(TAG, "[pageCommitVisible] url=$url")
                    logWebView("[pageCommitVisible] url=${url.orEmpty().take(200)}")
                    inspectPage(view, "commitVisible")
                    startInspectionLoop(view, "commitVisible")
                    view?.post { captureWebView(view, "commitVisible") }
                }

                override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                    super.onPageStarted(view, url, favicon)
                    Log.d(TAG, "[pageStarted] url=$url")
                    logWebView("[pageStarted] url=${url.orEmpty().take(200)}")
                    inspectPage(view, "started")
                    startInspectionLoop(view, "started")
                    view?.post { captureWebView(view, "started") }
                }

                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    val now = SystemClock.elapsedRealtime()
                    if (url == lastFinishedUrl && now - lastFinishedElapsedMs < PAGE_FINISHED_DEBOUNCE_MS) {
                        return
                    }
                    lastFinishedUrl = url.orEmpty()
                    lastFinishedElapsedMs = now
                    Log.d(TAG, "[pageFinished] url=$url title=${view?.title}")
                    logWebView("[pageFinished] url=${url.orEmpty().take(200)} title=${view?.title}")
                    view?.evaluateJavascript(INTERCEPT_SCRIPT) { result ->
                        logWebView("[interceptScript] $result")
                    }
                    view?.evaluateJavascript(SNAPSHOT_SCRIPT) { result ->
                        logWebView("[snapshotScript] $result")
                    }
                    inspectPage(view, "finished")
                    startInspectionLoop(view, "finished")
                    view?.post { captureWebView(view, "finished") }
                }

                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    return false
                }

                override fun onReceivedError(
                    view: WebView?,
                    request: WebResourceRequest?,
                    error: WebResourceError?,
                ) {
                    super.onReceivedError(view, request, error)
                    logWebView(
                        "[receivedError] url=${request?.url} isMainFrame=${request?.isForMainFrame} " +
                            "code=${error?.errorCode} desc=${error?.description}",
                    )
                }

                override fun onReceivedHttpError(
                    view: WebView?,
                    request: WebResourceRequest?,
                    errorResponse: WebResourceResponse?,
                ) {
                    super.onReceivedHttpError(view, request, errorResponse)
                    logWebView(
                        "[httpError] url=${request?.url} isMainFrame=${request?.isForMainFrame} " +
                            "status=${errorResponse?.statusCode} reason=${errorResponse?.reasonPhrase}",
                    )
                }

                override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
                    val url = request?.url?.toString().orEmpty()
                    val isMainFrame = request?.isForMainFrame == true
                    if (isMainFrame || requestLogCount < 200) {
                        if (!isMainFrame) requestLogCount += 1
                        logWebView(
                            "[request${if (isMainFrame) ":main" else "#$requestLogCount"}] " +
                                "method=${request?.method} mainFrame=$isMainFrame url=${url.take(200)}",
                        )
                    }
                    return super.shouldInterceptRequest(view, request)
                }

                override fun onLoadResource(view: WebView?, url: String?) {
                    super.onLoadResource(view, url)
                    if (requestLogCount < 200) {
                        requestLogCount += 1
                        logWebView("[loadResource#$requestLogCount] url=$url")
                    }
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
        val resumeMessage = "onResume cacheId=$cacheId pending=${if (cacheId >= 0) CaptchaCoordinator.isPending(cacheId) else false} terminal=${CaptchaCoordinator.isTerminalFailureActive()}"
        Log.d(TAG, resumeMessage)
        logWebView(resumeMessage)
        if (CaptchaCoordinator.isTerminalFailureActive()) {
            Log.d(TAG, "Finishing because terminal captcha failure is active")
            finish()
            return
        }
        if (cacheId >= 0 && !CaptchaCoordinator.isPending(cacheId)) {
            Log.d(TAG, "Finishing because cacheId=$cacheId is no longer pending")
            finish()
        }
    }

    private fun handleBack() {
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

        @JavascriptInterface
        fun log(message: String?) {
            runOnUiThread {
                logWebView(message)
            }
        }

        @JavascriptInterface
        fun onLimitExceeded(detail: String?) {
            runOnUiThread {
                handleCaptchaLimit("js", detail)
            }
        }

        @JavascriptInterface
        fun onCaptchaTelemetry(requestBody: String?, userAgent: String?) {
            runOnUiThread {
                if (VkCaptchaProfileStore.saveFromRequestBody(this@CaptchaActivity, requestBody, userAgent)) {
                    logWebView("[profile] saved browser telemetry")
                }
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
        val destroyMessage = "onDestroy cacheId=$cacheId redirectUri=$redirectUri"
        Log.d(TAG, destroyMessage)
        logWebView(destroyMessage)
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
        val applyMessage = "applyIntent cacheId=$nextCacheId redirectUri=${nextRedirectUri.take(200)}"
        Log.d(TAG, applyMessage)
        logWebView(applyMessage)
        if (nextCacheId < 0 || nextRedirectUri.isBlank()) {
            Log.d(TAG, "Missing cacheId or redirectUri, closing captcha activity")
            if (cacheId >= 0) {
                CaptchaCoordinator.cancel(cacheId)
            }
            finish()
            return
        }

        // Repeated tap on notification must not create a stack of stale captcha pages.
        if (cacheId == nextCacheId && redirectUri == nextRedirectUri) {
            Log.d(TAG, "Ignoring repeated intent for cacheId=$cacheId")
            CaptchaCoordinator.markVisible(cacheId)
            return
        }

        if (cacheId >= 0 && cacheId != nextCacheId) {
            Log.d(TAG, "Replacing previous captcha cacheId=$cacheId with cacheId=$nextCacheId")
            CaptchaCoordinator.cancel(cacheId)
        }

        cacheId = nextCacheId
        redirectUri = nextRedirectUri

        if (CaptchaCoordinator.isTerminalFailureActive()) {
            Log.d(TAG, "Terminal failure became active before loadUrl")
            finish()
            return
        }
        if (!CaptchaCoordinator.isPending(cacheId)) {
            Log.d(TAG, "cacheId=$cacheId is not pending before loadUrl")
            finish()
            return
        }

        CaptchaCoordinator.markVisible(cacheId)
        logWebView("[loadUrl] cacheId=$cacheId redirectUri=${redirectUri.take(200)}")
        webView?.loadUrl(redirectUri)
        webView?.postDelayed({
            logWebView("[loadUrl-post] cacheId=$cacheId url=${webView?.url} title=${webView?.title}")
            startInspectionLoop(webView, "postLoad")
        }, 500L)
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
                if (window.__androidCaptchaLoggingInstalled) {
                    return;
                }
                window.__androidCaptchaLoggingInstalled = true;
                function sendLog(message) {
                    try {
                        AndroidCaptcha.log(String(message));
                    } catch (e) {}
                }
                function bodyText() {
                    try {
                        return ((document.body && document.body.innerText) || '').trim();
                    } catch (e) {
                        return '';
                    }
                }
                function truncate(text, limit) {
                    if (!text) return '';
                    text = String(text);
                    return text.length > limit ? text.slice(0, limit) + '...(truncated)' : text;
                }
                function emitSnapshot(reason) {
                    var text = truncate(bodyText(), 4000);
                    sendLog('[dom:' + reason + '] title=' + truncate(document.title || '', 300) +
                        ' url=' + truncate(location.href || '', 500) +
                        ' text=' + text);
                    if (text.indexOf('Лимит попыток исчерпан') !== -1) {
                        try { AndroidCaptcha.onLimitExceeded('dom_text_limit'); } catch (e) {}
                    }
                }
                function ensureReadableCaptchaText() {
                    try {
                        if (document.getElementById('wg-turn-captcha-readable-style')) return;
                        var style = document.createElement('style');
                        style.id = 'wg-turn-captcha-readable-style';
                        style.textContent = [
                            'body { -webkit-text-size-adjust: 100% !important; }',
                            'button, [role="button"], [class*="slider" i], [class*="slider" i] * {',
                            '  opacity: 1 !important;',
                            '}',
                            '[class*="slider" i] button, [class*="slider" i] [role="button"] {',
                            '  font-size: max(14px, 1rem) !important;',
                            '  line-height: 1.25 !important;',
                            '}'
                        ].join('\n');
                        (document.head || document.documentElement).appendChild(style);
                    } catch (e) {
                        sendLog('[readable-style-error] ' + e);
                    }
                }
                function clickCheckboxOnce(reason) {
                    if (window.__androidCaptchaClicked) return false;
                    var node = document.querySelector('input[type="checkbox"], [role="checkbox"]');
                    if (!node) return false;
                    window.__androidCaptchaClicked = true;
                    try {
                        sendLog('[auto-click] checkbox reason=' + reason +
                            ' tag=' + node.tagName +
                            ' role=' + (node.getAttribute('role') || '') +
                            ' text=' + truncate(node.innerText || node.textContent || '', 300));
                        ['pointerdown', 'mousedown', 'mouseup', 'click'].forEach(function(type) {
                            node.dispatchEvent(new MouseEvent(type, {
                                bubbles: true,
                                cancelable: true,
                                view: window,
                                clientX: Math.max(1, Math.floor(node.getBoundingClientRect().left + node.getBoundingClientRect().width / 2)),
                                clientY: Math.max(1, Math.floor(node.getBoundingClientRect().top + node.getBoundingClientRect().height / 2))
                            }));
                        });
                        if (typeof node.click === 'function') node.click();
                        return true;
                    } catch (e) {
                        sendLog('[auto-click-error] ' + e);
                        return false;
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
                            sendLog('[xhr-send] url=' + truncate(xhr._captchaUrl || '', 500) +
                                ' body=' + truncate(requestBody || '', 2000));
                            if (String(xhr._captchaUrl).indexOf('captchaNotRobot.componentDone') !== -1 ||
                                String(xhr._captchaUrl).indexOf('captchaNotRobot.check') !== -1) {
                                try { AndroidCaptcha.onCaptchaTelemetry(String(requestBody || ''), String(navigator.userAgent || '')); } catch (e) {}
                            }
                        }
                    } catch (e) {}
                    xhr.addEventListener('load', function() {
                        try {
                            var body = xhr.responseText || '';
                            sendLog('[xhr] url=' + truncate(xhr._captchaUrl || '', 500) +
                                ' status=' + xhr.status +
                                ' body=' + truncate(body, 2000));
                                if (xhr._captchaUrl && xhr._captchaUrl.indexOf('captchaNotRobot.check') !== -1) {
                                    var data = JSON.parse(body);
                                    if (data.response && data.response.success_token) {
                                        AndroidCaptcha.onResult(data.response.success_token);
                                    } else if (data.response && data.response.status === 'ERROR_LIMIT') {
                                        AndroidCaptcha.onLimitExceeded('xhr_status_ERROR_LIMIT');
                                    } else if (data.response && data.response.status === 'ERROR') {
                                        AndroidCaptcha.onLimitExceeded('xhr_status_ERROR_checkbox_rejected');
                                    }
                                }
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
                                sendLog('[fetch-send] url=' + truncate(url || '', 500) +
                                    ' body=' + truncate(options && options.body || '', 2000));
                                if (url.indexOf('captchaNotRobot.componentDone') !== -1 ||
                                    url.indexOf('captchaNotRobot.check') !== -1) {
                                    try { AndroidCaptcha.onCaptchaTelemetry(String(options && options.body || ''), String(navigator.userAgent || '')); } catch (e) {}
                                }
                            }
                        } catch (e) {}
                        var p = origFetch.apply(this, arguments);
                        p.then(function(response) {
                            return response.clone().text().then(function(text) {
                                sendLog('[fetch] url=' + truncate(url || '', 500) +
                                    ' status=' + response.status +
                                    ' body=' + truncate(text, 2000));
                                if (typeof url === 'string' && url.indexOf('captchaNotRobot.check') !== -1) {
                                    try {
                                        var data = JSON.parse(text);
                                        if (data.response && data.response.success_token) {
                                            AndroidCaptcha.onResult(data.response.success_token);
                                        } else if (data.response && data.response.status === 'ERROR_LIMIT') {
                                            AndroidCaptcha.onLimitExceeded('fetch_status_ERROR_LIMIT');
                                        } else if (data.response && data.response.status === 'ERROR') {
                                            AndroidCaptcha.onLimitExceeded('fetch_status_ERROR_checkbox_rejected');
                                        }
                                    } catch (e) {
                                        sendLog('[fetch-parse-error] ' + e);
                                    }
                                }
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
                            ensureReadableCaptchaText();
                            emitSnapshot('mutation');
                            clickCheckboxOnce('mutation');
                        }, 350);
                    }).observe(document.documentElement, {
                        subtree: true,
                        childList: true,
                        characterData: true
                    });
                }

                ensureReadableCaptchaText();
                emitSnapshot('install');
                setTimeout(function() { clickCheckboxOnce('install-250'); }, 250);
                setTimeout(function() { clickCheckboxOnce('install-900'); }, 900);
            })();
        """.trimIndent()

        private val SNAPSHOT_SCRIPT = """
            (function() {
                try {
                    AndroidCaptcha.log(
                        '[snapshot] title=' + (document.title || '') +
                        ' url=' + (location.href || '') +
                        ' text=' + (((document.body && document.body.innerText) || '').trim().slice(0, 4000))
                    );
                } catch (e) {
                    AndroidCaptcha.log('[snapshot-error] ' + e);
                }
            })();
        """.trimIndent()

        fun solveCaptcha(context: Context, cacheId: Int, redirectUri: String): String {
            var silentResult = SilentCaptchaSolver.solve(context, cacheId, redirectUri)
            if (silentResult.reason == "timeout") {
                // A fresh WebView regularly succeeds immediately after the first hidden page
                // got stuck. Retry it off-screen before waking the user with a notification.
                Log.d(TAG, "Retrying timed-out silent captcha cacheId=$cacheId before visible fallback")
                silentResult = SilentCaptchaSolver.solve(
                    context,
                    cacheId,
                    redirectUri,
                    SILENT_RETRY_TIMEOUT_MS,
                )
            }
            if (silentResult.token.isNotBlank()) {
                Log.d(TAG, "Silent captcha solved cacheId=$cacheId tokenLength=${silentResult.token.length}")
                return silentResult.token
            }
            if (silentResult.terminal) {
                Log.w(TAG, "Silent captcha reached terminal state cacheId=$cacheId reason=${silentResult.reason}")
                return if (silentResult.reason.contains("checkbox_rejected", ignoreCase = true)) {
                    CAPTCHA_WAIT_SENTINEL
                } else {
                    CAPTCHA_LIMIT_SENTINEL
                }
            }
            Log.d(TAG, "Silent captcha did not solve cacheId=$cacheId reason=${silentResult.reason}; falling back to visible WebView")
            return CaptchaCoordinator.request(context, cacheId, redirectUri)
        }

        private const val CAPTCHA_LIMIT_SENTINEL = "__CAPTCHA_LIMIT_REACHED__"
        private const val CAPTCHA_WAIT_SENTINEL = "__CAPTCHA_WAIT_REQUIRED__"
        private const val SILENT_RETRY_TIMEOUT_MS = 15_000L
        private const val MAX_DEBUG_SCREENSHOTS = 12
        private const val PAGE_FINISHED_DEBOUNCE_MS = 1500L
    }
}
