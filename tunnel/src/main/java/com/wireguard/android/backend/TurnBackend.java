/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.Keep;
import androidx.annotation.Nullable;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * Native interface for TURN proxy management.
 */
public final class TurnBackend {
    private static final String TAG = "WireGuard/TurnBackend";
    private static final String REG_RU_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
    // VK endpoints can be slow/unreliable on filtered networks; keep these generous.
    private static final int VK_POST_CONNECT_TIMEOUT_MS = 15000;
    private static final int VK_POST_READ_TIMEOUT_MS = 20000;
    private static final AtomicReference<CompletableFuture<VpnService>> vpnServiceFutureRef = new AtomicReference<>(new CompletableFuture<>());
    private static final AtomicReference<Context> applicationContextRef = new AtomicReference<>();
    private static final AtomicReference<Runnable> vpnServiceRevokedListenerRef = new AtomicReference<>();

    // Latch for synchronization: signals that JNI is registered and ready to protect sockets
    private static final AtomicReference<CountDownLatch> vpnServiceLatchRef = new AtomicReference<>(new CountDownLatch(1));
    @FunctionalInterface
    public interface CaptchaHandler {
        String apply(int cacheId, String redirectUri);
    }

    private static volatile CaptchaHandler captchaHandler;

    private TurnBackend() {
    }

    /**
     * Registers the VpnService instance and notifies the native layer.
     * @param service The VpnService instance.
     */
    public static void onVpnServiceCreated(@Nullable VpnService service) {
        Log.d(TAG, "onVpnServiceCreated called with service=" + (service != null ? "non-null" : "null"));

        if (service != null) {
            // 1. First set in JNI so sockets can be protected
            Log.d(TAG, "Calling wgSetVpnService()...");
            wgSetVpnService(service);
            Log.d(TAG, "wgSetVpnService() complete");

            // 2. Count down latch — JNI is ready to protect sockets
            vpnServiceLatchRef.get().countDown();
            Log.d(TAG, "vpnServiceLatchRef.countDown()");

            // 3. Then complete Future for Java code
            CompletableFuture<VpnService> currentFuture = vpnServiceFutureRef.getAndSet(new CompletableFuture<>());
            if (!currentFuture.isDone()) {
                currentFuture.complete(service);
                Log.d(TAG, "VpnService future completed");
            } else {
                // Old future already completed — complete the new one
                CompletableFuture<VpnService> newFuture = vpnServiceFutureRef.get();
                if (!newFuture.isDone()) {
                    newFuture.complete(service);
                    Log.d(TAG, "VpnService future completed (replacement)");
                }
            }
        } else {
            // Service destroyed - reset everything for next cycle
            Log.d(TAG, "VpnService destroyed, resetting future and latch");
            wgSetVpnService(null);
            vpnServiceFutureRef.set(new CompletableFuture<>());
            vpnServiceLatchRef.set(new CountDownLatch(1));  // Recreate latch for next launch
        }
    }

    public static void setVpnServiceRevokedListener(@Nullable Runnable listener) {
        vpnServiceRevokedListenerRef.set(listener);
        Log.d(TAG, "VpnService revoked listener " + (listener != null ? "registered" : "cleared"));
    }

    public static void notifyVpnServiceRevoked() {
        final Runnable listener = vpnServiceRevokedListenerRef.get();
        if (listener == null) {
            Log.d(TAG, "notifyVpnServiceRevoked: no listener registered");
            return;
        }
        try {
            listener.run();
        } catch (Throwable t) {
            Log.w(TAG, "VpnService revoked listener failed: " + t.getMessage());
        }
    }

    /**
     * Returns a future that completes when the VpnService is created.
     */
    public static CompletableFuture<VpnService> getVpnServiceFuture() {
        return vpnServiceFutureRef.get();
    }
    
    /**
     * Waits until the VpnService is registered in JNI and ready to protect sockets.
     * @param timeout Maximum time to wait in milliseconds
     * @return true if successfully registered, false on timeout or interrupt
     */
    public static boolean waitForVpnServiceRegistered(long timeout) {
        try {
            CountDownLatch latch = vpnServiceLatchRef.get();
            boolean success = latch.await(timeout, TimeUnit.MILLISECONDS);
            Log.d(TAG, "waitForVpnServiceRegistered: " + (success ? "SUCCESS" : "TIMEOUT (" + timeout + "ms)"));
            return success;
        } catch (InterruptedException e) {
            Log.e(TAG, "Interrupted while waiting for VpnService registration", e);
            Thread.currentThread().interrupt();  // Restore interrupt flag
            return false;
        }
    }

    public static void setCaptchaHandler(@Nullable CaptchaHandler handler) {
        captchaHandler = handler;
        Log.d(TAG, "Captcha handler " + (handler != null ? "registered" : "cleared"));
    }

    @Keep
    @SuppressWarnings("unused")
    public static String onCaptchaRequired(int cacheId, String redirectUri) {
        final CaptchaHandler handler = captchaHandler;
        if (handler == null) {
            Log.e(TAG, "No captcha handler registered");
            return "";
        }
        try {
            final String result = handler.apply(cacheId, redirectUri);
            return result != null ? result : "";
        } catch (Exception e) {
            Log.e(TAG, "Captcha handler failed", e);
            return "";
        }
    }

    public static void setApplicationContext(Context context) {
        final Context appContext = context.getApplicationContext();
        applicationContextRef.set(appContext);
        wgSetApplicationContext(appContext);
    }

    @Keep
    @Nullable
    public static String fetchUrlOnCurrentNetwork(String rawUrl, String userAgent) {
        final Context context = applicationContextRef.get();
        if (context == null) {
            Log.w(TAG, "fetchUrlOnCurrentNetwork: application context is not set");
            return null;
        }
        try {
            final ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            final URL url = new URL(rawUrl);
            final List<NetworkCandidate> candidates = selectPhysicalNetworkCandidates(cm);
            if (candidates.isEmpty()) {
                Log.w(TAG, "fetchUrlOnCurrentNetwork: no non-VPN network available for " + rawUrl);
                return null;
            }
            final String effectiveUserAgent = rawUrl.contains("reg.ru/web-tools/myip/get_data") ? REG_RU_USER_AGENT : userAgent;
            Throwable lastError = null;
            for (final NetworkCandidate candidate : candidates) {
                HttpURLConnection conn = null;
                try {
                    Log.d(TAG, "fetchUrlOnCurrentNetwork trying " + candidate.describe(cm));
                    conn = (HttpURLConnection) candidate.network.openConnection(url);
                    conn.setInstanceFollowRedirects(true);
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(5000);
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("User-Agent", effectiveUserAgent);
                    conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
                    conn.setRequestProperty("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7");
                    conn.setRequestProperty("Cache-Control", "no-cache");
                    conn.setRequestProperty("Pragma", "no-cache");
                    conn.setRequestProperty("DNT", "1");
                    conn.setRequestProperty("Priority", "u=0, i");
                    conn.setRequestProperty("sec-ch-ua", "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"");
                    conn.setRequestProperty("sec-ch-ua-mobile", "?0");
                    conn.setRequestProperty("sec-ch-ua-platform", "\"Linux\"");
                    conn.setRequestProperty("Sec-Fetch-Dest", "document");
                    conn.setRequestProperty("Sec-Fetch-Mode", "navigate");
                    conn.setRequestProperty("Sec-Fetch-Site", "none");
                    conn.setRequestProperty("Sec-Fetch-User", "?1");
                    conn.setRequestProperty("Upgrade-Insecure-Requests", "1");
                    conn.connect();
                    final int code = conn.getResponseCode();
                    if (code != HttpURLConnection.HTTP_OK) {
                        Log.w(TAG, "fetchUrlOnCurrentNetwork: HTTP " + code + " for " + rawUrl + " via " + candidate.describe(cm));
                        return null;
                    }
                    try (InputStream in = conn.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                        final byte[] buffer = new byte[4096];
                        int read;
                        while ((read = in.read(buffer)) >= 0) {
                            out.write(buffer, 0, read);
                            if (out.size() > 16384) {
                                break;
                            }
                        }
                        final String body = out.toString(StandardCharsets.UTF_8);
                        if (rawUrl.contains("reg.ru/web-tools/myip/get_data") && !looksLikeJson(body)) {
                            final String webViewBody = fetchUrlViaWebView(context, cm, candidate.network, rawUrl);
                            if (looksLikeJson(webViewBody)) {
                                Log.d(TAG, "fetchUrlOnCurrentNetwork: reg.ru resolved via WebView fallback");
                                return webViewBody;
                            }
                        }
                        return body;
                    }
                } catch (Throwable t) {
                    lastError = t;
                    Log.w(TAG, "fetchUrlOnCurrentNetwork failed via " + candidate.describe(cm) + " for " + rawUrl + ": " + t.getMessage());
                    if (!isRetryableNetworkFailure(t)) {
                        break;
                    }
                } finally {
                    if (conn != null) {
                        conn.disconnect();
                    }
                }
            }
            if (lastError != null) {
                Log.w(TAG, "fetchUrlOnCurrentNetwork exhausted candidates for " + rawUrl + ": " + lastError.getMessage());
            }
            return null;
        } catch (Throwable t) {
            Log.w(TAG, "fetchUrlOnCurrentNetwork failed for " + rawUrl + ": " + t.getMessage());
            return null;
        }
    }

    @Keep
    @Nullable
    public static String postUrlOnCurrentNetwork(String rawUrl, String postData, String userAgent) {
        final Context context = applicationContextRef.get();
        if (context == null) {
            Log.w(TAG, "postUrlOnCurrentNetwork: application context is not set");
            return wrapNetworkResponse(false, -1, "", "", "application context is not set");
        }
        try {
            final ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            final URL url = new URL(rawUrl);
            final List<NetworkCandidate> candidates = selectPhysicalNetworkCandidates(cm);
            if (candidates.isEmpty()) {
                Log.w(TAG, "postUrlOnCurrentNetwork: no non-VPN network available for " + rawUrl);
                return wrapNetworkResponse(false, -1, "", "", "no non-VPN network available");
            }
            final String effectiveUserAgent = (userAgent == null || userAgent.isBlank())
                ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
                : userAgent;
            Throwable lastError = null;
            for (final NetworkCandidate candidate : candidates) {
                HttpURLConnection conn = null;
                try {
                    Log.d(TAG, "postUrlOnCurrentNetwork trying " + candidate.describe(cm));
                    conn = (HttpURLConnection) candidate.network.openConnection(url);
                    conn.setInstanceFollowRedirects(true);
                    // Keep Android-side attempt short to leave time budget for next non-VPN network
                    // and Go transport fallback under high stream concurrency.
                    conn.setConnectTimeout(VK_POST_CONNECT_TIMEOUT_MS);
                    conn.setReadTimeout(VK_POST_READ_TIMEOUT_MS);
                    conn.setDoOutput(true);
                    conn.setRequestMethod("POST");
                    for (final Map.Entry<String, String> header : buildVkRequestHeaders(effectiveUserAgent).entrySet()) {
                        conn.setRequestProperty(header.getKey(), header.getValue());
                    }
                    final byte[] payload = (postData != null ? postData : "").getBytes(StandardCharsets.UTF_8);
                    conn.setFixedLengthStreamingMode(payload.length);
                    conn.connect();
                    try (OutputStream out = conn.getOutputStream()) {
                        out.write(payload);
                        out.flush();
                    }
                    final int code = conn.getResponseCode();
                    final InputStream bodyStream = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
                    final String body = readResponseBody(bodyStream, 32768);
                    final String contentType = conn.getHeaderField("Content-Type");
                    if (code >= 400) {
                        Log.w(TAG, "postUrlOnCurrentNetwork: HTTP " + code + " for " + rawUrl + " via " + candidate.describe(cm));
                        return wrapNetworkResponse(false, code, contentType, body, "HTTP " + code);
                    }
                    return wrapNetworkResponse(true, code, contentType, body, "");
                } catch (Throwable t) {
                    lastError = t;
                    Log.w(TAG, "postUrlOnCurrentNetwork failed via " + candidate.describe(cm) + " for " + rawUrl + ": " + t.getMessage());
                    if (!isRetryableNetworkFailure(t)) {
                        break;
                    }
                } finally {
                    if (conn != null) {
                        conn.disconnect();
                    }
                }
            }
            final String webViewResp = postUrlViaWebView(context, rawUrl, postData, userAgent);
            if (webViewResp != null) {
                Log.d(TAG, "postUrlOnCurrentNetwork: WebView fallback used for " + rawUrl);
                return webViewResp;
            }
            return wrapNetworkResponse(false, -1, "", "", lastError != null ? lastError.toString() : "unknown network failure");
        } catch (Throwable t) {
            Log.w(TAG, "postUrlOnCurrentNetwork failed for " + rawUrl + ": " + t.getMessage());
            final String webViewResp = postUrlViaWebView(context, rawUrl, postData, userAgent);
            if (webViewResp != null) {
                Log.d(TAG, "postUrlOnCurrentNetwork: WebView fallback used for " + rawUrl);
                return webViewResp;
            }
            return wrapNetworkResponse(false, -1, "", "", t.toString());
        }
    }

    private static Map<String, String> buildVkRequestHeaders(String userAgent) {
        final Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", userAgent);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("Accept", "*/*");
        headers.put("Accept-Language", "en-US,en;q=0.9");
        headers.put("Origin", "https://vk.ru");
        headers.put("Referer", "https://vk.ru/");
        headers.put("sec-ch-ua-platform", "\"Windows\"");
        headers.put("sec-ch-ua", "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"");
        headers.put("sec-ch-ua-mobile", "?0");
        headers.put("Sec-Fetch-Site", "same-site");
        headers.put("Sec-Fetch-Mode", "cors");
        headers.put("Sec-Fetch-Dest", "empty");
        headers.put("DNT", "1");
        headers.put("Priority", "u=1, i");
        return headers;
    }

    private static String readResponseBody(@Nullable InputStream in, int limit) throws Exception {
        if (in == null) {
            return "";
        }
        try (InputStream input = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            final byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read == 0) {
                    continue;
                }
                final int remaining = limit - out.size();
                if (remaining <= 0) {
                    break;
                }
                out.write(buffer, 0, Math.min(read, remaining));
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private static String wrapNetworkResponse(boolean ok, int status, @Nullable String contentType, @Nullable String body, @Nullable String error) {
        try {
            final JSONObject obj = new JSONObject();
            obj.put("ok", ok);
            obj.put("status", status);
            obj.put("contentType", contentType != null ? contentType : "");
            obj.put("body", body != null ? body : "");
            obj.put("error", error != null ? error : "");
            return obj.toString();
        } catch (Throwable t) {
            Log.w(TAG, "wrapNetworkResponse failed: " + t.getMessage());
            return "{\"ok\":false,\"status\":-1,\"contentType\":\"\",\"body\":\"\",\"error\":\"wrap failure\"}";
        }
    }

    @Nullable
    private static String postUrlViaWebView(Context context, String rawUrl, @Nullable String postData, @Nullable String userAgent) {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<String> resultRef = new AtomicReference<>(null);
        final AtomicBoolean completed = new AtomicBoolean(false);
        final Handler handler = new Handler(Looper.getMainLooper());

        handler.post(() -> {
            final WebView webView = new WebView(context);
            final Runnable finish = () -> {
                if (!completed.compareAndSet(false, true)) {
                    return;
                }
                try {
                    webView.stopLoading();
                } catch (Throwable ignored) {
                }
                try {
                    webView.destroy();
                } catch (Throwable ignored) {
                }
                latch.countDown();
            };

            try {
                final WebSettings settings = webView.getSettings();
                settings.setJavaScriptEnabled(true);
                settings.setDomStorageEnabled(true);
                settings.setLoadsImagesAutomatically(false);
                settings.setBlockNetworkImage(true);
                settings.setUserAgentString((userAgent == null || userAgent.isBlank())
                    ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
                    : userAgent);

                webView.setWebViewClient(new WebViewClient() {
                    @Override
                    public void onPageFinished(WebView view, String url) {
                        if (!"about:blank".equals(url)) {
                            return;
                        }
                        final String script = "(async function(){try{const resp=await fetch(" +
                            JSONObject.quote(rawUrl) +
                            ",{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'*/*','Accept-Language':'en-US,en;q=0.9','Origin':'https://vk.ru','Referer':'https://vk.ru/','sec-ch-ua-platform':'\"Windows\"','sec-ch-ua':'\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"','sec-ch-ua-mobile':'?0','Sec-Fetch-Site':'same-site','Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty','DNT':'1','Priority':'u=1, i'},body:" +
                            JSONObject.quote(postData != null ? postData : "") +
                            "});const text=await resp.text();return JSON.stringify({ok:resp.ok,status:resp.status,contentType:resp.headers.get('content-type')||'',body:text,error:''});}catch(e){return JSON.stringify({ok:false,status:-1,contentType:'',body:'',error:String(e)});}})();";
                        view.evaluateJavascript(script, value -> {
                            try {
                                final Object parsed = new JSONTokener(value).nextValue();
                                if (parsed instanceof String) {
                                    resultRef.set((String) parsed);
                                }
                            } catch (Throwable t) {
                                Log.w(TAG, "WebView POST JSON extraction failed: " + t.getMessage());
                            } finally {
                                finish.run();
                            }
                        });
                    }

                    @Override
                    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                        Log.w(TAG, "WebView POST received error for " + rawUrl + ": " + (error != null ? error.getDescription() : "unknown"));
                        finish.run();
                    }
                });

                webView.loadUrl("about:blank");
                handler.postDelayed(finish, 25000);
            } catch (Throwable t) {
                Log.w(TAG, "WebView POST fallback failed for " + rawUrl + ": " + t.getMessage());
                finish.run();
            }
        });

        try {
            if (!latch.await(27, TimeUnit.SECONDS)) {
                Log.w(TAG, "WebView POST fallback timed out for " + rawUrl);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return resultRef.get();
    }

    private static boolean looksLikeJson(@Nullable String body) {
        if (body == null) {
            return false;
        }
        final String trimmed = body.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    @Nullable
    private static String fetchUrlViaWebView(Context context, @Nullable ConnectivityManager cm, @Nullable Network network, String rawUrl) {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<String> resultRef = new AtomicReference<>(null);
        final AtomicBoolean completed = new AtomicBoolean(false);
        final Handler handler = new Handler(Looper.getMainLooper());

        handler.post(() -> {
            final CookieManager cookieManager = CookieManager.getInstance();
            final boolean bound = cm != null && network != null && cm.bindProcessToNetwork(network);
            final WebView webView = new WebView(context);
            final Runnable finish = () -> {
                if (!completed.compareAndSet(false, true)) {
                    return;
                }
                try {
                    webView.stopLoading();
                } catch (Throwable ignored) {
                }
                try {
                    webView.destroy();
                } catch (Throwable ignored) {
                }
                if (bound && cm != null) {
                    cm.bindProcessToNetwork(null);
                }
                latch.countDown();
            };

            try {
                cookieManager.removeAllCookies(null);
                cookieManager.flush();

                final WebSettings settings = webView.getSettings();
                settings.setJavaScriptEnabled(true);
                settings.setDomStorageEnabled(true);
                settings.setLoadsImagesAutomatically(false);
                settings.setBlockNetworkImage(true);
                settings.setUserAgentString(REG_RU_USER_AGENT);

                webView.setWebViewClient(new WebViewClient() {
                    @Override
                    public void onPageFinished(WebView view, String url) {
                        handler.postDelayed(() -> view.evaluateJavascript("(function(){return document.body ? document.body.innerText : '';})()", value -> {
                            try {
                                String body = null;
                                final Object parsed = new JSONTokener(value).nextValue();
                                if (parsed instanceof String) {
                                    body = (String) parsed;
                                } else if (value != null && !"null".equals(value)) {
                                    body = value;
                                }
                                if (looksLikeJson(body)) {
                                    resultRef.set(body);
                                    finish.run();
                                    return;
                                }
                                if (body != null) {
                                    final String preview = body.length() > 120 ? body.substring(0, 120) : body;
                                    Log.d(TAG, "WebView onPageFinished non-JSON for " + url + ": " + preview);
                                }
                            } catch (Throwable t) {
                                Log.w(TAG, "WebView JSON extraction failed: " + t.getMessage());
                            }
                        }), 2500);
                    }

                    @Override
                    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                        Log.w(TAG, "WebView received error for " + rawUrl + ": " + (error != null ? error.getDescription() : "unknown"));
                        finish.run();
                    }
                });

                final Map<String, String> headers = new HashMap<>();
                headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
                headers.put("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7");
                headers.put("Cache-Control", "no-cache");
                headers.put("Pragma", "no-cache");
                headers.put("DNT", "1");
                headers.put("Priority", "u=0, i");
                headers.put("sec-ch-ua", "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"");
                headers.put("sec-ch-ua-mobile", "?0");
                headers.put("sec-ch-ua-platform", "\"Linux\"");
                headers.put("Sec-Fetch-Dest", "document");
                headers.put("Sec-Fetch-Mode", "navigate");
                headers.put("Sec-Fetch-Site", "none");
                headers.put("Sec-Fetch-User", "?1");
                headers.put("Upgrade-Insecure-Requests", "1");
                webView.loadUrl(rawUrl, headers);
                handler.postDelayed(finish, 10000);
            } catch (Throwable t) {
                Log.w(TAG, "WebView fallback failed for " + rawUrl + ": " + t.getMessage());
                finish.run();
            }
        });

        try {
            if (!latch.await(12, TimeUnit.SECONDS)) {
                Log.w(TAG, "WebView fallback timed out for " + rawUrl);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return resultRef.get();
    }

    private static final class NetworkCandidate {
        final Network network;
        final int score;

        NetworkCandidate(Network network, int score) {
            this.network = network;
            this.score = score;
        }

        String describe(ConnectivityManager cm) {
            return "score=" + score + " " + describeNetwork(cm, network);
        }
    }

    @Nullable
    private static Network selectPhysicalNetwork(@Nullable ConnectivityManager cm) {
        final List<NetworkCandidate> candidates = selectPhysicalNetworkCandidates(cm);
        if (candidates.isEmpty()) {
            return null;
        }
        return candidates.get(0).network;
    }

    private static List<NetworkCandidate> selectPhysicalNetworkCandidates(@Nullable ConnectivityManager cm) {
        if (cm == null) {
            return Collections.emptyList();
        }
        final Network active = cm.getActiveNetwork();
        final List<NetworkCandidate> candidates = new ArrayList<>();
        for (final Network network : cm.getAllNetworks()) {
            final NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps == null) {
                continue;
            }
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                continue;
            }
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                continue;
            }
            int score = 0;
            if (network.equals(active)) {
                score += 100;
            }
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                score += 50;
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                score += 30;
            } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                score += 20;
            } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                score += 10;
            }
            final NetworkCandidate candidate = new NetworkCandidate(network, score);
            Log.d(TAG, "selectPhysicalNetwork candidate " + candidate.describe(cm));
            candidates.add(candidate);
        }
        candidates.sort((a, b) -> Integer.compare(b.score, a.score));
        if (!candidates.isEmpty()) {
            Log.d(TAG, "selectPhysicalNetwork selected " + candidates.get(0).describe(cm));
        } else {
            Log.w(TAG, "selectPhysicalNetwork found no non-VPN internet network");
        }
        return candidates;
    }

    private static boolean isRetryableNetworkFailure(Throwable t) {
        Throwable current = t;
        while (current != null) {
            final String message = current.getMessage() != null ? current.getMessage() : "";
            if (
                current instanceof java.net.UnknownHostException ||
                current instanceof ConnectException ||
                current instanceof SocketException ||
                current instanceof SocketTimeoutException ||
                current instanceof IllegalStateException ||
                message.contains("android_getaddrinfo") ||
                message.contains("EAI_") ||
                message.contains("Name or service not known") ||
                message.contains("software caused connection abort") ||
                message.contains("connection reset") ||
                message.contains("broken pipe")
            ) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private static String describeNetwork(ConnectivityManager cm, Network network) {
        final NetworkCapabilities caps = cm.getNetworkCapabilities(network);
        final android.net.LinkProperties props = cm.getLinkProperties(network);
        final StringBuilder transports = new StringBuilder();
        if (caps != null) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                transports.append("wifi");
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                if (transports.length() > 0) transports.append(',');
                transports.append("cellular");
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                if (transports.length() > 0) transports.append(',');
                transports.append("ethernet");
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                if (transports.length() > 0) transports.append(',');
                transports.append("vpn");
            }
        }
        if (transports.length() == 0) {
            transports.append("unknown");
        }
        final StringBuilder dns = new StringBuilder();
        if (props != null && props.getDnsServers() != null) {
            for (final java.net.InetAddress address : props.getDnsServers()) {
                if (dns.length() > 0) dns.append(',');
                dns.append(address.getHostAddress());
            }
        }
        return "handle=" + network.getNetworkHandle()
            + " transports=" + transports
            + " validated=" + (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            + " dns=[" + dns + "]";
    }

    public static native void wgSetVpnService(@Nullable VpnService service);
    public static native void wgSetApplicationContext(Context context);
    public static native int wgTurnProxyStart(
            String peerAddr,
            String vklink,
            String mode,
            int n,
            int useUdp,
            String listenAddr,
            String turnIp,
            int turnPort,
            String peerType,
            int streamsPerCred,
            int watchdogTimeout,
            long networkHandle,
            String publicKey,
            int keepaliveSec
    );
    public static native void wgTurnProxyStop();
    public static native void wgNotifyNetworkChange();
    public static native String wgTurnProxyGetRuntimeStatusJson();
}
