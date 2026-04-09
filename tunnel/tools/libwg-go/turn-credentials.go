/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// VKCredentials stores VK API client credentials
type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

type currentNetworkHTTPResponse struct {
	OK          bool   `json:"ok"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
	Error       string `json:"error"`
}

// Predefined list of VK credentials (tried in order until success)
var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
	//{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"}, // VK_MVK_APP_ID
	//{ClientID: "52461373", ClientSecret: "o557NLIkAErNhakXrQ7A"}, // VK_WEB_VKVIDEO_APP_ID
	//{ClientID: "52649896", ClientSecret: "WStp4ihWG4l3nmXZgIbC"}, // VK_MVK_VKVIDEO_APP_ID
	//{ClientID: "51781872", ClientSecret: "IjjCNl4L4Tf5QZEXIHKK"}, // VK_ID_AUTH_APP
}

// TurnCredentials stores cached TURN credentials
type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

// StreamCredentialsCache holds credentials cache for a single stream
type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
)

var streamsPerCred = 4

// getCacheID returns the shared cache ID for a given stream ID
func getCacheID(streamID int) int {
	if streamsPerCred <= 0 {
		return streamID / 4
	}
	return streamID / streamsPerCred
}

// vkRequestMu serializes VK API requests to avoid flood control
var vkRequestMu sync.Mutex

// vkDelayRandom sleeps for a random duration between minMs and maxMs to avoid bot detection
func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// credentialsStore manages shared credentials caches
var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

// getStreamCache returns or creates a shared cache for the given stream ID
func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	// Try read lock first for fast path
	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	// Need to create new cache
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

// isAuthError checks if the error is an authentication error
func isAuthError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

// handleAuthError handles authentication errors for a specific stream.
// Returns true if cache was invalidated, false otherwise.
func handleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	now := time.Now().Unix()

	// Reset counter if enough time has passed
	if now-cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	turnLog("[STREAM %d] Auth error (cache=%d, count=%d/%d)", streamID, cacheID, count, maxCacheErrors)

	// Invalidate cache only after N errors within the time window
	if count >= maxCacheErrors {
		turnLog("[VK Auth] Multiple auth errors detected (%d), invalidating cache %d for stream %d...", count, cacheID, streamID)
		cache.invalidate(streamID)
		return true
	}

	return false
}

// invalidate invalidates the credentials cache for this stream
func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	// Reset auth error counter
	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	turnLog("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

// invalidateAllCaches invalidates all shared caches (called on network change)
func invalidateAllCaches() {
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	// Clear the map - old caches will be garbage collected.
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	turnLog("[VK Auth] All shared caches cleared (streams per credentials: %d)", streamsPerCred)
}

// getVkCreds fetches TURN credentials from VK/OK API with shared caching
func getVkCreds(ctx context.Context, link string, streamID int) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Check cache - another stream may have populated it while waiting.
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		turnLog("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, expires in %v)", streamID, cacheID, expires)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}

	turnLog("[STREAM %d] [VK Auth] Cache miss (cache=%d), starting credential fetch...", streamID, cacheID)

	// Check context before long fetch
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}

	// Fetch credentials with rate limiting
	turnLog("[STREAM %d] [VK Auth] Entering serialized credential fetch (cache=%d)", streamID, cacheID)
	user, pass, addr, err := fetchVkCredsSerialized(ctx, link, streamID)
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Serialized credential fetch failed (cache=%d): %v", streamID, cacheID, err)
		return "", "", "", err
	}
	turnLog("[STREAM %d] [VK Auth] Serialized credential fetch returned addr=%s user_len=%d pass_len=%d", streamID, addr, len(user), len(pass))

	// Store in cache
	cache.creds = TurnCredentials{
		Username:   user,
		Password:   pass,
		ServerAddr: addr,
		ExpiresAt:  time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:       link,
	}

	turnLog("[STREAM %d] [VK Auth] Cache updated with server=%s link=%s", streamID, cache.creds.ServerAddr, cache.creds.Link)
	turnLog("[STREAM %d] [VK Auth] Success! Credentials cached until %v (cache=%d)", streamID, cache.creds.ExpiresAt, cacheID)
	return user, pass, addr, nil
}

// fetchVkCredsSerialized wraps fetchVkCreds with rate limiting to avoid VK flood control
func fetchVkCredsSerialized(ctx context.Context, link string, streamID int) (string, string, string, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	user, pass, addr, err := fetchVkCreds(ctx, link, streamID)
	return user, pass, addr, err
}

// fetchVkCreds performs the actual VK/OK API calls to fetch credentials
func fetchVkCreds(ctx context.Context, link string, streamID int) (string, string, string, error) {
	var lastErr error

	// Try each credentials pair until success
	for _, creds := range vkCredentialsList {
		turnLog("[STREAM %d] [VK Auth] Trying credentials: client_id=%s", streamID, creds.ClientID)

		user, pass, addr, err := getTokenChain(ctx, link, streamID, creds)
		if err == nil {
			turnLog("[STREAM %d] [VK Auth] Success with client_id=%s", streamID, creds.ClientID)
			return user, pass, addr, nil
		}

		lastErr = err
		turnLog("[STREAM %d] [VK Auth] Failed with client_id=%s: %v", streamID, creds.ClientID, err)

		// Check if it's a rate limit error - wait and try next credentials
		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "Rate limit") {
			turnLog("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials...", streamID)
		}
	}

	return "", "", "", fmt.Errorf("all VK credentials failed: %w", lastErr)
}

// getTokenChain performs the VK/OK API token chain with given credentials.
// Token 1: messages anonym_token -> getCallPreview -> Token 2 (getAnonymousToken)
// -> Token 3 (OK session_key) -> Token 4 (TURN credentials)
func getTokenChain(ctx context.Context, link string, streamID int, creds VKCredentials) (string, string, string, error) {
	doRequest := func(data string, requestURL string) (resp map[string]interface{}, err error) {
		parsedURL, err := url.Parse(requestURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL: %w", err)
		}

		targetHost := parsedURL.Hostname()
		_ = targetHost // used below for SNI + address selection

		req, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		// Match the browser-style request profile used in the working vk-turn-proxy fork.
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)
		req.Header.Set("sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("DNT", "1")
		req.Header.Set("Priority", "u=1, i")

		targetPort := parsedURL.Port()
		if targetPort == "" {
			targetPort = "443"
		}
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   protectControl,
		}

		client := &http.Client{
						Timeout: 35 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					host, port, splitErr := net.SplitHostPort(addr)
					if splitErr == nil && strings.EqualFold(host, targetHost) {
						candidateAddrs := make([]string, 0, 4)
						ips := gatherCandidateIPs(ctx, targetHost, 8)
						for _, ip := range ips {
							candidateAddrs = append(candidateAddrs, net.JoinHostPort(ip, port))
						}
						if len(candidateAddrs) == 0 {
							resolvedIP, resolveErrOne := hostCache.Resolve(ctx, targetHost)
							if resolveErrOne == nil && resolvedIP != "" {
								candidateAddrs = append(candidateAddrs, net.JoinHostPort(resolvedIP, port))
							} else {
								turnLog("[STREAM %d] [VK Auth] DNS fallback for %s failed, using original addr %s: %v", streamID, targetHost, addr, resolveErrOne)
							}
						}
						candidateAddrs = append(candidateAddrs, addr)

						var lastDialErr error
						seen := make(map[string]struct{}, len(candidateAddrs))
						for _, candidate := range candidateAddrs {
							if _, ok := seen[candidate]; ok {
								continue
							}
							seen[candidate] = struct{}{}
							turnLog("[STREAM %d] [VK Auth] Dialing %s via %s", streamID, targetHost, candidate)
							conn, dialErr := dialer.DialContext(ctx, network, candidate)
							if dialErr == nil {
								return conn, nil
							}
							lastDialErr = dialErr
							turnLog("[STREAM %d] [VK Auth] Dial via %s failed: %v", streamID, candidate, dialErr)
						}
						if lastDialErr != nil {
							return nil, lastDialErr
						}
					} else if splitErr == nil && targetHost != "" && targetPort != "" && host == "" {
						addr = net.JoinHostPort(targetHost, targetPort)
					}
					return dialer.DialContext(ctx, network, addr)
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				TLSClientConfig: &tls.Config{
					ServerName: targetHost,
				},
			},
		}
		defer client.CloseIdleConnections()

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		if httpResp.StatusCode >= 400 {
			bodyPreview := string(body)
			if len(bodyPreview) > 500 {
				bodyPreview = bodyPreview[:500]
			}
			return nil, fmt.Errorf("HTTP %d from %s: %s", httpResp.StatusCode, requestURL, bodyPreview)
		}

		contentType := httpResp.Header.Get("Content-Type")
		if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "text/javascript") {
			bodyPreview := string(body)
			if len(bodyPreview) > 500 {
				bodyPreview = bodyPreview[:500]
			}
			return nil, fmt.Errorf("unexpected content-type %s, status %d, body: %s", contentType, httpResp.StatusCode, bodyPreview)
		}

		if err = json.Unmarshal(body, &resp); err != nil {
			bodyPreview := string(body)
			if len(bodyPreview) > 500 {
				bodyPreview = bodyPreview[:500]
			}
			return nil, fmt.Errorf("JSON parse error: %w, body: %s", err, bodyPreview)
		}
		if errMsg, ok := resp["error"].(map[string]interface{}); ok {
			return resp, fmt.Errorf("VK error: %v", errMsg)
		}
		return resp, nil
	}

	// Token 1 (messages anonym_token)
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Token 1 request failed: %v", streamID, err)
		return "", "", "", err
	}
	// Check for VK API error in response
	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		turnLog("[STREAM %d] [VK Auth] Token 1 VK API error: %v", streamID, errMsg)
		return "", "", "", fmt.Errorf("VK API error (token1): %v", errMsg)
	}
	dataRaw, ok := resp["data"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 1: 'data' field not found in response: %v", streamID, resp)
		return "", "", "", fmt.Errorf("invalid response structure for token1: 'data' not found")
	}
	dataMap, ok := dataRaw.(map[string]interface{})
	if !ok || dataMap == nil {
		turnLog("[STREAM %d] [VK Auth] Token 1: invalid data type: %T", streamID, dataRaw)
		return "", "", "", fmt.Errorf("invalid response structure for token1: %v", resp)
	}
	token1Raw, ok := dataMap["access_token"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 1: 'access_token' field not found in data: %v", streamID, dataMap)
		return "", "", "", fmt.Errorf("token1 not found in response: %v", resp)
	}
	token1, ok := token1Raw.(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 1: 'access_token' is not a string: %T", streamID, token1Raw)
		return "", "", "", fmt.Errorf("token1 is not a string: %v", token1Raw)
	}
	turnLog("[STREAM %d] [VK Auth] Token 1 (anonym_token) received", streamID)

	vkDelayRandom(50, 120)

	// getCallPreview - emulate browser behavior (HAR entry 189)
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s", url.QueryEscape(link), token1)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] getCallPreview request failed: %v", streamID, err)
	} else {
		turnLog("[STREAM %d] [VK Auth] getCallPreview completed (optional)", streamID)
	}

	vkDelayRandom(150, 300)

	// Token 2 (getAnonymousToken)
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=123&access_token=%s", url.QueryEscape(link), token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)
	resp, err = doRequest(data, urlAddr)
	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		captchaErr := ParseVkCaptchaError(errMsg)
		if captchaErr != nil && captchaErr.IsCaptchaError() {
			turnLog("[STREAM %d] [VK Auth] Token 2: Captcha detected, solving...", streamID)

			successToken, solveErr := solveVkCaptcha(ctx, captchaErr, streamID)
			if solveErr != nil {
				turnLog("[STREAM %d] [VK Auth] Token 2: Captcha solving failed: %v", streamID, solveErr)
				return "", "", "", fmt.Errorf("captcha solving failed: %w", solveErr)
			}

			turnLog("[STREAM %d] [VK Auth] Token 2: Retrying with captcha solution...", streamID)
			data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=123"+
				"&captcha_key="+
				"&captcha_sid=%s"+
				"&is_sound_captcha=0"+
				"&success_token=%s"+
				"&captcha_ts=%s"+
				"&captcha_attempt=%s"+
				"&access_token=%s",
				url.QueryEscape(link),
				captchaErr.CaptchaSid,
				successToken,
				captchaErr.CaptchaTs,
				captchaErr.CaptchaAttempt,
				token1)
			resp, err = doRequest(data, urlAddr)
			if err != nil {
				turnLog("[STREAM %d] [VK Auth] Token 2 retry failed: %v", streamID, err)
				return "", "", "", err
			}
			if errMsg2, ok := resp["error"].(map[string]interface{}); ok {
				turnLog("[STREAM %d] [VK Auth] Token 2 retry still has error: %v", streamID, errMsg2)
				return "", "", "", fmt.Errorf("VK API error (token2 retry): %v", errMsg2)
			}
		} else {
			turnLog("[STREAM %d] [VK Auth] Token 2 VK API error: %v", streamID, errMsg)
			return "", "", "", fmt.Errorf("VK API error (token2): %v", errMsg)
		}
	} else if err != nil {
		turnLog("[STREAM %d] [VK Auth] Token 2 request failed: %v", streamID, err)
		return "", "", "", err
	}
	responseRaw, ok := resp["response"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 2: 'response' field not found in response: %v", streamID, resp)
		return "", "", "", fmt.Errorf("invalid response structure for token2: 'response' not found")
	}
	responseMap, ok := responseRaw.(map[string]interface{})
	if !ok || responseMap == nil {
		turnLog("[STREAM %d] [VK Auth] Token 2: invalid response type: %T", streamID, responseRaw)
		return "", "", "", fmt.Errorf("invalid response structure for token2: %v", resp)
	}
	token2Raw, ok := responseMap["token"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 2: 'token' field not found in response: %v", streamID, responseMap)
		return "", "", "", fmt.Errorf("token2 not found in response: %v", resp)
	}
	token2, ok := token2Raw.(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 2: 'token' is not a string: %T", streamID, token2Raw)
		return "", "", "", fmt.Errorf("token2 is not a string: %v", token2Raw)
	}
	turnLog("[STREAM %d] [VK Auth] Token 2 (messages token) received", streamID)

	vkDelayRandom(50, 120)

	// Token 3 (auth.anonymLogin - independent request, doesn't need token2)
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", url.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Token 3 request failed: %v", streamID, err)
		return "", "", "", err
	}
	// Check for error in response
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		turnLog("[STREAM %d] [VK Auth] Token 3 API error: %s", streamID, errMsg)
		return "", "", "", fmt.Errorf("Token 3 API error: %s", errMsg)
	}
	token3Raw, ok := resp["session_key"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 3: 'session_key' field not found in response: %v", streamID, resp)
		return "", "", "", fmt.Errorf("token3 not found in response: %v", resp)
	}
	token3, ok := token3Raw.(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 3: 'session_key' is not a string: %T", streamID, token3Raw)
		return "", "", "", fmt.Errorf("token3 is not a string: %v", token3Raw)
	}
	turnLog("[STREAM %d] [VK Auth] Token 3 (session_key) received", streamID)

	vkDelayRandom(50, 120)

	// Token 4 (vchat.joinConversationByLink -> TURN credentials)
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", url.QueryEscape(link), token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Token 4 request failed: %v", streamID, err)
		return "", "", "", err
	}
	// Check for error in response
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		turnLog("[STREAM %d] [VK Auth] Token 4 API error: %s", streamID, errMsg)
		return "", "", "", fmt.Errorf("Token 4 API error: %s", errMsg)
	}
	turnLog("[STREAM %d] [VK Auth] TURN credentials received", streamID)

	tsRaw, ok := resp["turn_server"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'turn_server' field not found in response: %v", streamID, resp)
		return "", "", "", fmt.Errorf("turn_server not found in response: %v", resp)
	}
	ts, ok := tsRaw.(map[string]interface{})
	if !ok || ts == nil {
		turnLog("[STREAM %d] [VK Auth] 'turn_server' is not a map: %T", streamID, tsRaw)
		return "", "", "", fmt.Errorf("invalid turn_server type: %v", tsRaw)
	}
	urlsRaw, ok := ts["urls"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'urls' field not found in turn_server: %v", streamID, ts)
		return "", "", "", fmt.Errorf("urls not found in turn_server: %v", ts)
	}
	urls, ok := urlsRaw.([]interface{})
	if !ok || len(urls) == 0 {
		turnLog("[STREAM %d] [VK Auth] 'urls' is not a valid array: %T", streamID, urlsRaw)
		return "", "", "", fmt.Errorf("invalid urls in turn_server: %v", ts)
	}
	urlStr, ok := urls[0].(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] first url is not a string: %T", streamID, urls[0])
		return "", "", "", fmt.Errorf("invalid url type in turn_server: %v", ts)
	}
	address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(urlStr, "?")[0], "turn:"), "turns:")

	// Resolve TURN server address via cascading DNS (if it's a domain)
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		// Check if host is IP address
		if ip := net.ParseIP(host); ip == nil {
			// It's a domain name, resolve it
			resolvedIP, err := hostCache.Resolve(ctx, host)
			if err != nil {
				turnLog("[STREAM %d] [TURN DNS] Warning: failed to resolve TURN server %s: %v", streamID, host, err)
				// Don't fail, use original address
			} else {
				address = net.JoinHostPort(resolvedIP, port)
				turnLog("[STREAM %d] [TURN DNS] Resolved TURN server %s -> %s", streamID, host, resolvedIP)
			}
		}
	}

	usernameRaw, ok := ts["username"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'username' field not found in turn_server: %v", streamID, ts)
		return "", "", "", fmt.Errorf("username not found in turn_server: %v", ts)
	}
	username, ok := usernameRaw.(string)
	if !ok || username == "" {
		turnLog("[STREAM %d] [VK Auth] 'username' is not a valid string: %T", streamID, usernameRaw)
		return "", "", "", fmt.Errorf("username not found in turn_server: %v", ts)
	}
	credentialRaw, ok := ts["credential"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'credential' field not found in turn_server: %v", streamID, ts)
		return "", "", "", fmt.Errorf("credential not found in turn_server: %v", ts)
	}
	credential, ok := credentialRaw.(string)
	if !ok || credential == "" {
		turnLog("[STREAM %d] [VK Auth] 'credential' is not a valid string: %T", streamID, credentialRaw)
		return "", "", "", fmt.Errorf("credential not found in turn_server: %v", ts)
	}

	return username, credential, address, nil
}
