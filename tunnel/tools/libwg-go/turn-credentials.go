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

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
	tlsclient "github.com/kiper292/tls-client"
	"github.com/kiper292/tls-client/profiles"
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

const defaultVKCredentialsProfile = "web_app"

var vkCredentialsProfiles = map[string][]VKCredentials{
	"web_app": {
		{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
	},
	"mvk_app": {
		{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"}, // VK_MVK_APP_ID
	},
	"web_video_app": {
		{ClientID: "52461373", ClientSecret: "o557NLIkAErNhakXrQ7A"}, // VK_WEB_VKVIDEO_APP_ID
	},
	"mvk_video_app": {
		{ClientID: "52649896", ClientSecret: "WStp4ihWG4l3nmXZgIbC"}, // VK_MVK_VKVIDEO_APP_ID
	},
	"vk_id_auth_app": {
		{ClientID: "51781872", ClientSecret: "IjjCNl4L4Tf5QZEXIHKK"}, // VK_ID_AUTH_APP
	},
	"official_android_app": {
		{ClientID: "2274003", ClientSecret: "hHbZxrka2uZ6jB1inYsH"}, // VK official Android
	},
	"official_iphone_app": {
		{ClientID: "3140623", ClientSecret: "VeWdmVclDCtn6ihuP1nt"}, // VK official iPhone
	},
	"official_ipad_app": {
		{ClientID: "3682744", ClientSecret: "mY6CDUswIVdJLCD3j15n"}, // VK official iPad
	},
	"official_windows_app": {
		{ClientID: "3697615", ClientSecret: "AlVXZFMUqyrnABp8ncuU"}, // VK official Windows desktop
	},
	"official_windows_phone_app": {
		{ClientID: "3502557", ClientSecret: "PEObAuQi6KloPM4T30DV"}, // VK official Windows Phone
	},
}

var vkCredentialsProfileOrder = []string{
	"web_app",
	"mvk_app",
	"web_video_app",
	"mvk_video_app",
	"vk_id_auth_app",
	"official_android_app",
	"official_iphone_app",
	"official_ipad_app",
	"official_windows_app",
	// official_windows_phone_app currently only adds noise in auto-switch:
	// calls.getAnonymousToken returns error_code:29 Rate limit reached.
}

var currentVKCredentialsProfile = defaultVKCredentialsProfile
var autoSwitchVKCredentials bool
var enabledVKCredentialsProfilesMu sync.RWMutex
var enabledVKCredentialsProfiles = map[string]bool{}
var vkCredentialsProfileWaitMu sync.Mutex
var vkCredentialsProfileWaitUntil = map[string]int64{}
var vkCredentialsProfileRetryMu sync.Mutex
var vkCredentialsProfileRetryUntil = map[string]int64{}
var vkCredentialsProfileUnsupportedMu sync.Mutex
var vkCredentialsProfileUnsupported = map[string]string{}
var vkAutoSwitchRunSeq atomic.Uint64

func normalizeVKCredentialsProfile(profile string) string {
	switch strings.TrimSpace(strings.ToLower(profile)) {
	case "web_app", "mvk_app", "web_video_app", "mvk_video_app", "vk_id_auth_app",
		"official_android_app", "official_iphone_app", "official_ipad_app",
		"official_windows_app":
		return strings.TrimSpace(strings.ToLower(profile))
	default:
		return defaultVKCredentialsProfile
	}
}

func isKnownVKCredentialsProfile(profile string) bool {
	profile = strings.TrimSpace(strings.ToLower(profile))
	if _, ok := vkCredentialsProfiles[profile]; !ok {
		return false
	}
	return profile != "official_windows_phone_app"
}

func setVKCredentialsProfile(profile string) {
	currentVKCredentialsProfile = normalizeVKCredentialsProfile(profile)
	turnLog("[VK Auth] Active credentials profile: %s", currentVKCredentialsProfile)
}

func setAutoSwitchVKCredentials(enabled bool) {
	autoSwitchVKCredentials = enabled
	turnLog("[VK Auth] Auto-switch credentials profile: %t", autoSwitchVKCredentials)
}

func setVKCredentialsProfileOptions(raw string) {
	enabled := map[string]bool{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == '\t' || r == ' '
	}) {
		profile := strings.TrimSpace(strings.ToLower(part))
		if isKnownVKCredentialsProfile(profile) {
			enabled[profile] = true
		}
	}
	if len(enabled) == 0 {
		for _, profile := range vkCredentialsProfileOrder {
			enabled[profile] = true
		}
	}

	enabledVKCredentialsProfilesMu.Lock()
	enabledVKCredentialsProfiles = enabled
	enabledVKCredentialsProfilesMu.Unlock()

	if autoSwitchVKCredentials && !enabled[currentVKCredentialsProfile] {
		for _, profile := range vkCredentialsProfileOrder {
			if enabled[profile] {
				currentVKCredentialsProfile = profile
				break
			}
		}
	}

	ordered := make([]string, 0, len(enabled))
	for _, profile := range vkCredentialsProfileOrder {
		if enabled[profile] {
			ordered = append(ordered, profile)
		}
	}
	turnLog("[VK Auth] Enabled credentials profiles: %s", strings.Join(ordered, ","))
}

func isVKCredentialsProfileEnabled(profile string) bool {
	if !autoSwitchVKCredentials {
		return true
	}
	profile = normalizeVKCredentialsProfile(profile)
	enabledVKCredentialsProfilesMu.RLock()
	defer enabledVKCredentialsProfilesMu.RUnlock()
	if len(enabledVKCredentialsProfiles) == 0 {
		return true
	}
	return enabledVKCredentialsProfiles[profile]
}

func beginVKCredentialsRun() {
	if !autoSwitchVKCredentials {
		return
	}
	seq := vkAutoSwitchRunSeq.Add(1)
	turnLog("[VK Auth] Auto-switch run sequence: %d", seq)
}

func currentVKAutoSwitchOffset(size int) int {
	if !autoSwitchVKCredentials || size <= 0 {
		return 0
	}
	seq := vkAutoSwitchRunSeq.Load()
	if seq == 0 {
		return 0
	}
	return int((seq - 1) % uint64(size))
}

func rotatedStrings(items []string, offset int) []string {
	if len(items) == 0 {
		return items
	}
	offset %= len(items)
	if offset == 0 {
		return append([]string(nil), items...)
	}
	rotated := make([]string, 0, len(items))
	rotated = append(rotated, items[offset:]...)
	rotated = append(rotated, items[:offset]...)
	return rotated
}

func selectedVKCredentialsBaseProfiles() []string {
	start := normalizeVKCredentialsProfile(currentVKCredentialsProfile)
	profiles := []string{}
	if isVKCredentialsProfileEnabled(start) {
		profiles = append(profiles, start)
	}
	if autoSwitchVKCredentials {
		for _, profile := range vkCredentialsProfileOrder {
			if profile != start && isVKCredentialsProfileEnabled(profile) {
				profiles = append(profiles, profile)
			}
		}
		profiles = rotatedStrings(profiles, currentVKAutoSwitchOffset(len(profiles)))
	}
	if len(profiles) == 0 {
		return []string{defaultVKCredentialsProfile}
	}
	return profiles
}

func selectedVKCredentialsProfilesForLink(link string) []string {
	start := normalizeVKCredentialsProfile(currentVKCredentialsProfile)
	if !autoSwitchVKCredentials {
		return []string{start}
	}

	profiles := make([]string, 0, len(vkCredentialsProfileOrder)+1)
	add := func(profile string) {
		profile = normalizeVKCredentialsProfile(profile)
		if !containsString(profiles, profile) {
			profiles = append(profiles, profile)
		}
	}

	for _, profile := range runtimeActiveVKCredentialsProfiles() {
		profile = normalizeVKCredentialsProfile(profile)
		if isVKCredentialsProfileEnabled(profile) &&
			vkCredentialsProfileWaitRemaining(profile, link) == 0 &&
			vkCredentialsProfileRetryRemaining(profile, link) == 0 {
			add(profile)
		}
	}
	for _, profile := range selectedVKCredentialsBaseProfiles() {
		add(profile)
	}
	return profiles
}

func selectedVKCredentialsList(profile string) []VKCredentials {
	if list, ok := vkCredentialsProfiles[normalizeVKCredentialsProfile(profile)]; ok && len(list) > 0 {
		return list
	}
	return vkCredentialsProfiles[defaultVKCredentialsProfile]
}

var vkCallLinksState = struct {
	mu    sync.RWMutex
	links []string
}{
	links: nil,
}

func normalizeVKCallLink(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		if token := strings.TrimPrefix(parsed.Path, "/call/join/"); token != parsed.Path {
			return strings.TrimSpace(token)
		}
	}
	if idx := strings.Index(raw, "/call/join/"); idx >= 0 {
		token := raw[idx+len("/call/join/"):]
		if cut := strings.IndexAny(token, "?#& \t\r\n"); cut >= 0 {
			token = token[:cut]
		}
		return strings.TrimSpace(token)
	}
	return raw
}

func setVKCallLinks(primary string, pool string, enablePool bool) {
	seen := make(map[string]struct{})
	links := make([]string, 0, 4)
	add := func(raw string) {
		link := normalizeVKCallLink(raw)
		if link == "" {
			return
		}
		if _, ok := seen[link]; ok {
			return
		}
		seen[link] = struct{}{}
		links = append(links, link)
	}
	add(primary)
	if enablePool {
		for _, part := range strings.FieldsFunc(pool, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';' || r == '\t' || r == ' '
		}) {
			add(part)
		}
	}
	vkCallLinksState.mu.Lock()
	vkCallLinksState.links = links
	vkCallLinksState.mu.Unlock()
	turnLog("[VK Auth] VK call link pool configured: count=%d autoPool=%t", len(links), enablePool)
	for i, link := range links {
		turnLog("[VK Auth] VK call link #%d: %s", i+1, link)
	}
}

func selectedVKCallLinks(primary string) []string {
	vkCallLinksState.mu.RLock()
	links := append([]string(nil), vkCallLinksState.links...)
	vkCallLinksState.mu.RUnlock()
	if len(links) == 0 {
		if link := normalizeVKCallLink(primary); link != "" {
			return []string{link}
		}
	}
	if autoSwitchVKCredentials && len(links) > 1 {
		links = rotatedStrings(links, currentVKAutoSwitchOffset(len(links)))
	}
	return links
}

// TurnCredentials stores cached TURN credentials
type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
	Profile    string
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
var captchaLockoutMu sync.Mutex
var captchaLockoutByCache = map[string]int64{}

const (
	captchaLimitSentinel = "__CAPTCHA_LIMIT_REACHED__"
	captchaWaitSentinel  = "__CAPTCHA_WAIT_REQUIRED__"
)

// getCacheID returns the shared cache ID for a given stream ID
func getCacheID(streamID int) int {
	if streamsPerCred <= 0 {
		return streamID / 4
	}
	return streamID / streamsPerCred
}

// vkRequestMu serializes VK API requests to avoid flood control
var vkRequestMu sync.Mutex

type captchaSolveMode int

const (
	captchaSolveModeAuto captchaSolveMode = iota
	captchaSolveModeSliderPOC
	captchaSolveModeManual
)

func captchaSolveModeForAttempt(attempt int, manualCaptcha bool, enableSliderPOC bool) (captchaSolveMode, bool) {
	switch attempt {
	case 0:
		if enableSliderPOC {
			return captchaSolveModeAuto, true
		}
		if manualCaptcha {
			return captchaSolveModeManual, true
		}
	case 1:
		if enableSliderPOC {
			return captchaSolveModeSliderPOC, true
		}
	case 2:
		if manualCaptcha {
			return captchaSolveModeManual, true
		}
	}
	return 0, false
}

func captchaSolveModeLabel(mode captchaSolveMode) string {
	switch mode {
	case captchaSolveModeAuto:
		return "auto captcha"
	case captchaSolveModeSliderPOC:
		return "auto captcha slider POC"
	case captchaSolveModeManual:
		return "manual captcha"
	default:
		return "captcha"
	}
}

func vkProfileLinkKey(profile string, link string) string {
	return normalizeVKCredentialsProfile(profile) + "|" + normalizeVKCallLink(link)
}

func captchaLockoutKey(streamID int, profile string, link string) string {
	return fmt.Sprintf("%s:%d", vkProfileLinkKey(profile, link), getCacheID(streamID))
}

func captchaLockoutRemaining(streamID int, profile string, link string) time.Duration {
	key := captchaLockoutKey(streamID, profile, link)
	captchaLockoutMu.Lock()
	defer captchaLockoutMu.Unlock()

	until := captchaLockoutByCache[key]
	if until <= 0 {
		return 0
	}
	remaining := time.Until(time.Unix(until, 0))
	if remaining <= 0 {
		delete(captchaLockoutByCache, key)
		return 0
	}
	return remaining
}

func clearCaptchaLockouts() {
	captchaLockoutMu.Lock()
	defer captchaLockoutMu.Unlock()
	captchaLockoutByCache = map[string]int64{}
	vkCredentialsProfileWaitMu.Lock()
	vkCredentialsProfileWaitUntil = map[string]int64{}
	vkCredentialsProfileWaitMu.Unlock()
	vkCredentialsProfileRetryMu.Lock()
	vkCredentialsProfileRetryUntil = map[string]int64{}
	vkCredentialsProfileRetryMu.Unlock()
	vkCredentialsProfileUnsupportedMu.Lock()
	vkCredentialsProfileUnsupported = map[string]string{}
	vkCredentialsProfileUnsupportedMu.Unlock()
}

func noteCaptchaWaitLockout(streamID int, profile string, link string, reason string) {
	if captchaBackoffSec <= 0 {
		turnLog("[STREAM %d] [Captcha] VK captcha wait detected for profile=%s link=%s (%s); per-cache lockout disabled", streamID, normalizeVKCredentialsProfile(profile), normalizeVKCallLink(link), reason)
		return
	}
	cacheID := getCacheID(streamID)
	profile = normalizeVKCredentialsProfile(profile)
	link = normalizeVKCallLink(link)
	key := captchaLockoutKey(streamID, profile, link)
	until := time.Now().Add(time.Duration(captchaBackoffSec) * time.Second)
	captchaLockoutMu.Lock()
	captchaLockoutByCache[key] = until.Unix()
	captchaLockoutMu.Unlock()
	noteVKCredentialsProfileWait(profile, link, until)
	turnLog("[STREAM %d] [Captcha] VK captcha wait detected for profile=%s link=%s cache=%d (%s); suppressing until %s", streamID, profile, link, cacheID, reason, until.Format(time.RFC3339))
	setRuntimeModeInfo(fmt.Sprintf("VK captcha cooldown: %s link %s cache %d for %s", profile, link, cacheID, time.Until(until).Round(time.Second)))
}

func noteVKCredentialsProfileWait(profile string, link string, until time.Time) {
	key := vkProfileLinkKey(profile, link)
	vkCredentialsProfileWaitMu.Lock()
	vkCredentialsProfileWaitUntil[key] = until.Unix()
	vkCredentialsProfileWaitMu.Unlock()
}

func vkCredentialsProfileWaitRemaining(profile string, link string) time.Duration {
	key := vkProfileLinkKey(profile, link)
	vkCredentialsProfileWaitMu.Lock()
	defer vkCredentialsProfileWaitMu.Unlock()
	until := vkCredentialsProfileWaitUntil[key]
	if until <= 0 {
		return 0
	}
	remaining := time.Until(time.Unix(until, 0))
	if remaining <= 0 {
		delete(vkCredentialsProfileWaitUntil, key)
		return 0
	}
	return remaining
}

func noteVKCredentialsProfileRetryBackoff(profile string, link string, until time.Time) {
	key := vkProfileLinkKey(profile, link)
	vkCredentialsProfileRetryMu.Lock()
	vkCredentialsProfileRetryUntil[key] = until.Unix()
	vkCredentialsProfileRetryMu.Unlock()
}

func vkCredentialsProfileRetryRemaining(profile string, link string) time.Duration {
	key := vkProfileLinkKey(profile, link)
	vkCredentialsProfileRetryMu.Lock()
	defer vkCredentialsProfileRetryMu.Unlock()
	until := vkCredentialsProfileRetryUntil[key]
	if until <= 0 {
		return 0
	}
	remaining := time.Until(time.Unix(until, 0))
	if remaining <= 0 {
		delete(vkCredentialsProfileRetryUntil, key)
		return 0
	}
	return remaining
}

func noteVKCredentialsProfileUnsupported(profile string, reason string) {
	profile = normalizeVKCredentialsProfile(profile)
	vkCredentialsProfileUnsupportedMu.Lock()
	vkCredentialsProfileUnsupported[profile] = reason
	vkCredentialsProfileUnsupportedMu.Unlock()
}

func vkCredentialsProfileUnsupportedReason(profile string) string {
	profile = normalizeVKCredentialsProfile(profile)
	vkCredentialsProfileUnsupportedMu.Lock()
	defer vkCredentialsProfileUnsupportedMu.Unlock()
	return vkCredentialsProfileUnsupported[profile]
}

func profileRetryBackoffDuration() time.Duration {
	backoffSec := quotaBackoffSec
	if backoffSec <= 0 {
		backoffSec = 1
	}
	return time.Duration(backoffSec) * time.Second
}

func isVKRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "error_code:29") || strings.Contains(strings.ToLower(msg), "rate limit")
}

func isVKProfileRetryError(err error) bool {
	if err == nil {
		return false
	}
	return isVKRateLimitError(err)
}

func isVKUnsupportedProfileError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "error_code:3") ||
		strings.Contains(msg, "error_code:43")
}

func shortVKProfileErrorReason(err error) string {
	if err == nil {
		return "unknown VK API error"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "error_code:3"):
		return "error_code:3 Unknown method"
	case strings.Contains(msg, "error_code:43"):
		return "error_code:43 temporary unavailable"
	default:
		return msg
	}
}

// vkDelayRandom sleeps for a random duration between minMs and maxMs to avoid bot detection
func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func getCustomNetDialer() net.Dialer {
	return net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   protectControl,
	}
}

func getCustomDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	resolvedIP, err := hostCache.Resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	dialer := getCustomNetDialer()
	return dialer.DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
}

func newVKCaptchaHTTPClient() (tlsclient.HttpClient, Profile, error) {
	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithDialer(getCustomNetDialer()),
		tlsclient.WithDialContext(getCustomDialContext),
	)
	if err != nil {
		return nil, Profile{}, fmt.Errorf("failed to create captcha tlsclient: %w", err)
	}
	return client, Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}, nil
}

func doVKBrowserProfileRequest(ctx context.Context, requestURL string, data string, client tlsclient.HttpClient, profile Profile) (map[string]interface{}, error) {
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("parse request URL: %w", err)
	}

	req, err := fhttp.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return nil, err
	}

	req.Host = parsedURL.Hostname()
	applyBrowserProfileFhttp(req, profileWithSavedCaptcha(profile))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	origin := "https://vk.ru"
	if strings.EqualFold(parsedURL.Hostname(), "api.vk.ru") {
		origin = "https://api.vk.ru"
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Priority", "u=1, i")

	httpResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = httpResp.Body.Close()
	}()

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

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		bodyPreview := string(body)
		if len(bodyPreview) > 500 {
			bodyPreview = bodyPreview[:500]
		}
		return nil, fmt.Errorf("browser-profile JSON parse error: %w, body: %s", err, bodyPreview)
	}
	return resp, nil
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
func getVkCreds(ctx context.Context, link string, streamID int) (string, string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)
	links := selectedVKCallLinks(link)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Check cache - another stream may have populated it while waiting.
	if containsString(links, cache.creds.Link) && cache.creds.Profile != "" && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		turnLog("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, profile=%s, link=%s, expires in %v)", streamID, cacheID, cache.creds.Profile, cache.creds.Link, expires)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, cache.creds.Profile, nil
	}

	turnLog("[STREAM %d] [VK Auth] Cache miss (cache=%d), starting credential fetch...", streamID, cacheID)

	// Check context before long fetch
	select {
	case <-ctx.Done():
		return "", "", "", "", ctx.Err()
	default:
	}

	// Fetch credentials with rate limiting
	turnLog("[STREAM %d] [VK Auth] Entering serialized credential fetch (cache=%d)", streamID, cacheID)
	user, pass, addr, profile, usedLink, err := fetchVkCredsSerialized(ctx, link, streamID)
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Serialized credential fetch failed (cache=%d): %v", streamID, cacheID, err)
		return "", "", "", profile, err
	}
	turnLog("[STREAM %d] [VK Auth] Serialized credential fetch returned profile=%s link=%s addr=%s user_len=%d pass_len=%d", streamID, profile, usedLink, addr, len(user), len(pass))

	// Store in cache
	cache.creds = TurnCredentials{
		Username:   user,
		Password:   pass,
		ServerAddr: addr,
		ExpiresAt:  time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:       usedLink,
		Profile:    normalizeVKCredentialsProfile(profile),
	}

	turnLog("[STREAM %d] [VK Auth] Cache updated with profile=%s server=%s link=%s", streamID, cache.creds.Profile, cache.creds.ServerAddr, cache.creds.Link)
	turnLog("[STREAM %d] [VK Auth] Success! Credentials cached until %v (cache=%d)", streamID, cache.creds.ExpiresAt, cacheID)
	return user, pass, addr, cache.creds.Profile, nil
}

// fetchVkCredsSerialized wraps fetchVkCreds with rate limiting to avoid VK flood control
func fetchVkCredsSerialized(ctx context.Context, link string, streamID int) (string, string, string, string, string, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	user, pass, addr, profile, usedLink, err := fetchVkCreds(ctx, link, streamID)
	return user, pass, addr, profile, usedLink, err
}

// fetchVkCreds performs the actual VK/OK API calls to fetch credentials
func fetchVkCreds(ctx context.Context, link string, streamID int) (string, string, string, string, string, error) {
	var lastErr error
	var captchaWaitErr error
	var retryWaitErr error
	var usableErr error
	var skippedErr error
	links := selectedVKCallLinks(link)
	rememberErr := func(err error, skipped bool) {
		if err == nil {
			return
		}
		lastErr = err
		msg := err.Error()
		switch {
		case strings.Contains(msg, "CAPTCHA_WAIT_REQUIRED"):
			if captchaWaitErr == nil {
				captchaWaitErr = err
			}
		case strings.Contains(msg, "VK_PROFILE_RETRY_WAIT"):
			if retryWaitErr == nil {
				retryWaitErr = err
			}
		case skipped:
			if skippedErr == nil {
				skippedErr = err
			}
		default:
			usableErr = err
		}
	}

	for linkIndex, candidateLink := range links {
		profiles := selectedVKCredentialsProfilesForLink(candidateLink)
		for _, profile := range profiles {
			profile = normalizeVKCredentialsProfile(profile)
			if reason := vkCredentialsProfileUnsupportedReason(profile); reason != "" {
				err := fmt.Errorf("VK credentials profile %s skipped in this tunnel run: %s", profile, reason)
				rememberErr(err, true)
				if !autoSwitchVKCredentials {
					return "", "", "", profile, candidateLink, err
				}
				turnLog("[STREAM %d] [VK Auth] Skipping profile=%s link=%s: %v", streamID, profile, candidateLink, err)
				continue
			}

			if remaining := vkCredentialsProfileRetryRemaining(profile, candidateLink); remaining > 0 {
				err := fmt.Errorf("VK_PROFILE_RETRY_WAIT: VK credentials profile %s link %s cooldown active for %s", profile, candidateLink, remaining.Round(time.Second))
				rememberErr(err, false)
				if !autoSwitchVKCredentials {
					return "", "", "", profile, candidateLink, err
				}
				turnLog("[STREAM %d] [VK Auth] Skipping profile=%s link=%s: %v", streamID, profile, candidateLink, err)
				continue
			}

			if remaining := vkCredentialsProfileWaitRemaining(profile, candidateLink); remaining > 0 {
				err := fmt.Errorf("CAPTCHA_WAIT_REQUIRED: VK credentials profile %s link %s cooldown active for %s", profile, candidateLink, remaining.Round(time.Second))
				rememberErr(err, false)
				if !autoSwitchVKCredentials {
					return "", "", "", profile, candidateLink, err
				}
				turnLog("[STREAM %d] [VK Auth] Skipping profile=%s link=%s: %v", streamID, profile, candidateLink, err)
				continue
			}

			if remaining := captchaLockoutRemaining(streamID, profile, candidateLink); remaining > 0 {
				err := fmt.Errorf("CAPTCHA_WAIT_REQUIRED: captcha cache %d profile %s link %s lockout active for %s", getCacheID(streamID), profile, candidateLink, remaining.Round(time.Second))
				rememberErr(err, false)
				if !autoSwitchVKCredentials {
					return "", "", "", profile, candidateLink, err
				}
				turnLog("[STREAM %d] [VK Auth] Skipping profile=%s link=%s cache=%d: %v", streamID, profile, candidateLink, getCacheID(streamID), err)
				continue
			}

			for _, creds := range selectedVKCredentialsList(profile) {
				turnLog("[STREAM %d] [VK Auth] Trying link=%d/%d profile=%s client_id=%s", streamID, linkIndex+1, len(links), profile, creds.ClientID)

				user, pass, addr, err := getTokenChain(ctx, candidateLink, streamID, profile, creds, true)
				if err == nil {
					if currentVKCredentialsProfile != profile {
						currentVKCredentialsProfile = profile
						turnLog("[VK Auth] Switched active credentials profile to %s", profile)
					}
					turnLog("[STREAM %d] [VK Auth] Success with link=%s profile=%s client_id=%s", streamID, candidateLink, profile, creds.ClientID)
					return user, pass, addr, profile, candidateLink, nil
				}

				rememberErr(err, false)
				noteRuntimeVKCredentialsProfileError(profile)
				turnLog("[STREAM %d] [VK Auth] Failed with link=%s profile=%s client_id=%s: %v", streamID, candidateLink, profile, creds.ClientID, err)

				if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") {
					backoffSec := captchaBackoffSec
					if backoffSec <= 0 {
						backoffSec = 1
					}
					noteVKCredentialsProfileWait(profile, candidateLink, time.Now().Add(time.Duration(backoffSec)*time.Second))
					if autoSwitchVKCredentials {
						turnLog("[STREAM %d] [VK Auth] Profile=%s link=%s hit captcha wait; trying next profile/link", streamID, profile, candidateLink)
						break
					}
				}

				if isVKProfileRetryError(err) {
					until := time.Now().Add(profileRetryBackoffDuration())
					noteVKCredentialsProfileRetryBackoff(profile, candidateLink, until)
					if isVKRateLimitError(err) {
						turnLog("[STREAM %d] [VK Auth] Rate limit detected for profile=%s link=%s; suppressing until %s", streamID, profile, candidateLink, until.Format(time.RFC3339))
					} else {
						turnLog("[STREAM %d] [VK Auth] Profile-dependent VK error for profile=%s link=%s; suppressing until %s", streamID, profile, candidateLink, until.Format(time.RFC3339))
					}
					if autoSwitchVKCredentials {
						turnLog("[STREAM %d] [VK Auth] Profile=%s link=%s hit profile-dependent VK error; trying next profile/link", streamID, profile, candidateLink)
						break
					}
				}

				if isVKUnsupportedProfileError(err) {
					reason := shortVKProfileErrorReason(err)
					noteVKCredentialsProfileUnsupported(profile, reason)
					turnLog("[STREAM %d] [VK Auth] Profile=%s is not usable for calls API in this tunnel run: %s", streamID, profile, reason)
					if autoSwitchVKCredentials {
						turnLog("[STREAM %d] [VK Auth] Profile=%s marked unsupported; trying next profile", streamID, profile)
						break
					}
				}
			}
		}
	}

	switch {
	case captchaWaitErr != nil:
		lastErr = captchaWaitErr
	case retryWaitErr != nil:
		lastErr = retryWaitErr
	case usableErr != nil:
		lastErr = usableErr
	case skippedErr != nil:
		lastErr = fmt.Errorf("CAPTCHA_WAIT_REQUIRED: VK credentials profiles are temporarily unavailable; trying another profile/link later")
	case lastErr == nil:
		lastErr = fmt.Errorf("CAPTCHA_WAIT_REQUIRED: no VK credentials candidates are ready")
	}
	return "", "", "", "", "", fmt.Errorf("all VK credentials failed: %w", lastErr)
}

// getTokenChain performs the VK/OK API token chain with given credentials.
// Token 1: messages anonym_token -> getCallPreview -> Token 2 (getAnonymousToken)
// -> Token 3 (OK session_key) -> Token 4 (TURN credentials)
func getTokenChain(ctx context.Context, link string, streamID int, profile string, creds VKCredentials, manualCaptcha bool) (string, string, string, error) {
	link = normalizeVKCallLink(link)
	doRequest := func(data string, requestURL string) (resp map[string]interface{}, err error) {
		browserProfile := profileWithSavedCaptcha(Profile{
			UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
			SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			SecChUaMobile:   "?0",
			SecChUaPlatform: `"Windows"`,
		})
		browserUserAgent := browserProfile.UserAgent

		parsedURL, err := url.Parse(requestURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL: %w", err)
		}

		targetHost := parsedURL.Hostname()
		_ = targetHost // used below for SNI + address selection

		// For Android builds, VK/OK auth requests should prefer the platform-selected
		// physical network so root/kernel mode does not recurse back into the tunnel.
		if currentNetworkRaw, currentNetworkErr := postWithCurrentNetwork(requestURL, data, browserUserAgent); currentNetworkErr == nil {
			var networkResp currentNetworkHTTPResponse
			if err := json.Unmarshal([]byte(currentNetworkRaw), &networkResp); err != nil {
				turnLog("[STREAM %d] [VK Auth] Current-network POST wrapper parse failed for %s: %v", streamID, requestURL, err)
			} else if !networkResp.OK {
				preview := strings.TrimSpace(networkResp.Body)
				if len(preview) > 500 {
					preview = preview[:500]
				}
				turnLog(
					"[STREAM %d] [VK Auth] Current-network POST failed for %s: status=%d error=%s body=%s",
					streamID,
					requestURL,
					networkResp.Status,
					networkResp.Error,
					preview,
				)
			} else {
				if networkResp.ContentType != "" &&
					!strings.Contains(networkResp.ContentType, "application/json") &&
					!strings.Contains(networkResp.ContentType, "text/javascript") {
					bodyPreview := strings.TrimSpace(networkResp.Body)
					if len(bodyPreview) > 500 {
						bodyPreview = bodyPreview[:500]
					}
					return nil, fmt.Errorf("unexpected current-network content-type %s, status %d, body: %s", networkResp.ContentType, networkResp.Status, bodyPreview)
				}
				if err := json.Unmarshal([]byte(networkResp.Body), &resp); err != nil {
					bodyPreview := strings.TrimSpace(networkResp.Body)
					if len(bodyPreview) > 500 {
						bodyPreview = bodyPreview[:500]
					}
					return nil, fmt.Errorf("current-network JSON parse error: %w, body: %s", err, bodyPreview)
				}
				if errMsg, ok := resp["error"].(map[string]interface{}); ok {
					return resp, fmt.Errorf("VK error: %v", errMsg)
				}
				turnLog("[STREAM %d] [VK Auth] Current-network POST succeeded for %s", streamID, requestURL)
				return resp, nil
			}
		} else {
			turnLog("[STREAM %d] [VK Auth] Current-network POST unavailable for %s: %v", streamID, requestURL, currentNetworkErr)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		// Match the browser-style request profile used in the working vk-turn-proxy fork.
		req.Header.Set("User-Agent", browserUserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		origin := "https://vk.ru"
		if strings.EqualFold(parsedURL.Hostname(), "api.vk.ru") {
			origin = "https://api.vk.ru"
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Referer", origin+"/")
		req.Header.Set("sec-ch-ua-platform", browserProfile.SecChUaPlatform)
		req.Header.Set("sec-ch-ua", browserProfile.SecChUa)
		req.Header.Set("sec-ch-ua-mobile", browserProfile.SecChUaMobile)
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
		if errMsg, ok := resp["error"].(map[string]interface{}); resp != nil && ok {
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
	name := generateName()
	escapedName := url.QueryEscape(name)
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	captchaClient, captchaProfile, err := newVKCaptchaHTTPClient()
	if err != nil {
		turnLog("[STREAM %d] [Captcha] TLS captcha client unavailable: %v", streamID, err)
	}
	if captchaClient != nil {
		defer captchaClient.CloseIdleConnections()
	}

	var token2 string
	for attempt := 0; ; attempt++ {
		if remaining := captchaLockoutRemaining(streamID, profile, link); remaining > 0 {
			return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED: captcha cache %d profile %s link %s lockout active for %s", getCacheID(streamID), normalizeVKCredentialsProfile(profile), link, remaining.Round(time.Second))
		}
		resp, err = doRequest(data, urlAddr)
		if resp == nil && err != nil && captchaClient != nil {
			turnLog("[STREAM %d] [VK Auth] Current-network token2 POST did not return a response, trying browser-profile: %v", streamID, err)
			resp, err = doVKBrowserProfileRequest(ctx, urlAddr, data, captchaClient, captchaProfile)
			if err == nil {
				turnLog("[STREAM %d] [VK Auth] Browser-profile POST succeeded for %s", streamID, urlAddr)
			} else {
				turnLog("[STREAM %d] [VK Auth] Browser-profile POST failed for %s: %v", streamID, urlAddr, err)
			}
		}
		if resp == nil {
			if err != nil {
				turnLog("[STREAM %d] [VK Auth] Token 2 request failed: %v", streamID, err)
				return "", "", "", err
			}
			return "", "", "", fmt.Errorf("empty token2 response")
		}

		if errMsg, ok := resp["error"].(map[string]interface{}); ok {
			captchaErr := ParseVkCaptchaError(errMsg)
			if captchaErr == nil || !captchaErr.IsCaptchaError() {
				turnLog("[STREAM %d] [VK Auth] Token 2 VK API error: %v", streamID, errMsg)
				return "", "", "", fmt.Errorf("VK API error (token2): %v", errMsg)
			}

			solveMode, hasSolveMode := captchaSolveModeForAttempt(attempt, manualCaptcha, captchaClient != nil)
			if !hasSolveMode {
				turnLog("[STREAM %d] [Captcha] No more solve modes available (attempt %d)", streamID, attempt+1)
				noteCaptchaWaitLockout(streamID, profile, link, "no_more_solve_modes")
				return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
			}

			turnLog("[STREAM %d] [Captcha] Token 2 captcha detected, mode=%s", streamID, captchaSolveModeLabel(solveMode))
			var successToken string
			var solveErr error

			captchaMutex.Lock()
			switch solveMode {
			case captchaSolveModeAuto:
				successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, captchaClient, captchaProfile, false)
			case captchaSolveModeSliderPOC:
				successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, captchaClient, captchaProfile, true)
			case captchaSolveModeManual:
				successToken, solveErr = solveVkCaptchaManual(captchaErr, streamID)
			}
			captchaMutex.Unlock()

			if solveErr != nil {
				turnLog("[STREAM %d] [Captcha] %s failed (attempt %d): %v", streamID, captchaSolveModeLabel(solveMode), attempt+1, solveErr)
				if strings.Contains(solveErr.Error(), "ERROR_LIMIT") ||
					strings.Contains(solveErr.Error(), "CAPTCHA_LIMIT_REACHED") ||
					strings.Contains(solveErr.Error(), "CAPTCHA_WAIT_REQUIRED") {
					noteCaptchaWaitLockout(streamID, profile, link, solveErr.Error())
					return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}
				if nextSolveMode, ok := captchaSolveModeForAttempt(attempt+1, manualCaptcha, captchaClient != nil); ok {
					turnLog("[STREAM %d] [Captcha] Falling back to %s...", streamID, captchaSolveModeLabel(nextSolveMode))
					continue
				}
				noteCaptchaWaitLockout(streamID, profile, link, solveErr.Error())
				return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
			}

			if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
				captchaErr.CaptchaAttempt = "1"
			}
			values := url.Values{}
			values.Set("vk_join_link", "https://vk.com/call/join/"+link)
			values.Set("name", name)
			values.Set("captcha_key", "")
			values.Set("is_sound_captcha", "0")
			values.Set("success_token", successToken)
			values.Set("access_token", token1)
			if captchaErr.CaptchaSid != "" {
				values.Set("captcha_sid", captchaErr.CaptchaSid)
			}
			if captchaErr.CaptchaTs != "" {
				values.Set("captcha_ts", captchaErr.CaptchaTs)
			}
			if captchaErr.CaptchaAttempt != "" {
				values.Set("captcha_attempt", captchaErr.CaptchaAttempt)
			}
			data = values.Encode()
			continue
		}
		if err != nil {
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
		token2, ok = token2Raw.(string)
		if !ok {
			turnLog("[STREAM %d] [VK Auth] Token 2: 'token' is not a string: %T", streamID, token2Raw)
			return "", "", "", fmt.Errorf("token2 is not a string: %v", token2Raw)
		}
		break
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
