/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2023 The Pion community <https://pion.ly>
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <android/log.h>
#include <stdlib.h>
extern int wgProtectSocket(int fd);
extern char* wgFetchUrlWithCurrentNetwork(const char* raw_url, const char* user_agent);
extern const char* getNetworkDnsServers(long long network_handle);
*/
import "C"

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

var turnClientTag = C.CString("WireGuard/TurnClient")

func turnLog(format string, args ...interface{}) {
	l := AndroidLogger{level: C.ANDROID_LOG_INFO, tag: turnClientTag}
	l.Printf(format, args...)
}

func protectControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		C.wgProtectSocket(C.int(fd))
	})
}

func (s *stream) writeDTLS(conn *dtls.Conn, payload []byte, deadline time.Duration) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if deadline > 0 {
		conn.SetWriteDeadline(time.Now().Add(deadline))
		defer conn.SetWriteDeadline(time.Time{})
	}
	return conn.Write(payload)
}

func init() {
}

//export wgNotifyNetworkChange
func wgNotifyNetworkChange() {
	// Clear DNS cache
	ClearCache()

	turnHTTPClient.CloseIdleConnections()
	turnLog("[NETWORK] Network change notified: HTTP connections cleared, DNS cache cleared")
}

var turnHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: protectControl,
		}).DialContext,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	},
}

var streamStartDelayMs = 200
var startupTimeoutSec = 75
var quotaBackoffSec = 15

type stream struct {
	ctx             context.Context
	id              int
	in              chan []byte
	out             net.PacketConn
	peer            atomic.Pointer[net.Addr] // Last seen addr from WireGuard
	ready           atomic.Bool
	writeMu         sync.Mutex
	sessionID       []byte
	cert            *tls.Certificate
	meta            *metaRuntime
	peerType        string
	watchdogTimeout int
	startup         *startupTracker
}

const iPacketBuffMaxSize = 2048

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, iPacketBuffMaxSize)
	},
}

// Metrics for diagnostics
var (
	dtlsTxDropCount    atomic.Uint64 // Drops in DTLS TX goroutine
	dtlsRxErrorCount   atomic.Uint64 // Errors in DTLS RX goroutine
	relayTxErrorCount  atomic.Uint64 // Errors in relay TX
	relayRxErrorCount  atomic.Uint64 // Errors in relay RX
	noDtlsTxDropCount  atomic.Uint64 // Drops in NoDTLS TX
	noDtlsRxErrorCount atomic.Uint64 // Errors in NoDTLS RX
)

type startupTracker struct {
	mu                sync.Mutex
	totalStreams      int
	anyReady          bool
	forbiddenByStream map[int]struct{}
	terminalFailure   bool
	terminalByStream  map[int]string
}

func newStartupTracker(totalStreams int) *startupTracker {
	return &startupTracker{
		totalStreams:      totalStreams,
		forbiddenByStream: make(map[int]struct{}, totalStreams),
		terminalByStream:  make(map[int]string, totalStreams),
	}
}

func (t *startupTracker) noteReady() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.anyReady = true
	t.mu.Unlock()
}

func (t *startupTracker) noteForbidden(streamID int) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.anyReady || t.terminalFailure {
		return false
	}
	t.forbiddenByStream[streamID] = struct{}{}
	// Forbidden IP is a hard relay-side rejection for current egress IP.
	// During startup we fail fast on the first such error to avoid noisy retries.
	t.terminalFailure = true
	return true
}

func (t *startupTracker) noteTerminalStartupError(streamID int, reason string) (bool, string) {
	if t == nil {
		return false, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.anyReady || t.terminalFailure {
		return false, ""
	}
	if reason == "" {
		reason = "startup terminal error"
	}
	t.terminalByStream[streamID] = reason
	if len(t.terminalByStream) < t.totalStreams {
		return false, ""
	}
	t.terminalFailure = true

	unique := make(map[string]struct{}, len(t.terminalByStream))
	var last string
	for _, v := range t.terminalByStream {
		unique[v] = struct{}{}
		last = v
	}
	if len(unique) == 1 {
		return true, last
	}
	return true, "multiple terminal startup errors"
}

type externalIPResponse struct {
	IP string `json:"ip"`
}

type metaRuntime struct {
	PublicKey      string
	SessionIDHex   string
	KeepaliveSec   int
	lastFrameByKey sync.Map // key(streamID:relayIP) -> sent
	ipMu           sync.RWMutex
	resolveMu      sync.Mutex
	clientPublicIP string
	nextResolveAt  time.Time
}

const publicIPRetryCooldown = 10 * time.Minute
const regRuUserAgent = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36"

func (m *metaRuntime) getClientPublicIP() string {
	m.ipMu.RLock()
	defer m.ipMu.RUnlock()
	return m.clientPublicIP
}

func (m *metaRuntime) setClientPublicIP(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	m.ipMu.Lock()
	m.clientPublicIP = ip
	m.ipMu.Unlock()
}

func (m *metaRuntime) ensureClientPublicIP(ctx context.Context, timeout time.Duration) string {
	if ip := m.getClientPublicIP(); ip != "" {
		return ip
	}
	m.resolveMu.Lock()
	defer m.resolveMu.Unlock()

	if ip := m.getClientPublicIP(); ip != "" {
		return ip
	}
	if !m.nextResolveAt.IsZero() && time.Now().Before(m.nextResolveAt) {
		return ""
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	setRuntimeModeInfo("Resolving public IP")
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	resolved := getExternalIP(reqCtx)
	cancel()
	if resolved != "" {
		m.setClientPublicIP(resolved)
		m.nextResolveAt = time.Time{}
		setRuntimeModeInfo("Public IP resolved")
		return resolved
	}
	m.nextResolveAt = time.Now().Add(publicIPRetryCooldown)
	turnLog("[META] external IP unresolved, skipping client_public_ip for %s", publicIPRetryCooldown)
	setRuntimeModeInfo("Public IP unavailable")
	return ""
}

type runtimeStatus struct {
	ModeInfo       string   `json:"mode_info"`
	ClientPublicIP string   `json:"client_public_ip"`
	RelayIPs       []string `json:"relay_ips"`
	LastSyncUnix   int64    `json:"last_sync_unix"`
	ActiveStreams  int      `json:"active_streams"`
	ErrorCount     int      `json:"error_count"`
	LastError      string   `json:"last_error"`
}

var runtimeState struct {
	mu     sync.RWMutex
	status runtimeStatus
}

func resetRuntimeState() {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	runtimeState.status = runtimeStatus{}
}

func setRuntimeModeInfo(mode string) {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	runtimeState.status.ModeInfo = strings.TrimSpace(mode)
}

func updateRuntimeState(clientIP string, relayIP string) {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	if clientIP != "" {
		runtimeState.status.ClientPublicIP = clientIP
	}
	if relayIP != "" && !containsString(runtimeState.status.RelayIPs, relayIP) {
		runtimeState.status.RelayIPs = append(runtimeState.status.RelayIPs, relayIP)
		sort.Strings(runtimeState.status.RelayIPs)
	}
	runtimeState.status.LastSyncUnix = time.Now().Unix()
}

func updateActiveStreams(delta int) int {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	runtimeState.status.ActiveStreams += delta
	if runtimeState.status.ActiveStreams < 0 {
		runtimeState.status.ActiveStreams = 0
	}
	runtimeState.status.LastSyncUnix = time.Now().Unix()
	return runtimeState.status.ActiveStreams
}

func setRuntimeError(err error) {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	runtimeState.status.ErrorCount++
	if err != nil {
		runtimeState.status.LastError = err.Error()
	}
	runtimeState.status.LastSyncUnix = time.Now().Unix()
}

func isForbiddenIPError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "forbidden ip") ||
		(strings.Contains(msg, "error 403") && strings.Contains(msg, "forbidden"))
}

func startupTerminalReason(err error) string {
	if err == nil {
		return ""
	}
	if isForbiddenIPError(err) {
		return "relay forbidden ip"
	}
	if isAllocationQuotaError(err) {
		return "relay allocation quota reached"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "all retransmissions failed") {
		return "relay unreachable (all retransmissions failed)"
	}
	return ""
}

func containsString(items []string, candidate string) bool {
	for _, v := range items {
		if v == candidate {
			return true
		}
	}
	return false
}

func runtimeStatusJSON() string {
	runtimeState.mu.RLock()
	defer runtimeState.mu.RUnlock()
	data, err := json.Marshal(runtimeState.status)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func parseExternalIPResponse(body []byte) string {
	var data externalIPResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}
	return strings.TrimSpace(data.IP)
}

func encodeURIComponent(value string) string {
	escaped := url.QueryEscape(value)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "%28", "(")
	escaped = strings.ReplaceAll(escaped, "%29", ")")
	return escaped
}

func regRuChallengeCookies(setCookies []*http.Cookie, userAgent string) []*http.Cookie {
	var jsCookie *http.Cookie
	for _, cookie := range setCookies {
		if cookie != nil && cookie.Name == "__js_p_" {
			jsCookie = cookie
			break
		}
	}
	if jsCookie == nil {
		return nil
	}

	parts := strings.Split(jsCookie.Value, ",")
	if len(parts) < 1 {
		return nil
	}
	code, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}

	x := 123456789
	k := 0
	for i := 0; i < 1677696; i++ {
		x = ((x + code) ^ (x + (x % 3) + (x % 17) + code) ^ i) % 16776960
		if x%117 == 0 {
			k = (k + 1) % 1111
		}
	}

	return []*http.Cookie{
		{Name: "__js_p_", Value: jsCookie.Value},
		{Name: "__jhash_", Value: strconv.Itoa(k)},
		{Name: "__jua_", Value: encodeURIComponent(userAgent)},
	}
}

func regRuCookieHeader(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

func getExternalIP(ctx context.Context) string {
	const metaHost = "www.reg.ru"
	const metaPath = "/web-tools/myip/get_data"

	rawURL := "https://" + metaHost + metaPath
	cRawURL := C.CString(rawURL)
	cUserAgent := C.CString(regRuUserAgent)
	javaBody := C.wgFetchUrlWithCurrentNetwork(cRawURL, cUserAgent)
	C.free(unsafe.Pointer(cRawURL))
	C.free(unsafe.Pointer(cUserAgent))
	if javaBody != nil {
		body := C.GoString(javaBody)
		C.free(unsafe.Pointer(javaBody))
		if ip := parseExternalIPResponse([]byte(body)); ip != "" {
			turnLog("[META] external IP resolved via Android network stack")
			return ip
		}
		preview := strings.TrimSpace(body)
		if len(preview) > 160 {
			preview = preview[:160]
		}
		turnLog("[META] Android network stack returned non-JSON for %s: %q", metaHost, preview)
	}

	doReq := func(rawURL string, hostHeader string, tlsServerName string) string {
		prepareClient := func() *http.Client {
			client := turnHTTPClient
			if tlsServerName == "" {
				return client
			}
			base, ok := turnHTTPClient.Transport.(*http.Transport)
			if !ok {
				return client
			}
			clone := base.Clone()
			if clone.TLSClientConfig == nil {
				clone.TLSClientConfig = &tls.Config{ServerName: tlsServerName}
			} else {
				cfg := clone.TLSClientConfig.Clone()
				cfg.ServerName = tlsServerName
				clone.TLSClientConfig = cfg
			}
			return &http.Client{Timeout: turnHTTPClient.Timeout, Transport: clone}
		}

		doOnce := func(extraCookies []*http.Cookie) (string, string) {
			req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
			if err != nil {
				return "", fmt.Sprintf("build request: %v", err)
			}
			req.Header.Set("User-Agent", regRuUserAgent)
			req.Header.Set("Accept", "application/json,text/plain,*/*")
			if hostHeader != "" {
				req.Host = hostHeader
			}
			for _, cookie := range extraCookies {
				req.AddCookie(cookie)
			}

			resp, err := prepareClient().Do(req)
			if err != nil {
				return "", fmt.Sprintf("request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			if err != nil {
				return "", fmt.Sprintf("read body: %v", err)
			}
			if ip := parseExternalIPResponse(body); ip != "" {
				return ip, ""
			}

			contentType := resp.Header.Get("Content-Type")
			preview := strings.TrimSpace(string(body))
			if len(preview) > 160 {
				preview = preview[:160]
			}

			if challengeCookies := regRuChallengeCookies(resp.Cookies(), regRuUserAgent); len(challengeCookies) > 0 && !strings.Contains(contentType, "application/json") {
				retryReq, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
				if err != nil {
					return "", fmt.Sprintf("build retry request: %v", err)
				}
				retryReq.Header.Set("User-Agent", regRuUserAgent)
				retryReq.Header.Set("Accept", "application/json,text/plain,*/*")
				if hostHeader != "" {
					retryReq.Host = hostHeader
				}
				cookieHeader := regRuCookieHeader(challengeCookies)
				if cookieHeader != "" {
					retryReq.Header.Set("Cookie", cookieHeader)
				}

				retryResp, err := prepareClient().Do(retryReq)
				if err != nil {
					return "", fmt.Sprintf("challenge retry failed: %v", err)
				}
				defer retryResp.Body.Close()

				retryBody, err := io.ReadAll(io.LimitReader(retryResp.Body, 16*1024))
				if err != nil {
					return "", fmt.Sprintf("challenge body: %v", err)
				}
				if ip := parseExternalIPResponse(retryBody); ip != "" {
					return ip, ""
				}

				retryPreview := strings.TrimSpace(string(retryBody))
				if len(retryPreview) > 160 {
					retryPreview = retryPreview[:160]
				}
				return "", fmt.Sprintf("challenge retry status=%d content-type=%q body=%q", retryResp.StatusCode, retryResp.Header.Get("Content-Type"), retryPreview)
			}

			return "", fmt.Sprintf("status=%d content-type=%q body=%q", resp.StatusCode, contentType, preview)
		}

		ip, reason := doOnce(nil)
		if ip != "" {
			return ip
		}
		turnLog("[META] external IP request attempt failed for %s via %s: %s", metaHost, rawURL, reason)
		return ""
	}

	// Prefer resolved IP + explicit SNI/Host to avoid broken system DNS before tunnel is up.
	if ip, err := hostCache.Resolve(ctx, metaHost); err == nil && ip != "" {
		if resolved := doReq("https://"+net.JoinHostPort(ip, "443")+metaPath, metaHost, metaHost); resolved != "" {
			return resolved
		}
	}

	// Fallback to default HTTPS URL if custom resolution path failed.
	if direct := doReq("https://"+metaHost+metaPath, "", ""); direct != "" {
		return direct
	}

	turnLog("[META] external IP request failed for %s", metaHost)
	return ""
}

func relayIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func encodeMetaFrame(meta ClientMeta) ([]byte, error) {
	payload, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	if len(payload) > 0xFFFF {
		return nil, errors.New("control payload too large")
	}
	frame := make([]byte, 8+len(payload))
	copy(frame[:4], []byte{'W', 'G', 'T', 'M'})
	frame[4] = 1
	frame[5] = 1
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)
	return frame, nil
}

type ClientMeta struct {
	PublicKey      string `json:"public_key"`
	SessionID      string `json:"session_id"`
	ClientPublicIP string `json:"client_public_ip,omitempty"`
	RelayIP        string `json:"relay_ip"`
	StreamID       byte   `json:"stream_id"`
	KeepaliveSec   int    `json:"persistent_keepalive"`
	TsUnix         int64  `json:"ts_unix"`
}

func (s *stream) sendMetaFrame(conn *dtls.Conn, relayIP string, clientIP string) {
	m := s.meta
	meta := ClientMeta{
		PublicKey:      m.PublicKey,
		SessionID:      m.SessionIDHex,
		ClientPublicIP: clientIP,
		RelayIP:        relayIP,
		StreamID:       byte(s.id),
		KeepaliveSec:   m.KeepaliveSec,
		TsUnix:         time.Now().Unix(),
	}
	frameKey := fmt.Sprintf("%d:%s", s.id, relayIP)
	lastClientIP, _ := m.lastFrameByKey.Load(frameKey)
	if sentClientIP, _ := lastClientIP.(string); sentClientIP == clientIP {
		return
	}
	turnLog("[STREAM %d] metadata frame prepare: pubkey=%t relay=%s client_ip=%s keepalive=%ds", s.id, m.PublicKey != "", relayIP, clientIP, m.KeepaliveSec)
	frame, err := encodeMetaFrame(meta)
	if err != nil {
		turnLog("[STREAM %d] metadata frame encode failed: %v", s.id, err)
		return
	}
	if _, err := s.writeDTLS(conn, frame, 2*time.Second); err != nil {
		turnLog("[STREAM %d] metadata frame send failed: %v", s.id, err)
	} else {
		m.lastFrameByKey.Store(frameKey, clientIP)
		turnLog("[STREAM %d] metadata frame sent: relay=%s client_ip=%s", s.id, relayIP, clientIP)
	}
}

func (s *stream) run(link string, peer *net.UDPAddr, udp bool, okchan chan<- struct{}, turnIp string, turnPort int) {
	reconnectAttempt := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		err := func() error {
			s.ready.Store(false)
			sCtx, sCancel := context.WithCancel(s.ctx)
			defer sCancel()

			if globalGetCreds == nil {
				return fmt.Errorf("credentials function not initialized")
			}
			user, pass, addr, err := globalGetCreds(sCtx, link, s.id)
			if err != nil {
				return fmt.Errorf("TURN creds failed: %w", err)
			}

			// Override TURN address if provided
			if turnIp != "" {
				_, origPort, _ := net.SplitHostPort(addr)
				if turnPort != 0 {
					addr = net.JoinHostPort(turnIp, fmt.Sprintf("%d", turnPort))
				} else if origPort != "" {
					addr = net.JoinHostPort(turnIp, origPort)
				} else {
					addr = turnIp
				}
				turnLog("[STREAM %d] Using custom TURN IP: %s", s.id, addr)
			} else if turnPort != 0 {
				origHost, _, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(origHost, fmt.Sprintf("%d", turnPort))
				turnLog("[STREAM %d] Using custom TURN port: %s", s.id, addr)
			}

			turnLog("[STREAM %d] Dialing TURN server %s...", s.id, addr)
			// addr is already resolved during credential fetch via cascading DNS, so use DialContext without Resolver
			dialer := &net.Dialer{
				Timeout: 30 * time.Second,
				Control: protectControl,
			}
			var turnConn net.PacketConn
			if udp {
				c, err := dialer.DialContext(sCtx, "udp", addr)
				if err != nil {
					return fmt.Errorf("TURN UDP dial failed: %w", err)
				}
				defer c.Close()
				turnConn = &connectedUDPConn{c.(*net.UDPConn)}
			} else {
				c, err := dialer.DialContext(sCtx, "tcp", addr)
				if err != nil {
					return fmt.Errorf("TURN TCP dial failed: %w", err)
				}
				defer c.Close()
				turnConn = turn.NewSTUNConn(c)
			}

			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: addr, TURNServerAddr: addr, Username: user, Password: pass,
				Conn: turnConn, LoggerFactory: logging.NewDefaultLoggerFactory(),
			})
			if err != nil {
				return fmt.Errorf("TURN client creation failed: %w", err)
			}
			defer client.Close()
			if err := client.Listen(); err != nil {
				// Check if this is an authentication error (stale credentials)
				if isAuthError(err) {
					handleAuthError(s.id)
				}
				return fmt.Errorf("TURN listen failed: %w", err)
			}

			turnLog("[STREAM %d] Requesting TURN allocation...", s.id)
			relayConn, err := client.Allocate()
			if err != nil {
				// Check if this is an authentication error (stale credentials)
				if isAuthError(err) {
					handleAuthError(s.id)
				}
				return fmt.Errorf("TURN allocation failed: %w", err)
			}
			defer relayConn.Close()

			turnLog("[STREAM %d] Allocated relay address: %s", s.id, relayConn.LocalAddr())

			// Delegate to mode-specific handler
			if s.peerType == "wireguard" {
				return s.runNoDTLS(sCtx, relayConn, peer, okchan)
			}
			return s.runDTLS(sCtx, relayConn, peer, okchan, s.peerType != "proxy_v1")
		}()

		if err != nil && s.ctx.Err() == nil {
			setRuntimeError(err)
			if isForbiddenIPError(err) && s.startup != nil && s.startup.noteForbidden(s.id) {
				setRuntimeModeInfo("TURN stopped due to relay error")
				turnLog("[PROXY] Fatal startup error across all streams: %v", err)
				cancelCurrentTurn()
				return
			}
			if s.startup != nil {
				if reason := startupTerminalReason(err); reason != "" {
					if stop, summary := s.startup.noteTerminalStartupError(s.id, reason); stop {
						setRuntimeModeInfo("TURN stopped due to startup error")
						turnLog("[PROXY] Startup fail-fast (%s): %v", summary, err)
						cancelCurrentTurn()
						return
					}
				}
			}
			reconnectAttempt++
			backoff := reconnectBackoff(err, reconnectAttempt)
			if isAllocationQuotaError(err) {
				turnLog("[STREAM %d] Error: %v. Server quota/backpressure detected, backing off %s before reconnect...", s.id, err, backoff)
			} else {
				turnLog("[STREAM %d] Error: %v. Reconnecting in %s...", s.id, err, backoff)
			}
			time.Sleep(backoff)
		}
	}
}

func reconnectBackoff(err error, attempt int) time.Duration {
	base := time.Second
	limit := 30 * time.Second
	if isAllocationQuotaError(err) {
		if quotaBackoffSec <= 0 {
			quotaBackoffSec = 15
		}
		base = time.Duration(quotaBackoffSec) * time.Second
		limit = 5 * time.Minute
	}
	if attempt < 1 {
		attempt = 1
	}
	delay := base << min(attempt-1, 4)
	if delay > limit {
		delay = limit
	}
	return delay
}

func isAllocationQuotaError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Allocation Quota Reached") ||
		strings.Contains(msg, "error 486") ||
		strings.Contains(msg, "486:")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// runNoDTLS handles packet relay without DTLS obfuscation
func (s *stream) runNoDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, okchan chan<- struct{}) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()
	errCh := make(chan error, 1)
	var errOnce sync.Once
	reportErr := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() {
			errCh <- err
			sCancel()
		})
	}
	turnLog("[STREAM %d] No DTLS mode - direct relay", s.id)
	turnLog("[STREAM %d] Forwarding to WireGuard server: %s", s.id, peer.String())

	wg := sync.WaitGroup{}
	wg.Add(2)

	// WireGuard backend (s.in channel) -> TURN -> WireGuard server (TX)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				_, err := relayConn.WriteTo(b, peer)
				packetPool.Put(b[:cap(b)])

				if err != nil {
					noDtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX error: %v", s.id, err)
					reportErr(fmt.Errorf("NoDTLS TX error: %w", err))
					return
				}
			}
		}
	}()

	// WireGuard server -> TURN -> WireGuard backend (s.out socket) (RX)
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(buf)
			if err != nil {
				noDtlsRxErrorCount.Add(1)
				turnLog("[STREAM %d] RX error: %v", s.id, err)
				reportErr(fmt.Errorf("NoDTLS RX error: %w", err))
				return
			}
			if from.String() == peer.String() {
				addr := s.peer.Load()
				if addr == nil {
					turnLog("[STREAM %d] RX: no peer address yet", s.id)
					continue
				}
				if _, err := s.out.WriteTo(buf[:n], *addr); err != nil {
					noDtlsRxErrorCount.Add(1)
					turnLog("[STREAM %d] RX write error: %v", s.id, err)
					reportErr(fmt.Errorf("NoDTLS RX write error: %w", err))
					return
				}
			}
		}
	}()

	s.ready.Store(true)
	if s.startup != nil {
		s.startup.noteReady()
	}
	select {
	case okchan <- struct{}{}:
	default:
	}

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// runDTLS handles packet relay with DTLS obfuscation
func (s *stream) runDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, okchan chan<- struct{}, sendHandshake bool) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()
	errCh := make(chan error, 1)
	var errOnce sync.Once
	reportErr := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() {
			errCh <- err
			sCancel()
		})
	}
	popReportedErr := func() error {
		select {
		case err := <-errCh:
			return err
		default:
			return nil
		}
	}

	var dtlsConn *dtls.Conn

	c1, c2 := connutil.AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
		Certificates: []tls.Certificate{*s.cert}, InsecureSkipVerify: true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	})
	if err != nil {
		return fmt.Errorf("DTLS client creation failed: %w", err)
	}
	defer dtlsConn.Close()

	wg := sync.WaitGroup{}
	wg.Add(3)

	// Robust cleanup
	context.AfterFunc(sCtx, func() {
		relayConn.Close()
		c1.Close() // Breaks dtlsConn
	})

	// DTLS <-> Relay (via Pipe) - MUST start before handshake
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, _, err := c2.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := relayConn.WriteTo(buf[:n], peer); err != nil {
				relayTxErrorCount.Add(1)
				turnLog("[STREAM %d] Relay TX error: %v", s.id, err)
				reportErr(fmt.Errorf("Relay TX error: %w", err))
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(buf)
			if err != nil {
				relayRxErrorCount.Add(1)
				turnLog("[STREAM %d] Relay RX error: %v", s.id, err)
				reportErr(fmt.Errorf("Relay RX error: %w", err))
				return
			}
			if from.String() == peer.String() {
				if _, err := c2.WriteTo(buf[:n], peer); err != nil {
					relayTxErrorCount.Add(1)
					turnLog("[STREAM %d] Relay RX->Pipe error: %v", s.id, err)
					reportErr(fmt.Errorf("Relay RX->Pipe error: %w", err))
					return
				}
			}
		}
	}()

	// Deadline updater
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sCtx.Done():
				return
			case <-ticker.C:
				deadline := time.Now().Add(30 * time.Second)
				relayConn.SetDeadline(deadline)
				dtlsConn.SetDeadline(deadline)
				c2.SetDeadline(deadline)
			}
		}
	}()

	// Set explicit deadline for handshake
	turnLog("[STREAM %d] Starting DTLS handshake...", s.id)
	dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := dtlsConn.HandshakeContext(sCtx); err != nil {
		turnLog("[STREAM %d] DTLS handshake FAILED: %v", s.id, err)
		if reported := popReportedErr(); reported != nil {
			return reported
		}
		return fmt.Errorf("DTLS handshake timeout: %w", err)
	}

	// Clear deadline after successful handshake
	dtlsConn.SetDeadline(time.Time{})
	turnLog("[STREAM %d] DTLS handshake SUCCESS", s.id)

	if sendHandshake {
		handshakeBuf := make([]byte, 17)
		copy(handshakeBuf[:16], s.sessionID)
		handshakeBuf[16] = byte(s.id)

		if _, err := s.writeDTLS(dtlsConn, handshakeBuf, 5*time.Second); err != nil {
			return fmt.Errorf("session ID handshake failed: %w", err)
		}
	}

	relayIP := relayIPFromAddr(relayConn.LocalAddr())
	updateRuntimeState("", relayIP)
	if s.peerType == "proxy_v2_meta" {
		s.sendMetaFrame(dtlsConn, relayIP, "")
	}

	s.ready.Store(true)
	if s.startup != nil {
		s.startup.noteReady()
	}
	updateActiveStreams(1)
	setRuntimeModeInfo("TURN active")
	go func() {
		for sCtx.Err() == nil {
			clientIP := s.meta.ensureClientPublicIP(sCtx, 30*time.Second)
			if clientIP != "" && sCtx.Err() == nil {
				turnLog("[META] external IP ready=%s", clientIP)
				updateRuntimeState(clientIP, relayIP)
				if s.peerType == "proxy_v2_meta" {
					s.sendMetaFrame(dtlsConn, relayIP, clientIP)
				}
				return
			}
			if sCtx.Err() != nil {
				return
			}
			time.Sleep(publicIPRetryCooldown)
		}
	}()
	defer func() {
		if s.ready.Load() {
			s.ready.Store(false)
			activeStreams := updateActiveStreams(-1)
			if activeStreams > 0 {
				setRuntimeModeInfo("TURN active")
			}
		}
	}()
	select {
	case okchan <- struct{}{}:
	default:
	}

	var lastRx atomic.Int64
	lastRx.Store(time.Now().Unix())

	wg.Add(2)

	// WireGuard -> DTLS (TX)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:

				// Watchdog
				if s.watchdogTimeout > 0 && time.Since(time.Unix(lastRx.Load(), 0)) > time.Duration(s.watchdogTimeout)*time.Second {
					packetPool.Put(b[:cap(b)])
					dtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX watchdog timeout (%ds)", s.id, s.watchdogTimeout)
					reportErr(fmt.Errorf("DTLS TX watchdog timeout (%ds)", s.watchdogTimeout))
					return
				}

				_, err := s.writeDTLS(dtlsConn, b, 0)
				packetPool.Put(b[:cap(b)])

				if err != nil {
					dtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX error: %v", s.id, err)
					reportErr(fmt.Errorf("DTLS TX error: %w", err))
					return
				}
			}
		}
	}()

	// DTLS -> WireGuard (RX)
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, err := dtlsConn.Read(buf)
			if err != nil {
				dtlsRxErrorCount.Add(1)
				turnLog("[STREAM %d] RX error: %v", s.id, err)
				reportErr(fmt.Errorf("DTLS RX error: %w", err))
				return
			}
			lastRx.Store(time.Now().Unix())
			if last := s.peer.Load(); last != nil {
				if _, err := s.out.WriteTo(buf[:n], *last); err != nil {
					dtlsRxErrorCount.Add(1)
					turnLog("[STREAM %d] RX write error: %v", s.id, err)
					reportErr(fmt.Errorf("DTLS RX write error: %w", err))
					return
				}
			}
		}
	}()

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

var currentTurnCancel context.CancelFunc
var turnMutex sync.Mutex

func cancelCurrentTurn() {
	turnMutex.Lock()
	cancel := currentTurnCancel
	turnMutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Global credentials function for mode selection (set by wgTurnProxyStart)
type getCredsFunc func(context.Context, string, int) (string, string, string, error)

var globalGetCreds getCredsFunc

//export wgTurnProxyStart
func wgTurnProxyStart(peerAddrC *C.char, vklinkC *C.char, modeC *C.char, n C.int, udp C.int, listenAddrC *C.char, turnIpC *C.char, turnPortC C.int, peerTypeC *C.char, streamsPerCredC C.int, watchdogTimeoutC C.int, vkCredProfileC *C.char, streamStartDelayMsC C.int, startupTimeoutSecC C.int, quotaBackoffSecC C.int, networkHandleC C.longlong, publicKeyC *C.char, keepaliveSecC C.int) int32 {
	// Force initialization of resolver and HTTP client with current environment
	wgNotifyNetworkChange()
	if networkHandleC != 0 {
		if dnsStr := C.getNetworkDnsServers(C.longlong(networkHandleC)); dnsStr != nil {
			dnsGo := C.GoString(dnsStr)
			servers := strings.Split(dnsGo, ",")
			InitSystemDns(servers)
		}
	}
	resetRuntimeState()

	peerAddr := C.GoString(peerAddrC)
	vklink := C.GoString(vklinkC)
	mode := C.GoString(modeC)
	listenAddr := C.GoString(listenAddrC)
	turnIp := C.GoString(turnIpC)
	peerType := C.GoString(peerTypeC)
	vkCredProfile := C.GoString(vkCredProfileC)
	publicKey := C.GoString(publicKeyC)
	keepaliveSec := int(keepaliveSecC)
	turnPort := int(turnPortC)
	streamsPerCred = int(streamsPerCredC)
	if streamsPerCred <= 0 {
		streamsPerCred = 4
	}
	watchdogTimeout := int(watchdogTimeoutC)
	streamStartDelayMs = int(streamStartDelayMsC)
	if streamStartDelayMs < 0 || streamStartDelayMs > 5000 {
		streamStartDelayMs = 200
	}
	startupTimeoutSec = int(startupTimeoutSecC)
	if startupTimeoutSec < 10 || startupTimeoutSec > 300 {
		startupTimeoutSec = 75
	}
	quotaBackoffSec = int(quotaBackoffSecC)
	if quotaBackoffSec < 1 || quotaBackoffSec > 600 {
		quotaBackoffSec = 15
	}
	setVKCredentialsProfile(vkCredProfile)
	if peerType == "" {
		peerType = "proxy_v2_meta"
	}
	networkHandle := int64(networkHandleC)

	turnLog("[PROXY] Hub starting on %s (streams=%d, mode=%s, peerType=%s, streamsPerCred=%d, watchdogTimeout=%d, vkCredProfile=%s, streamStartDelayMs=%d, startupTimeoutSec=%d, quotaBackoffSec=%d, networkHandle=%d)", listenAddr, int(n), mode, peerType, streamsPerCred, watchdogTimeout, currentVKCredentialsProfile, streamStartDelayMs, startupTimeoutSec, quotaBackoffSec, networkHandle)
	turnMutex.Lock()
	if currentTurnCancel != nil {
		currentTurnCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	currentTurnCancel = cancel
	turnMutex.Unlock()

	// Setup credentials function based on mode
	if mode == "wb" {
		turnLog("[PROXY] Using WB (Wildberries) credential mode")
		globalGetCreds = func(ctx context.Context, link string, streamID int) (string, string, string, error) {
			return wbFetch(ctx, link)
		}
	} else {
		turnLog("[PROXY] Using VK Link credential mode")
		globalGetCreds = func(ctx context.Context, lk string, streamID int) (string, string, string, error) {
			return getVkCreds(ctx, lk, streamID)
		}
	}

	// Resolve peerAddr via cascading DNS (if it's a domain)
	var peer *net.UDPAddr
	host, port, err := net.SplitHostPort(peerAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip == nil {
			// It's a domain name, resolve it
			resolvedIP, err := hostCache.Resolve(context.Background(), host)
			if err != nil {
				turnLog("[DNS] Warning: failed to resolve peer: %v, using original", err)
				peer, err = net.ResolveUDPAddr("udp", peerAddr)
				if err != nil {
					return -1
				}
			} else {
				peerAddr = net.JoinHostPort(resolvedIP, port)
				//turnLog("[DNS] Resolved peer %s -> %s", host, resolvedIP)
				peer, err = net.ResolveUDPAddr("udp", peerAddr)
				if err != nil {
					return -1
				}
			}
		} else {
			peer, err = net.ResolveUDPAddr("udp", peerAddr)
			if err != nil {
				return -1
			}
		}
	} else {
		peer, err = net.ResolveUDPAddr("udp", peerAddr)
		if err != nil {
			return -1
		}
	}

	// Determine link for VK mode (for WB mode, link is just "wb")
	var link string
	if mode == "wb" {
		link = "wb"
	} else {
		parts := strings.Split(vklink, "join/")
		link = parts[len(parts)-1]
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
	}

	lc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return -1
	}
	context.AfterFunc(ctx, func() { lc.Close() })

	// Generate fresh Session ID for every run to avoid server-side conflicts
	sessionID, _ := uuid.New().MarshalBinary()
	turnLog("[PROXY] Session ID generated: %x", sessionID)
	meta := &metaRuntime{
		PublicKey:    strings.TrimSpace(publicKey),
		SessionIDHex: fmt.Sprintf("%x", sessionID),
		KeepaliveSec: keepaliveSec,
	}

	// Generate DTLS certificate once for all streams to save CPU
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		turnLog("[PROXY] Failed to generate DTLS certificate: %v", err)
		return -1
	}

	ok := make(chan struct{}, int(n))
	startup := newStartupTracker(int(n))
	streams := make([]*stream, int(n))
	for i := 0; i < int(n); i++ {
		streams[i] = &stream{
			ctx:             ctx,
			id:              i,
			in:              make(chan []byte, 512),
			out:             lc,
			sessionID:       sessionID,
			cert:            &cert,
			meta:            meta,
			peerType:        peerType,
			watchdogTimeout: watchdogTimeout,
			startup:         startup,
		}
		go streams[i].run(link, peer, udp != 0, ok, turnIp, turnPort)
		time.Sleep(time.Duration(streamStartDelayMs) * time.Millisecond)
	}

	go func() {
		nStreams := int(len(streams))
		var lastUsed int = 0

		for {
			b := packetPool.Get().([]byte)[:iPacketBuffMaxSize]
			nRead, addr, err := lc.ReadFrom(b)
			if err != nil {
				packetPool.Put(b[:cap(b)])
				return
			}

			// Round-Robin selection
			lastUsed = (lastUsed + 1) % nStreams

			var s *stream
			for i := 0; i < nStreams; i++ {
				st := streams[(lastUsed+i)%nStreams]
				if st.ready.Load() {
					s = st
					break
				}
			}

			if s == nil {
				packetPool.Put(b[:cap(b)])
				continue
			}

			returnAddr := addr
			s.peer.Store(&returnAddr)

			select {
			case s.in <- b[:nRead]:
				// Packet queued successfully
			default:
				packetPool.Put(b[:cap(b)])
			}
		}
	}()

	select {
	case <-ok:
		turnLog("[PROXY] First stream is ready, tunnel can start")
		return 0
	case <-ctx.Done():
		turnLog("[PROXY] Startup cancelled before any stream became ready")
		return -1
	case <-time.After(time.Duration(startupTimeoutSec) * time.Second):
		turnLog("[PROXY] TIMEOUT waiting for any stream to be ready")
		cancel()
		return -1
	}
}

//export wgTurnProxyStop
func wgTurnProxyStop() {
	turnMutex.Lock()
	defer turnMutex.Unlock()
	if currentTurnCancel != nil {
		turnLog("[PROXY] Stopping TURN proxy")
		currentTurnCancel()
		currentTurnCancel = nil
		resetRuntimeState()
	}
}

//export wgTurnProxyGetRuntimeStatusJson
func wgTurnProxyGetRuntimeStatusJson() *C.char {
	return C.CString(runtimeStatusJSON())
}

type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
