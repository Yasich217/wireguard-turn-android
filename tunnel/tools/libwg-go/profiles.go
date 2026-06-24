package main

import (
	"encoding/json"
	"math/rand"
	"strings"
	"sync"
)

type Profile struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
}

type SavedProfile struct {
	Profile    Profile
	DeviceJSON string
	BrowserFp  string
}

var savedCaptchaProfile struct {
	sync.RWMutex
	profile *SavedProfile
}

func setSavedCaptchaProfileJSON(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var profile SavedProfile
	if err := json.Unmarshal([]byte(raw), &profile); err != nil {
		return err
	}
	if strings.TrimSpace(profile.Profile.UserAgent) == "" {
		return nil
	}
	savedCaptchaProfile.Lock()
	savedCaptchaProfile.profile = &profile
	savedCaptchaProfile.Unlock()
	return nil
}

func getSavedCaptchaProfile() *SavedProfile {
	savedCaptchaProfile.RLock()
	defer savedCaptchaProfile.RUnlock()
	if savedCaptchaProfile.profile == nil {
		return nil
	}
	copied := *savedCaptchaProfile.profile
	return &copied
}

func profileWithSavedCaptcha(base Profile) Profile {
	saved := getSavedCaptchaProfile()
	if saved == nil {
		return base
	}
	if strings.TrimSpace(saved.Profile.UserAgent) != "" {
		base.UserAgent = strings.TrimSpace(saved.Profile.UserAgent)
	}
	if strings.TrimSpace(saved.Profile.SecChUa) != "" {
		base.SecChUa = strings.TrimSpace(saved.Profile.SecChUa)
	}
	if strings.TrimSpace(saved.Profile.SecChUaMobile) != "" {
		base.SecChUaMobile = strings.TrimSpace(saved.Profile.SecChUaMobile)
	}
	if strings.TrimSpace(saved.Profile.SecChUaPlatform) != "" {
		base.SecChUaPlatform = strings.TrimSpace(saved.Profile.SecChUaPlatform)
	}
	return base
}

// profiles contain paired User-Agent and Client Hints strings to harden bot detection.
var profile = []Profile{
	// Windows Chrome
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// Windows Edge
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Microsoft Edge";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Microsoft Edge";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// macOS Chrome
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},

	// Linux Chrome
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
}

// getRandomProfile returns a paired User-Agent and Client Hints profile.
func getRandomProfile() Profile {
	return profile[rand.Intn(len(profile))]
}
