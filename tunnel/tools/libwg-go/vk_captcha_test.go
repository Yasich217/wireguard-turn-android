package main

import (
	"testing"
	"time"
)

func TestParseVkCaptchaErrorRedirectOnly(t *testing.T) {
	errData := map[string]interface{}{
		"error_code":         float64(14),
		"error_msg":          "Captcha need",
		"is_enabled_captcha": true,
		"redirect_uri":       "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=test-token&variant=popup&blank=1",
	}

	captchaErr := ParseVkCaptchaError(errData)
	if captchaErr == nil {
		t.Fatal("expected captcha error")
	}
	if !captchaErr.IsCaptchaError() {
		t.Fatalf("expected IsCaptchaError=true, got %#v", captchaErr)
	}
	if captchaErr.SessionToken != "test-token" {
		t.Fatalf("unexpected session token %q", captchaErr.SessionToken)
	}
	if captchaErr.CaptchaSid != "" {
		t.Fatalf("unexpected captcha sid %q", captchaErr.CaptchaSid)
	}
	if captchaErr.CaptchaImg != "" {
		t.Fatalf("unexpected captcha img %q", captchaErr.CaptchaImg)
	}
}

func TestParseVkCaptchaErrorLegacyFields(t *testing.T) {
	errData := map[string]interface{}{
		"error_code":      float64(14),
		"error_msg":       "Captcha needed",
		"redirect_uri":    "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=test-token&variant=popup&blank=1",
		"captcha_sid":     float64(123456),
		"captcha_img":     "https://vk.ru/captcha.php?sid=123456",
		"captcha_ts":      float64(1775206851),
		"captcha_attempt": float64(1),
	}

	captchaErr := ParseVkCaptchaError(errData)
	if captchaErr == nil {
		t.Fatal("expected captcha error")
	}
	if captchaErr.CaptchaSid != "123456" {
		t.Fatalf("unexpected captcha sid %q", captchaErr.CaptchaSid)
	}
	if captchaErr.CaptchaTs != "1775206851" {
		t.Fatalf("unexpected captcha ts %q", captchaErr.CaptchaTs)
	}
	if captchaErr.CaptchaAttempt != "1" {
		t.Fatalf("unexpected captcha attempt %q", captchaErr.CaptchaAttempt)
	}
}

func TestCaptchaWaitLockoutIsScopedToCredentialCache(t *testing.T) {
	oldStreamsPerCred := streamsPerCred
	oldBackoff := captchaBackoffSec
	t.Cleanup(func() {
		streamsPerCred = oldStreamsPerCred
		captchaBackoffSec = oldBackoff
		clearCaptchaLockouts()
	})

	streamsPerCred = 4
	captchaBackoffSec = 120
	clearCaptchaLockouts()
	noteCaptchaWaitLockout(0, "web_app", "test-link", "test")

	if remaining := captchaLockoutRemaining(0, "web_app", "test-link"); remaining <= 0 || remaining > 2*time.Minute {
		t.Fatalf("expected cache 0 lockout near two minutes, got %s", remaining)
	}
	if remaining := captchaLockoutRemaining(4, "web_app", "test-link"); remaining != 0 {
		t.Fatalf("cache 1 must remain usable after cache 0 rejection, got lockout %s", remaining)
	}
}
