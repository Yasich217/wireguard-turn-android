package main

import "testing"

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
