package oauthms

import (
	"strings"
	"testing"
	"time"

	"oauth2smtp/internal/config"
)

func TestParseRedirectCallbackAllowsAnyMatchingHost(t *testing.T) {
	redirect := "https://login.example.net/oauth/callback"
	callback := "https://login.example.net/oauth/callback?code=abc123&state=state-1"
	code, err := ParseRedirectCallback(callback, redirect, "state-1")
	if err != nil {
		t.Fatal(err)
	}
	if code != "abc123" {
		t.Fatalf("code = %q", code)
	}
}

func TestParseRedirectCallbackRejectsDifferentRedirectTarget(t *testing.T) {
	_, err := ParseRedirectCallback(
		"https://other.example.net/oauth/callback?code=abc123&state=state-1",
		"https://login.example.net/oauth/callback",
		"state-1",
	)
	if err == nil || !strings.Contains(err.Error(), "redirect_uri") {
		t.Fatalf("expected redirect_uri error, got %v", err)
	}
}

func TestParseRedirectCallbackRejectsBadState(t *testing.T) {
	_, err := ParseRedirectCallback(
		"https://login.example.net/oauth/callback?code=abc123&state=wrong",
		"https://login.example.net/oauth/callback",
		"state-1",
	)
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("expected state error, got %v", err)
	}
}

func TestParseRedirectCallbackTreatsEmptyPathAsSlash(t *testing.T) {
	code, err := ParseRedirectCallback(
		"https://login.example.net/?code=abc123&state=state-1",
		"https://login.example.net",
		"state-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if code != "abc123" {
		t.Fatalf("code = %q", code)
	}
}

func TestNeedsRefresh(t *testing.T) {
	now := time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)
	if !NeedsRefresh(config.Token{}, now, time.Minute) {
		t.Fatal("empty token should refresh")
	}
	if !NeedsRefresh(config.Token{AccessToken: "a", Expiry: now.Add(30 * time.Second)}, now, time.Minute) {
		t.Fatal("token inside skew should refresh")
	}
	if NeedsRefresh(config.Token{AccessToken: "a", Expiry: now.Add(2 * time.Minute)}, now, time.Minute) {
		t.Fatal("fresh token should not refresh")
	}
}
