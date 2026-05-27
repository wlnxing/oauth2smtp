package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := Default()
	cfg.OAuth.ClientID = "client-id"
	cfg.OAuth.RedirectURI = "https://auth.example.com/callback"
	cfg.Accounts = []Account{{
		Name:         "work",
		SMTPUsername: "legacy",
		SMTPPassword: "secret",
		Email:        "user@example.com",
		AllowedFrom:  []string{"alias@example.com"},
		Token: Token{
			AccessToken:  "access",
			RefreshToken: "refresh",
			TokenType:    "Bearer",
			Expiry:       time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC),
		},
	}}

	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %v, want 0600", got)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Server.Listen != DefaultListen {
		t.Fatalf("listen = %q, want %q", loaded.Server.Listen, DefaultListen)
	}
	acc := loaded.FindAccountByName("WORK")
	if acc == nil {
		t.Fatal("account not found")
	}
	if acc.Token.RefreshToken != "refresh" {
		t.Fatalf("refresh token = %q", acc.Token.RefreshToken)
	}
}

func TestFromAllowedAndAliasRoute(t *testing.T) {
	acc := Account{
		Email:       "user@example.com",
		AllowedFrom: []string{"Alias <alias@example.com>"},
		AliasRoutes: []AliasRoute{
			{From: "shared@example.com", GraphUser: "shared-box@example.com"},
		},
	}
	for _, from := range []string{"user@example.com", "alias@example.com", "Shared <shared@example.com>"} {
		if !acc.IsFromAllowed(from) {
			t.Fatalf("expected %q to be allowed", from)
		}
	}
	if acc.IsFromAllowed("other@example.com") {
		t.Fatal("unexpected allowed sender")
	}
	graphUser, ok := acc.RouteForFrom("Shared <shared@example.com>")
	if !ok || graphUser != "shared-box@example.com" {
		t.Fatalf("route = %q, %v", graphUser, ok)
	}
}
