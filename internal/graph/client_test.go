package graph

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"oauth2smtp/internal/config"
)

func TestEndpointForFrom(t *testing.T) {
	acc := config.Account{
		AliasRoutes: []config.AliasRoute{
			{From: "shared@example.com", GraphUser: "shared-box@example.com"},
		},
	}
	if got := EndpointForFrom(acc, "user@example.com"); got != "/me/sendMail" {
		t.Fatalf("default endpoint = %q", got)
	}
	if got := EndpointForFrom(acc, "Shared <shared@example.com>"); got != "/users/shared-box@example.com/sendMail" {
		t.Fatalf("alias endpoint = %q", got)
	}
}

func TestSendMIMEPostsBase64MIME(t *testing.T) {
	mime := []byte("From: user@example.com\r\nTo: dest@example.com\r\nSubject: Hi\r\n\r\nBody")
	var gotPath, gotAuth, gotContentType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := New(srv.URL, srv.Client())
	if err := client.SendMIME(context.Background(), "token", "/me/sendMail", mime); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/me/sendMail" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer token" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotContentType != "text/plain" {
		t.Fatalf("content-type = %q", gotContentType)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(gotBody))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(mime) {
		t.Fatalf("decoded body mismatch")
	}
}
