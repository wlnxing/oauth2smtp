package smtpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oauth2smtp/internal/config"
)

func TestHeaderFrom(t *testing.T) {
	data := []byte("From: User <user@example.com>\r\nTo: dest@example.com\r\nSubject: Hi\r\n\r\nBody")
	if got := HeaderFrom(data); got != "user@example.com" {
		t.Fatalf("from = %q", got)
	}
}

func TestEHLOAdvertisesSTARTTLSWhenCertConfigured(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	cfg := config.Default()
	cfg.Server.TLSCertFile = certFile
	cfg.Server.TLSKeyFile = keyFile

	caps := ehloCapabilities(t, cfg)
	if !strings.Contains(caps, "STARTTLS") {
		t.Fatalf("EHLO capabilities did not advertise STARTTLS:\n%s", caps)
	}
}

func TestEHLONoSTARTTLSWithoutCert(t *testing.T) {
	cfg := config.Default()

	caps := ehloCapabilities(t, cfg)
	if strings.Contains(caps, "STARTTLS") {
		t.Fatalf("EHLO capabilities unexpectedly advertised STARTTLS:\n%s", caps)
	}
}

func TestEHLOAdvertisesPlainAndLoginAuth(t *testing.T) {
	cfg := config.Default()

	caps := ehloCapabilities(t, cfg)
	if !strings.Contains(caps, "AUTH PLAIN LOGIN") {
		t.Fatalf("EHLO capabilities did not advertise AUTH PLAIN LOGIN:\n%s", caps)
	}
}

func TestSMTPSRequiresCertificate(t *testing.T) {
	cfg := config.Default()
	cfg.Server.SMTPSListen = "127.0.0.1:2465"

	relay := New("", cfg, log.New(io.Discard, "", 0), nil)
	_, err := relay.smtpsServer()
	if err == nil {
		t.Fatal("expected missing certificate error")
	}
	if !strings.Contains(err.Error(), "smtps_listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSMTPSImplicitTLS(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	cfg := config.Default()
	cfg.Server.TLSCertFile = certFile
	cfg.Server.TLSKeyFile = keyFile
	cfg.Server.SMTPSListen = "127.0.0.1:0"

	relay := New("", cfg, log.New(io.Discard, "", 0), nil)
	srv, err := relay.smtpsServer()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", srv.Addr, srv.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)
	defer tp.Close()
	if _, msg, err := tp.ReadResponse(220); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(msg, cfg.Server.Hostname) {
		t.Fatalf("unexpected greeting: %s", msg)
	}
	_ = tp.PrintfLine("QUIT")
}

func TestSMTPForwardingAndAuth(t *testing.T) {
	mime := "From: User <user@example.com>\r\nTo: dest@example.com\r\nSubject: Hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/html\r\n\r\n<b>Body</b>\r\n--abc\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"note.txt\"\r\n\r\nattachment body\r\n--abc--\r\n"
	var graphPath string
	var graphMIME []byte
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		graphPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		graphMIME, _ = base64.StdEncoding.DecodeString(string(body))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer graphSrv.Close()

	cfgPath, cfg := testConfig(t, graphSrv.URL)
	relay := New(cfgPath, cfg, log.New(io.Discard, "", 0), graphSrv.Client())
	srv, err := relay.smtpServer()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	defer srv.Shutdown(context.Background())

	addr := ln.Addr().String()
	auth := smtp.PlainAuth("", "legacy", "secret", "127.0.0.1")
	if err := smtp.SendMail(addr, auth, "user@example.com", []string{"dest@example.com"}, []byte(mime)); err != nil {
		t.Fatal(err)
	}
	if graphPath != "/me/sendMail" {
		t.Fatalf("graph path = %q", graphPath)
	}
	if string(graphMIME) != mime {
		t.Fatalf("MIME changed:\n%s", graphMIME)
	}

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed") {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Millisecond):
	}
}

func TestSMTPForwardingWithLoginAuth(t *testing.T) {
	mime := "From: User <user@example.com>\r\nTo: dest@example.com\r\nSubject: Hi\r\n\r\nBody\r\n"
	var graphCalled bool
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		graphCalled = true
		if r.URL.Path != "/me/sendMail" {
			t.Fatalf("graph path = %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		graphMIME, _ := base64.StdEncoding.DecodeString(string(body))
		if string(graphMIME) != mime {
			t.Fatalf("MIME changed:\n%s", graphMIME)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer graphSrv.Close()

	cfgPath, cfg := testConfig(t, graphSrv.URL)
	relay := New(cfgPath, cfg, log.New(io.Discard, "", 0), graphSrv.Client())
	srv, err := relay.smtpServer()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	auth := loginAuth{username: "legacy", password: "secret"}
	if err := smtp.SendMail(ln.Addr().String(), auth, "user@example.com", []string{"dest@example.com"}, []byte(mime)); err != nil {
		t.Fatal(err)
	}
	if !graphCalled {
		t.Fatal("Graph was not called")
	}
}

func TestSMTPRejectsBadPassword(t *testing.T) {
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Graph should not be called")
	}))
	defer graphSrv.Close()

	cfgPath, cfg := testConfig(t, graphSrv.URL)
	relay := New(cfgPath, cfg, log.New(io.Discard, "", 0), graphSrv.Client())
	srv, err := relay.smtpServer()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	auth := smtp.PlainAuth("", "legacy", "wrong", "127.0.0.1")
	err = smtp.SendMail(ln.Addr().String(), auth, "user@example.com", []string{"dest@example.com"}, []byte("From: user@example.com\r\n\r\nBody"))
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestSMTPRejectsUnauthorizedFrom(t *testing.T) {
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Graph should not be called")
	}))
	defer graphSrv.Close()

	cfgPath, cfg := testConfig(t, graphSrv.URL)
	relay := New(cfgPath, cfg, log.New(io.Discard, "", 0), graphSrv.Client())
	srv, err := relay.smtpServer()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	auth := smtp.PlainAuth("", "legacy", "secret", "127.0.0.1")
	err = smtp.SendMail(ln.Addr().String(), auth, "other@example.com", []string{"dest@example.com"}, []byte("From: other@example.com\r\n\r\nBody"))
	if err == nil {
		t.Fatal("expected sender rejection")
	}
}

func TestBackgroundRefreshUpdatesAccessAndRefreshToken(t *testing.T) {
	var tokenRequests int
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/common/oauth2/v2.0/token" {
			t.Fatalf("unexpected token path %s", r.URL.Path)
		}
		tokenRequests++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.Form.Get("refresh_token"); got != "old-refresh" {
			t.Fatalf("refresh_token = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600,"scope":"offline_access https://graph.microsoft.com/Mail.Send"}`)
	}))
	defer tokenSrv.Close()

	cfg := config.Default()
	cfg.OAuth.ClientID = "client"
	cfg.OAuth.RedirectURI = "https://auth.example.com/callback"
	cfg.OAuth.TokenURL = tokenSrv.URL + "/common/oauth2/v2.0/token"
	cfg.Accounts = []config.Account{
		{
			Name:         "work",
			SMTPUsername: "legacy",
			SMTPPassword: "secret",
			Email:        "user@example.com",
			Token: config.Token{
				AccessToken:  "old-access",
				RefreshToken: "old-refresh",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(5 * time.Minute),
			},
		},
		{
			Name:         "not-authorized",
			SMTPUsername: "skip",
			SMTPPassword: "secret",
			Email:        "skip@example.com",
			Token: config.Token{
				AccessToken: "skip-access",
				Expiry:      time.Now().Add(5 * time.Minute),
			},
		},
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	relay := New(path, cfg, log.New(io.Discard, "", 0), tokenSrv.Client())
	refreshed, skipped, failed := relay.refreshExpiringTokensOnce(context.Background(), 10*time.Minute)
	if refreshed != 1 || skipped != 1 || failed != 0 {
		t.Fatalf("refreshed=%d skipped=%d failed=%d", refreshed, skipped, failed)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d", tokenRequests)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	acc := loaded.FindAccountByName("work")
	if acc == nil {
		t.Fatal("work account missing")
	}
	if acc.Token.AccessToken != "new-access" {
		t.Fatalf("access token = %q", acc.Token.AccessToken)
	}
	if acc.Token.RefreshToken != "new-refresh" {
		t.Fatalf("refresh token = %q", acc.Token.RefreshToken)
	}
}

func testConfig(t *testing.T, graphURL string) (string, *config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Graph.BaseURL = graphURL
	cfg.OAuth.ClientID = "client"
	cfg.OAuth.RedirectURI = "https://auth.example.com/callback"
	cfg.Accounts = []config.Account{{
		Name:         "work",
		SMTPUsername: "legacy",
		SMTPPassword: "secret",
		Email:        "user@example.com",
		AllowedFrom:  []string{"user@example.com"},
		Token: config.Token{
			AccessToken:  "access",
			RefreshToken: "refresh",
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(time.Hour),
		},
	}}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

type loginAuth struct {
	username string
	password string
}

func (a loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch string(fromServer) {
	case "Username:":
		return []byte(a.username), nil
	case "Password:":
		return []byte(a.password), nil
	default:
		return nil, errors.New("unexpected LOGIN challenge")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("secret", "secret") {
		t.Fatal("expected equal")
	}
	if constantTimeEqual("secret", "other") {
		t.Fatal("expected not equal")
	}
	if HeaderFrom(bytes.NewBufferString("not a message").Bytes()) != "" {
		t.Fatal("unexpected from")
	}
}

func ehloCapabilities(t *testing.T, cfg *config.Config) string {
	t.Helper()

	relay := New("", cfg, log.New(io.Discard, "", 0), nil)
	srv, err := relay.smtpServer()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)
	defer tp.Close()
	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	if err := tp.PrintfLine("EHLO test.local"); err != nil {
		t.Fatal(err)
	}
	_, caps, err := tp.ReadResponse(250)
	if err != nil {
		t.Fatal(err)
	}
	_ = tp.PrintfLine("QUIT")
	return caps
}

func writeTestCert(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
