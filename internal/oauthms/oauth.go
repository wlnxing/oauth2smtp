package oauthms

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oauth2smtp/internal/config"
)

const loginBase = "https://login.microsoftonline.com"

type authRequest struct {
	State         string
	CodeVerifier  string
	CodeChallenge string
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func AuthorizeInteractive(ctx context.Context, oauth config.OAuthConfig, manual bool, in io.Reader, out io.Writer, client *http.Client) (config.Token, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if err := validateOAuthConfig(oauth); err != nil {
		return config.Token{}, err
	}

	req, err := newAuthRequest(oauth.ClientSecret == "")
	if err != nil {
		return config.Token{}, err
	}
	authURL, err := AuthCodeURL(oauth, req)
	if err != nil {
		return config.Token{}, err
	}

	var code string
	if manual {
		fmt.Fprintf(out, "Open this URL in a browser:\n%s\n\nPaste the full redirected URL: ", authURL)
		code, err = readManualCode(in, oauth.RedirectURI, req.State)
	} else {
		fmt.Fprintf(out, "Open this URL in a browser:\n%s\n\nWaiting for OAuth callback...\n", authURL)
		code, err = listenForCode(ctx, oauth.RedirectURI, req.State, out)
		if err != nil {
			return config.Token{}, fmt.Errorf("%w; rerun with --manual if this redirect URI cannot be listened on this machine", err)
		}
	}
	if err != nil {
		return config.Token{}, err
	}
	return exchangeCode(ctx, oauth, code, req.CodeVerifier, client)
}

func AuthCodeURL(oauth config.OAuthConfig, req authRequest) (string, error) {
	if err := validateOAuthConfig(oauth); err != nil {
		return "", err
	}
	values := url.Values{}
	values.Set("client_id", oauth.ClientID)
	values.Set("response_type", "code")
	values.Set("redirect_uri", oauth.RedirectURI)
	values.Set("response_mode", "query")
	values.Set("scope", strings.Join(scopes(oauth), " "))
	values.Set("state", req.State)
	if req.CodeChallenge != "" {
		values.Set("code_challenge", req.CodeChallenge)
		values.Set("code_challenge_method", "S256")
	}
	return fmt.Sprintf("%s/%s/oauth2/v2.0/authorize?%s", loginBase, tenant(oauth), values.Encode()), nil
}

func ParseRedirectCallback(callbackURL, redirectURI, expectedState string) (string, error) {
	callback, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("parse callback URL: %w", err)
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect URI: %w", err)
	}
	if !sameRedirectTarget(callback, redirect) {
		return "", fmt.Errorf("callback URL does not match configured redirect_uri")
	}
	query := callback.Query()
	if got := query.Get("state"); got != expectedState {
		return "", fmt.Errorf("invalid OAuth state")
	}
	if oauthErr := query.Get("error"); oauthErr != "" {
		desc := query.Get("error_description")
		if desc == "" {
			desc = oauthErr
		}
		return "", fmt.Errorf("OAuth error %s: %s", oauthErr, desc)
	}
	code := query.Get("code")
	if code == "" {
		return "", fmt.Errorf("callback URL has no code")
	}
	return code, nil
}

func NeedsRefresh(tok config.Token, now time.Time, skew time.Duration) bool {
	if tok.AccessToken == "" {
		return true
	}
	if tok.Expiry.IsZero() {
		return false
	}
	return !tok.Expiry.After(now.Add(skew))
}

func EnsureAccessToken(ctx context.Context, oauth config.OAuthConfig, acc *config.Account, client *http.Client, force bool) (bool, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if acc == nil {
		return false, errors.New("account is nil")
	}
	if !force && !NeedsRefresh(acc.Token, time.Now(), time.Minute) {
		return false, nil
	}
	if acc.Token.RefreshToken == "" {
		return false, errors.New("account has no refresh token; run account auth first")
	}
	tok, err := refreshToken(ctx, oauth, acc.Token.RefreshToken, client)
	if err != nil {
		return false, err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = acc.Token.RefreshToken
	}
	acc.Token = tok
	return true, nil
}

func newAuthRequest(withPKCE bool) (authRequest, error) {
	state, err := randomURLToken(32)
	if err != nil {
		return authRequest{}, err
	}
	req := authRequest{State: state}
	if withPKCE {
		verifier, err := randomURLToken(64)
		if err != nil {
			return authRequest{}, err
		}
		sum := sha256.Sum256([]byte(verifier))
		req.CodeVerifier = verifier
		req.CodeChallenge = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return req, nil
}

func readManualCode(in io.Reader, redirectURI, state string) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", errors.New("empty callback URL")
	}
	return ParseRedirectCallback(line, redirectURI, state)
}

func listenForCode(ctx context.Context, redirectURI, state string, out io.Writer) (string, error) {
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	if redirect.Scheme != "http" {
		return "", fmt.Errorf("automatic callback only supports http redirect_uri")
	}
	host := redirect.Hostname()
	port := redirect.Port()
	if port == "" {
		port = "80"
	}
	addr := net.JoinHostPort(host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer ln.Close()

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath(redirect), func(w http.ResponseWriter, r *http.Request) {
		cb := *redirect
		cb.RawQuery = r.URL.RawQuery
		code, err := ParseRedirectCallback(cb.String(), redirectURI, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			fmt.Fprintln(w, "OAuth authorization complete. You can close this browser tab.")
		}
		select {
		case resultCh <- result{code: code, err: err}:
		default:
		}
	})

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(ln)
	}()
	defer server.Shutdown(context.Background())

	select {
	case res := <-resultCh:
		return res.code, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Minute):
		fmt.Fprintln(out, "OAuth callback timed out")
		return "", context.DeadlineExceeded
	}
}

func exchangeCode(ctx context.Context, oauth config.OAuthConfig, code, verifier string, client *http.Client) (config.Token, error) {
	form := url.Values{}
	form.Set("client_id", oauth.ClientID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oauth.RedirectURI)
	form.Set("scope", strings.Join(scopes(oauth), " "))
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if oauth.ClientSecret != "" {
		form.Set("client_secret", oauth.ClientSecret)
	}
	return postTokenForm(ctx, oauth, form, client)
}

func refreshToken(ctx context.Context, oauth config.OAuthConfig, refresh string, client *http.Client) (config.Token, error) {
	if err := validateOAuthConfig(oauth); err != nil {
		return config.Token{}, err
	}
	form := url.Values{}
	form.Set("client_id", oauth.ClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	form.Set("scope", strings.Join(scopes(oauth), " "))
	if oauth.ClientSecret != "" {
		form.Set("client_secret", oauth.ClientSecret)
	}
	return postTokenForm(ctx, oauth, form, client)
}

func postTokenForm(ctx context.Context, oauth config.OAuthConfig, form url.Values, client *http.Client) (config.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/%s/oauth2/v2.0/token", loginBase, tenant(oauth)), strings.NewReader(form.Encode()))
	if err != nil {
		return config.Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return config.Token{}, err
	}
	defer resp.Body.Close()
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return config.Token{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || tr.Error != "" {
		if tr.ErrorDescription == "" {
			tr.ErrorDescription = resp.Status
		}
		return config.Token{}, fmt.Errorf("token endpoint error %s: %s", tr.Error, tr.ErrorDescription)
	}
	if tr.AccessToken == "" {
		return config.Token{}, errors.New("token endpoint response has no access_token")
	}
	if tr.TokenType == "" {
		tr.TokenType = "Bearer"
	}
	return config.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Expiry:       time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		Scope:        tr.Scope,
	}, nil
}

func validateOAuthConfig(oauth config.OAuthConfig) error {
	if strings.TrimSpace(oauth.ClientID) == "" {
		return errors.New("oauth.client_id is required")
	}
	if strings.TrimSpace(oauth.RedirectURI) == "" {
		return errors.New("oauth.redirect_uri is required")
	}
	if _, err := url.ParseRequestURI(oauth.RedirectURI); err != nil {
		return fmt.Errorf("oauth.redirect_uri is invalid: %w", err)
	}
	return nil
}

func sameRedirectTarget(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) &&
		callbackPath(a) == callbackPath(b)
}

func callbackPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func scopes(oauth config.OAuthConfig) []string {
	if len(oauth.Scopes) > 0 {
		return oauth.Scopes
	}
	return []string{"offline_access", "https://graph.microsoft.com/Mail.Send"}
}

func tenant(oauth config.OAuthConfig) string {
	t := strings.TrimSpace(oauth.TenantID)
	if t == "" {
		return "common"
	}
	return url.PathEscape(t)
}

func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
