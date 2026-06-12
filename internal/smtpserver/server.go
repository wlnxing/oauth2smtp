package smtpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"oauth2smtp/internal/config"
	"oauth2smtp/internal/graph"
	"oauth2smtp/internal/oauthms"
)

const (
	backgroundRefreshInterval = 30 * time.Minute
	backgroundRefreshSkew     = 10 * time.Minute
	sendRefreshSkew           = time.Minute
)

type Relay struct {
	configPath string
	cfg        *config.Config
	logger     *log.Logger
	httpClient *http.Client
	mu         sync.Mutex
}

type session struct {
	relay       *Relay
	auth        bool
	accountName string
	mailFrom    string
	rcpts       []string
}

type sendSnapshot struct {
	account      config.Account
	graphBaseURL string
}

func New(configPath string, cfg *config.Config, logger *log.Logger, httpClient *http.Client) *Relay {
	if cfg == nil {
		cfg = config.Default()
	}
	cfg.ApplyDefaults()
	if logger == nil {
		logger = log.Default()
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Relay{
		configPath: configPath,
		cfg:        cfg,
		logger:     logger,
		httpClient: httpClient,
	}
}

func (r *Relay) ListenAndServe(ctx context.Context) error {
	s, err := r.smtpServer()
	if err != nil {
		return err
	}
	smtps, err := r.smtpsServer()
	if err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go r.runTokenRefreshLoop(ctx, backgroundRefreshInterval, backgroundRefreshSkew)
	go func() {
		r.logger.Printf("smtp listening on %s", s.Addr)
		errCh <- s.ListenAndServe()
	}()
	if smtps != nil {
		go func() {
			r.logger.Printf("smtps listening on %s", smtps.Addr)
			errCh <- smtps.ListenAndServeTLS()
		}()
	}

	select {
	case <-ctx.Done():
		return shutdownServers(10*time.Second, s, smtps)
	case err := <-errCh:
		if errors.Is(err, smtp.ErrServerClosed) {
			return nil
		}
		_ = shutdownServers(10*time.Second, s, smtps)
		return err
	}
}

func (r *Relay) smtpServer() (*smtp.Server, error) {
	return r.newSMTPServer(r.cfg.Server.Listen)
}

func (r *Relay) smtpsServer() (*smtp.Server, error) {
	if r.cfg.Server.SMTPSListen == "" {
		return nil, nil
	}
	if r.cfg.Server.TLSCertFile == "" || r.cfg.Server.TLSKeyFile == "" {
		return nil, errors.New("server.smtps_listen requires both server.tls_cert_file and server.tls_key_file")
	}
	return r.newSMTPServer(r.cfg.Server.SMTPSListen)
}

func (r *Relay) newSMTPServer(addr string) (*smtp.Server, error) {
	r.cfg.ApplyDefaults()
	s := smtp.NewServer(r)
	s.Addr = addr
	s.Domain = r.cfg.Server.Hostname
	s.MaxMessageBytes = r.cfg.Server.MessageSizeLimit
	s.MaxRecipients = 200
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute
	s.AllowInsecureAuth = true
	s.ErrorLog = r.logger
	s.EnableSMTPUTF8 = true

	if r.cfg.Server.TLSCertFile != "" || r.cfg.Server.TLSKeyFile != "" {
		if r.cfg.Server.TLSCertFile == "" || r.cfg.Server.TLSKeyFile == "" {
			return nil, errors.New("both server.tls_cert_file and server.tls_key_file are required for TLS")
		}
		cert, err := tls.LoadX509KeyPair(r.cfg.Server.TLSCertFile, r.cfg.Server.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return s, nil
}

func shutdownServers(timeout time.Duration, servers ...*smtp.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var errs []error
	for _, server := range servers {
		if server == nil {
			continue
		}
		if err := server.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *Relay) runTokenRefreshLoop(ctx context.Context, interval, skew time.Duration) {
	if interval <= 0 {
		return
	}
	r.refreshExpiringTokens(ctx, skew)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refreshExpiringTokens(ctx, skew)
		}
	}
}

func (r *Relay) refreshExpiringTokens(ctx context.Context, skew time.Duration) {
	refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	refreshed, skipped, failed := r.refreshExpiringTokensOnce(refreshCtx, skew)
	if refreshed > 0 || failed > 0 {
		r.logger.Printf("oauth background refresh complete refreshed=%d skipped=%d failed=%d", refreshed, skipped, failed)
	}
}

func (r *Relay) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{relay: r}, nil
}

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return s.authenticateSMTP(username, password)
		}), nil
	case sasl.Login:
		return newLoginServer(func(username, password string) error {
			return s.authenticateSMTP(username, password)
		}), nil
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

func (s *session) authenticateSMTP(username, password string) error {
	acc, err := s.relay.authenticate(username, password)
	if err != nil {
		return smtp.ErrAuthFailed
	}
	s.auth = true
	s.accountName = acc.Name
	s.relay.logger.Printf("smtp auth ok user=%s account=%s", username, acc.Name)
	return nil
}

type loginServer struct {
	authenticate func(username, password string) error
	username     string
	step         int
	done         bool
}

func newLoginServer(authenticate func(username, password string) error) sasl.Server {
	return &loginServer{authenticate: authenticate}
}

func (s *loginServer) Next(response []byte) ([]byte, bool, error) {
	if s.done {
		return nil, false, sasl.ErrUnexpectedClientResponse
	}

	switch s.step {
	case 0:
		if response == nil {
			return []byte("Username:"), false, nil
		}
		s.username = string(response)
		s.step = 1
		return []byte("Password:"), false, nil
	case 1:
		if response == nil {
			return nil, false, sasl.ErrUnexpectedClientResponse
		}
		s.done = true
		return nil, true, s.authenticate(s.username, string(response))
	default:
		return nil, false, sasl.ErrUnexpectedClientResponse
	}
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	if !s.auth {
		return smtp.ErrAuthRequired
	}
	if config.NormalizeAddress(from) == "" {
		return smtpError(553, "invalid MAIL FROM address")
	}
	s.mailFrom = from
	s.rcpts = nil
	return nil
}

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if !s.auth {
		return smtp.ErrAuthRequired
	}
	if config.NormalizeAddress(to) == "" {
		return smtpError(553, "invalid RCPT TO address")
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	if !s.auth {
		return smtp.ErrAuthRequired
	}
	if s.mailFrom == "" || len(s.rcpts) == 0 {
		return smtpError(503, "MAIL FROM and RCPT TO are required before DATA")
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	headerFrom := HeaderFrom(data)
	sender := headerFrom
	if sender == "" {
		sender = s.mailFrom
	}

	snapshot, err := s.relay.snapshotForSend(s.accountName)
	if err != nil {
		return smtpError(451, err.Error())
	}
	acc := snapshot.account
	if !acc.IsFromAllowed(sender) {
		s.relay.logger.Printf("smtp sender rejected account=%s sender=%s", acc.Name, sender)
		return smtpError(550, "sender is not allowed for this SMTP account")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := s.relay.ensureAccessToken(ctx, acc.Name); err != nil {
		s.relay.logger.Printf("oauth token refresh failed account=%s error=%v", acc.Name, err)
		return smtpError(451, "temporary OAuth token refresh failure")
	}

	snapshot, err = s.relay.snapshotForSend(s.accountName)
	if err != nil {
		return smtpError(451, err.Error())
	}
	acc = snapshot.account
	endpoint := graph.EndpointForFrom(acc, sender)
	g := graph.New(snapshot.graphBaseURL, s.relay.httpClient)
	if err := g.SendMIME(ctx, acc.Token.AccessToken, endpoint, data); err != nil {
		s.relay.logger.Printf("graph send failed account=%s endpoint=%s error=%v", acc.Name, endpoint, err)
		return graphToSMTPError(err)
	}

	s.relay.logger.Printf("message sent account=%s sender=%s rcpts=%d endpoint=%s bytes=%d", acc.Name, config.NormalizeAddress(sender), len(s.rcpts), endpoint, len(data))
	return nil
}

func (s *session) Reset() {
	s.mailFrom = ""
	s.rcpts = nil
}

func (s *session) Logout() error {
	return nil
}

func (r *Relay) authenticate(username, password string) (config.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reloadLocked(); err != nil {
		r.logger.Printf("config reload failed during auth: %v", err)
		return config.Account{}, errors.New("configuration reload failed")
	}
	acc := r.cfg.FindAccountBySMTPUsername(username)
	if acc == nil {
		r.logger.Printf("smtp auth failed user=%s reason=unknown_user", username)
		return config.Account{}, errors.New("invalid username or password")
	}
	if !constantTimeEqual(acc.SMTPPassword, password) {
		r.logger.Printf("smtp auth failed user=%s reason=bad_password", username)
		return config.Account{}, errors.New("invalid username or password")
	}
	return *acc, nil
}

func (r *Relay) snapshotForSend(name string) (sendSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reloadLocked(); err != nil {
		return sendSnapshot{}, err
	}
	acc := r.cfg.FindAccountByName(name)
	if acc == nil {
		return sendSnapshot{}, fmt.Errorf("account %q no longer exists", name)
	}
	return sendSnapshot{account: *acc, graphBaseURL: r.cfg.Graph.BaseURL}, nil
}

func (r *Relay) ensureAccessToken(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reloadLocked(); err != nil {
		return err
	}
	acc := r.cfg.FindAccountByName(name)
	if acc == nil {
		return fmt.Errorf("account %q no longer exists", name)
	}
	changed, err := oauthms.EnsureAccessTokenWithSkew(ctx, r.cfg.OAuth, acc, r.httpClient, false, sendRefreshSkew)
	if err != nil {
		return err
	}
	if changed {
		if err := config.Save(r.configPath, r.cfg); err != nil {
			return err
		}
		r.logger.Printf("oauth token refreshed account=%s", name)
	}
	return nil
}

func (r *Relay) refreshExpiringTokensOnce(ctx context.Context, skew time.Duration) (refreshed, skipped, failed int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reloadLocked(); err != nil {
		r.logger.Printf("oauth background refresh skipped: config reload failed: %v", err)
		return 0, 0, 1
	}

	changed := false
	for i := range r.cfg.Accounts {
		acc := &r.cfg.Accounts[i]
		if acc.Token.RefreshToken == "" {
			skipped++
			continue
		}
		tokenChanged, err := oauthms.EnsureAccessTokenWithSkew(ctx, r.cfg.OAuth, acc, r.httpClient, false, skew)
		if err != nil {
			failed++
			r.logger.Printf("oauth background refresh failed account=%s error=%v", acc.Name, err)
			continue
		}
		if tokenChanged {
			refreshed++
			changed = true
			r.logger.Printf("oauth token refreshed account=%s", acc.Name)
		} else {
			skipped++
		}
	}

	if changed {
		if err := config.Save(r.configPath, r.cfg); err != nil {
			failed++
			r.logger.Printf("oauth background refresh save failed: %v", err)
		}
	}
	return refreshed, skipped, failed
}

func (r *Relay) reloadLocked() error {
	if r.configPath == "" {
		return nil
	}
	cfg, err := config.Load(r.configPath)
	if err != nil {
		return err
	}
	r.cfg = cfg
	return nil
}

func HeaderFrom(data []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	raw := msg.Header.Get("From")
	if raw == "" {
		return ""
	}
	addrs, err := mail.ParseAddressList(raw)
	if err != nil || len(addrs) == 0 {
		return raw
	}
	return addrs[0].Address
}

func smtpError(code int, msg string) *smtp.SMTPError {
	return &smtp.SMTPError{Code: code, EnhancedCode: smtp.EnhancedCodeNotSet, Message: msg}
}

func graphToSMTPError(err error) error {
	var graphErr *graph.Error
	if errors.As(err, &graphErr) {
		if graphErr.StatusCode == http.StatusTooManyRequests || graphErr.StatusCode >= 500 {
			return smtpError(451, "temporary Graph send failure")
		}
		return smtpError(554, "Graph rejected the message")
	}
	return smtpError(451, "temporary Graph send failure")
}

func constantTimeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
