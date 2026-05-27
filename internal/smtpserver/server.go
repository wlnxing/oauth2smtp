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

	errCh := make(chan error, 1)
	go func() {
		r.logger.Printf("smtp listening on %s", s.Addr)
		errCh <- s.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, smtp.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (r *Relay) smtpServer() (*smtp.Server, error) {
	r.cfg.ApplyDefaults()
	s := smtp.NewServer(r)
	s.Addr = r.cfg.Server.Listen
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

func (r *Relay) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{relay: r}, nil
}

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		acc, err := s.relay.authenticate(username, password)
		if err != nil {
			return smtp.ErrAuthFailed
		}
		s.auth = true
		s.accountName = acc.Name
		s.relay.logger.Printf("smtp auth ok user=%s account=%s", username, acc.Name)
		return nil
	}), nil
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
	changed, err := oauthms.EnsureAccessToken(ctx, r.cfg.OAuth, acc, r.httpClient, false)
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
