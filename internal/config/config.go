package config

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListen   = "127.0.0.1:2525"
	DefaultHostname = "oauth2smtp.local"
	DefaultGraphURL = "https://graph.microsoft.com/v1.0"
)

type Config struct {
	Server   ServerConfig `yaml:"server"`
	OAuth    OAuthConfig  `yaml:"oauth"`
	Graph    GraphConfig  `yaml:"graph"`
	Accounts []Account    `yaml:"accounts"`
}

type ServerConfig struct {
	Listen           string `yaml:"listen"`
	Hostname         string `yaml:"hostname"`
	TLSCertFile      string `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile       string `yaml:"tls_key_file,omitempty"`
	MessageSizeLimit int64  `yaml:"message_size_limit,omitempty"`
}

type OAuthConfig struct {
	TenantID     string   `yaml:"tenant_id"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret,omitempty"`
	RedirectURI  string   `yaml:"redirect_uri"`
	Scopes       []string `yaml:"scopes,omitempty"`
	TokenURL     string   `yaml:"token_url,omitempty"`
}

type GraphConfig struct {
	BaseURL string `yaml:"base_url,omitempty"`
}

type Account struct {
	Name         string       `yaml:"name"`
	SMTPUsername string       `yaml:"smtp_username"`
	SMTPPassword string       `yaml:"smtp_password"`
	Email        string       `yaml:"email"`
	AllowedFrom  []string     `yaml:"allowed_from,omitempty"`
	AliasRoutes  []AliasRoute `yaml:"alias_routes,omitempty"`
	Token        Token        `yaml:"token,omitempty"`
}

type AliasRoute struct {
	From      string `yaml:"from"`
	GraphUser string `yaml:"graph_user"`
}

type Token struct {
	AccessToken  string    `yaml:"access_token,omitempty"`
	RefreshToken string    `yaml:"refresh_token,omitempty"`
	TokenType    string    `yaml:"token_type,omitempty"`
	Expiry       time.Time `yaml:"expiry,omitempty"`
	Scope        string    `yaml:"scope,omitempty"`
}

func Default() *Config {
	cfg := &Config{}
	cfg.ApplyDefaults()
	return cfg
}

func (c *Config) ApplyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListen
	}
	if c.Server.Hostname == "" {
		c.Server.Hostname = DefaultHostname
	}
	if c.Server.MessageSizeLimit == 0 {
		c.Server.MessageSizeLimit = 25 * 1024 * 1024
	}
	if c.Graph.BaseURL == "" {
		c.Graph.BaseURL = DefaultGraphURL
	}
	if len(c.OAuth.Scopes) == 0 {
		c.OAuth.Scopes = []string{"offline_access", "https://graph.microsoft.com/Mail.Send"}
	}
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.ApplyDefaults()
	return cfg, nil
}

func LoadOrDefault(path string) (*Config, error) {
	cfg, err := Load(path)
	if err == nil {
		return cfg, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	return nil, err
}

func Save(path string, cfg *Config) error {
	cfg.ApplyDefaults()
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".oauth2smtp-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (c *Config) FindAccountByName(name string) *Account {
	for i := range c.Accounts {
		if strings.EqualFold(c.Accounts[i].Name, name) {
			return &c.Accounts[i]
		}
	}
	return nil
}

func (c *Config) FindAccountBySMTPUsername(username string) *Account {
	for i := range c.Accounts {
		if strings.EqualFold(c.Accounts[i].SMTPUsername, username) {
			return &c.Accounts[i]
		}
	}
	return nil
}

func (a Account) IsFromAllowed(from string) bool {
	norm := NormalizeAddress(from)
	if norm == "" {
		return false
	}
	for _, candidate := range a.allowedFromCandidates() {
		if NormalizeAddress(candidate) == norm {
			return true
		}
	}
	return false
}

func (a Account) RouteForFrom(from string) (string, bool) {
	norm := NormalizeAddress(from)
	for _, route := range a.AliasRoutes {
		if NormalizeAddress(route.From) == norm && strings.TrimSpace(route.GraphUser) != "" {
			return strings.TrimSpace(route.GraphUser), true
		}
	}
	return "", false
}

func (a Account) allowedFromCandidates() []string {
	var candidates []string
	if a.Email != "" {
		candidates = append(candidates, a.Email)
	}
	candidates = append(candidates, a.AllowedFrom...)
	for _, route := range a.AliasRoutes {
		candidates = append(candidates, route.From)
	}
	return candidates
}

func NormalizeAddress(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(s); err == nil {
		s = addr.Address
	}
	return strings.ToLower(strings.TrimSpace(s))
}
