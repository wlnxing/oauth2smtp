package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"oauth2smtp/internal/config"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

type Error struct {
	StatusCode int
	Body       string
}

func (e *Error) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("graph returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("graph returned HTTP %d: %s", e.StatusCode, e.Body)
}

func New(baseURL string, httpClient *http.Client) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = config.DefaultGraphURL
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: httpClient}
}

func EndpointForFrom(acc config.Account, from string) string {
	if graphUser, ok := acc.RouteForFrom(from); ok {
		return "/users/" + url.PathEscape(graphUser) + "/sendMail"
	}
	return "/me/sendMail"
}

func (c *Client) SendMIME(ctx context.Context, accessToken, endpoint string, mime []byte) error {
	if strings.TrimSpace(accessToken) == "" {
		return fmt.Errorf("missing access token")
	}
	if endpoint == "" {
		endpoint = "/me/sendMail"
	}
	body := base64.StdEncoding.EncodeToString(mime)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+endpoint, bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &Error{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))}
}
