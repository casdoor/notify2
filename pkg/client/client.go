// Package client is the thin HTTP consumer SDK for the Hanzo Notify
// service. Targets the /v1/notify/* surface notifyd exposes; every
// method maps 1:1 to one HTTP endpoint with no client-side fan-out.
//
// Auth is bearer-token: callers provide a Hanzo IAM JWT (via
// WithToken) which notifyd validates against IAM's JWKS.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hanzoai/notify/pkg/types"
)

// Client is the canonical HTTP consumer SDK.
type Client struct {
	base       *url.URL
	token      string
	httpClient *http.Client
}

// Option configures a Client at construction time.
type Option func(*Client)

// WithToken sets the IAM JWT used for the Authorization header.
func WithToken(jwt string) Option {
	return func(c *Client) { c.token = jwt }
}

// WithHTTPClient swaps the underlying http.Client (e.g. for retries,
// tracing, or test fakes).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// New returns a Client targeting baseURL (e.g. "https://notify.hanzo.ai").
// baseURL is parsed once at construction; an invalid URL returns an
// error rather than panicking later in a Send call.
func New(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("client: baseURL is required")
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("client: parse base url: %w", err)
	}
	c := &Client{
		base:       u,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Send dispatches one notification. With sync=false (the default
// async mode) notifyd enqueues a hanzoai/tasks workflow and returns a
// task_id immediately; with sync=true notifyd blocks until the provider
// either accepts the message or returns an error.
func (c *Client) Send(ctx context.Context, req types.SendRequest, sync bool) (*types.SendResponse, error) {
	q := url.Values{}
	if sync {
		q.Set("sync", "true")
	}
	var out types.SendResponse
	if err := c.do(ctx, http.MethodPost, "/v1/notify/send", q, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Message fetches the persisted record by id.
func (c *Client) Message(ctx context.Context, id string) (*types.Message, error) {
	var out types.Message
	if err := c.do(ctx, http.MethodGet, "/v1/notify/messages/"+url.PathEscape(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Providers lists the configured providers for the authenticated tenant.
func (c *Client) Providers(ctx context.Context) ([]types.Provider, error) {
	var out struct {
		Items []types.Provider `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/notify/providers", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// Templates lists the configured templates for the authenticated tenant.
func (c *Client) Templates(ctx context.Context) ([]types.Template, error) {
	var out struct {
		Items []types.Template `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/notify/templates", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// do issues an authenticated HTTP request. Empty body is OK (GET/DELETE);
// non-nil out triggers JSON decode. Non-2xx responses unmarshal the
// error envelope and return it as a typed error.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := *c.base
	u.Path += path
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("client: marshal body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("client: new request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("client: do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return &APIError{
			Status: resp.StatusCode,
			Body:   string(raw),
		}
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("client: decode: %w", err)
	}
	return nil
}

// APIError is returned for non-2xx HTTP responses. Routes layer encodes
// a JSON error envelope; this preserves the raw body for callers that
// want to inspect provider-specific failure detail.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("notify: api error status=%d body=%s", e.Status, e.Body)
}
