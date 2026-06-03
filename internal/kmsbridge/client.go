// Package kmsbridge is notify's direct line to Hanzo KMS.
//
// Canonical KMS routes (luxfi/kms post-canonical-migration):
//   - GET/DELETE: /v1/kms/orgs/{org}/secrets/{path}/{name}
//   - POST:       /v1/kms/orgs/{org}/secrets   (body: {path, name, value})
//
// Auth: IAM client_credentials grant at /v1/iam/oauth/access_token.
// The bearer is cached in-process until 60s before expiry. A static
// KMS_AUTH_TOKEN overrides the exchange — used by tests.
//
// The base/plugins/platform.KMSClient surface is kept identical
// (GetSecret/SetSecret/DeleteSecret/InvalidateCache) so callers can
// swap the import path without rewriting call sites.
package kmsbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// secretCacheTTL matches platform.KMSClient — one minute. Rotations land
// in under TTL+1m worst case.
const secretCacheTTL = 1 * time.Minute

// Config captures the (env-derived) inputs the bridge needs to mint
// tokens against IAM and call KMS. All fields are required except
// HTTPClient (which defaults to a 15s-timeout http.Client) and
// StaticBearer (an opaque override that bypasses the IAM exchange — set
// it from KMS_AUTH_TOKEN when tests want a fixed bearer).
type Config struct {
	// KMSEndpoint is the KMS server URL (e.g.
	// "http://liquid-kms.liquidity.svc.cluster.local:8443").
	KMSEndpoint string

	// IAMEndpoint is the IAM server URL (e.g.
	// "http://liquid-iam.liquidity.svc.cluster.local:8000"). The bridge
	// POSTs `IAMEndpoint + "/v1/iam/oauth/access_token"` to exchange
	// client_credentials for a bearer.
	IAMEndpoint string

	// ClientID is the IAM application client_id used for the
	// client_credentials grant.
	ClientID string

	// ClientSecret is the IAM application client_secret.
	ClientSecret string

	// StaticBearer, when non-empty, suppresses the IAM exchange and is
	// sent verbatim on every KMS request. Reserved for tests.
	StaticBearer string

	// HTTPClient is an optional override; nil → 15s-timeout default.
	HTTPClient *http.Client
}

// Client is the bridge type. Safe for concurrent use. One per process is
// enough; the cache amortizes the IAM token exchange and the secret
// reads across goroutines.
type Client struct {
	kmsEndpoint  string
	iamEndpoint  string
	clientID     string
	clientSecret string
	staticBearer string
	http         *http.Client

	// IAM token cache.
	tokMu       sync.Mutex
	accessToken string
	tokenExpiry time.Time

	// Secret value cache (orgId+"/"+secretPath → entry).
	secMu sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	value   string
	expires time.Time
}

// New returns a configured bridge. Returns an error if KMSEndpoint is
// blank or, when StaticBearer is empty, if any IAM field is missing —
// those are programmer errors caught at boot rather than at first send.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.KMSEndpoint) == "" {
		return nil, errors.New("kmsbridge: KMSEndpoint is required")
	}
	if strings.TrimSpace(cfg.StaticBearer) == "" {
		if strings.TrimSpace(cfg.IAMEndpoint) == "" {
			return nil, errors.New("kmsbridge: IAMEndpoint is required (no StaticBearer override)")
		}
		if strings.TrimSpace(cfg.ClientID) == "" {
			return nil, errors.New("kmsbridge: ClientID is required (no StaticBearer override)")
		}
		if strings.TrimSpace(cfg.ClientSecret) == "" {
			return nil, errors.New("kmsbridge: ClientSecret is required (no StaticBearer override)")
		}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		kmsEndpoint:  strings.TrimRight(cfg.KMSEndpoint, "/"),
		iamEndpoint:  strings.TrimRight(cfg.IAMEndpoint, "/"),
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		staticBearer: strings.TrimSpace(cfg.StaticBearer),
		http:         httpClient,
		cache:        make(map[string]*cacheEntry),
	}, nil
}

// GetSecret fetches one secret value for (orgId, secretPath). secretPath
// looks like "brand/liquidity/plivo/auth-id" — the last segment is the
// secret name and everything before it is the directory.
//
// The 1-minute cache amortizes hot-path repeats (e.g. Plivo creds on
// every SMS). On a fresh process the first read pays the full IAM token
// exchange + KMS round trip; subsequent reads inside the TTL are a map
// lookup.
func (c *Client) GetSecret(orgId, secretPath string) (string, error) {
	if c == nil {
		return "", errors.New("kmsbridge: nil receiver")
	}
	if strings.TrimSpace(orgId) == "" {
		return "", errors.New("kmsbridge: orgId is required")
	}
	if strings.TrimSpace(secretPath) == "" {
		return "", errors.New("kmsbridge: secretPath is required")
	}

	cacheKey := orgId + "/" + secretPath
	c.secMu.RLock()
	if e, ok := c.cache[cacheKey]; ok && time.Now().Before(e.expires) {
		val := e.value
		c.secMu.RUnlock()
		return val, nil
	}
	c.secMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	val, err := c.httpGet(ctx, orgId, secretPath)
	if err != nil {
		return "", err
	}

	c.secMu.Lock()
	c.cache[cacheKey] = &cacheEntry{value: val, expires: time.Now().Add(secretCacheTTL)}
	if len(c.cache) > 5000 {
		c.evictExpiredLocked()
	}
	c.secMu.Unlock()

	return val, nil
}

// SetSecret upserts a secret. POST /v1/kms/orgs/{org}/secrets with a
// JSON body {path, name, value}. The KMS server splits the upsert by
// (path, name).
func (c *Client) SetSecret(orgId, secretPath, value string) error {
	if c == nil {
		return errors.New("kmsbridge: nil receiver")
	}
	if strings.TrimSpace(orgId) == "" {
		return errors.New("kmsbridge: orgId is required")
	}
	if strings.TrimSpace(secretPath) == "" {
		return errors.New("kmsbridge: secretPath is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.httpPut(ctx, orgId, secretPath, value); err != nil {
		return err
	}
	c.secMu.Lock()
	delete(c.cache, orgId+"/"+secretPath)
	c.secMu.Unlock()
	return nil
}

// DeleteSecret removes a secret. 404 from KMS is treated as success
// (idempotent delete) per the platform.KMSClient contract.
func (c *Client) DeleteSecret(orgId, secretPath string) error {
	if c == nil {
		return errors.New("kmsbridge: nil receiver")
	}
	if strings.TrimSpace(orgId) == "" {
		return errors.New("kmsbridge: orgId is required")
	}
	if strings.TrimSpace(secretPath) == "" {
		return errors.New("kmsbridge: secretPath is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.httpDelete(ctx, orgId, secretPath); err != nil {
		return err
	}
	c.secMu.Lock()
	delete(c.cache, orgId+"/"+secretPath)
	c.secMu.Unlock()
	return nil
}

// InvalidateCache drops every cached entry under the given org. Called
// after a write so the next read goes back to KMS.
func (c *Client) InvalidateCache(orgId string) {
	if c == nil {
		return
	}
	prefix := orgId + "/"
	c.secMu.Lock()
	for k := range c.cache {
		if strings.HasPrefix(k, prefix) {
			delete(c.cache, k)
		}
	}
	c.secMu.Unlock()
}

// secretURL builds the canonical KMS read/delete URL:
//
//	{endpoint}/v1/kms/orgs/{org}/secrets/{path}/{name}
//
// Each path segment is URL-escaped. The {path} portion can be empty
// (top-level secret), in which case the URL collapses to
// /v1/kms/orgs/{org}/secrets/{name}.
func (c *Client) secretURL(orgId, secretPath string) string {
	p := strings.Trim(secretPath, "/")
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return fmt.Sprintf("%s/v1/kms/orgs/%s/secrets/%s",
		c.kmsEndpoint,
		url.PathEscape(orgId),
		strings.Join(segs, "/"),
	)
}

func (c *Client) httpGet(ctx context.Context, orgId, secretPath string) (string, error) {
	token, err := c.bearer(ctx)
	if err != nil {
		return "", fmt.Errorf("kmsbridge: auth: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.secretURL(orgId, secretPath), nil)
	if err != nil {
		return "", fmt.Errorf("kmsbridge: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("kmsbridge: request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("kmsbridge: secret %s/%s not found", orgId, secretPath)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kmsbridge: status %d: %s", resp.StatusCode, string(body))
	}
	// The canonical kmsd returns either {"secret":{"value":"..."}} or
	// {"value":"..."} (older wire shape). Accept both.
	var wrapped struct {
		Secret struct {
			Value string `json:"value"`
		} `json:"secret"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return "", fmt.Errorf("kmsbridge: decode: %w", err)
	}
	if wrapped.Secret.Value != "" {
		return wrapped.Secret.Value, nil
	}
	return wrapped.Value, nil
}

func (c *Client) httpPut(ctx context.Context, orgId, secretPath, value string) error {
	token, err := c.bearer(ctx)
	if err != nil {
		return fmt.Errorf("kmsbridge: auth: %w", err)
	}
	// Split secretPath into (path, name) — last segment is the name.
	path, name := splitSecretPath(secretPath)
	if name == "" {
		return errors.New("kmsbridge: secretPath has no name segment")
	}
	u := fmt.Sprintf("%s/v1/kms/orgs/%s/secrets",
		c.kmsEndpoint,
		url.PathEscape(orgId),
	)
	payload, _ := json.Marshal(map[string]string{
		"path":  path,
		"name":  name,
		"value": value,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("kmsbridge: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kmsbridge: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("kmsbridge: put status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *Client) httpDelete(ctx context.Context, orgId, secretPath string) error {
	token, err := c.bearer(ctx)
	if err != nil {
		return fmt.Errorf("kmsbridge: auth: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.secretURL(orgId, secretPath), nil)
	if err != nil {
		return fmt.Errorf("kmsbridge: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kmsbridge: request failed: %w", err)
	}
	defer resp.Body.Close()
	// 404 is success for idempotent delete.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("kmsbridge: delete status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// splitSecretPath splits "brand/liquidity/plivo/auth-id" into
// (path="brand/liquidity/plivo", name="auth-id"). For a single-segment
// input, path is empty and the whole input is the name.
func splitSecretPath(s string) (path, name string) {
	s = strings.Trim(s, "/")
	idx := strings.LastIndex(s, "/")
	if idx < 0 {
		return "", s
	}
	return s[:idx], s[idx+1:]
}

// bearer returns a valid IAM bearer, refreshing the cached token when
// fewer than 60s remain on the existing one.
func (c *Client) bearer(ctx context.Context) (string, error) {
	if c.staticBearer != "" {
		return c.staticBearer, nil
	}
	c.tokMu.Lock()
	defer c.tokMu.Unlock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return c.accessToken, nil
	}

	// IAM v1.18.7 advertises /v1/iam/oauth/access_token as the canonical
	// machine-token endpoint and accepts /v1/iam/login/oauth/access_token
	// + /api/iam/login/oauth/access_token + /oauth/access_token as
	// aliases (collapsed by PathRewriteFilter). We pick the canonical
	// form so a future alias trim doesn't break us.
	tokenURL := c.iamEndpoint + "/v1/iam/oauth/access_token"
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("iam token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("iam token exchange: status %d: %s", resp.StatusCode, string(body))
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("iam token decode: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("iam returned empty access token")
	}
	c.accessToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		c.tokenExpiry = time.Now().Add(1 * time.Hour)
	}
	return c.accessToken, nil
}

func (c *Client) evictExpiredLocked() {
	now := time.Now()
	for k, v := range c.cache {
		if now.After(v.expires) {
			delete(c.cache, k)
		}
	}
}
