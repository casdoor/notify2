// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package tenant

// Multi-provider retry / fallback for notify.
//
// Today notify resolves ONE provider per send. That makes Plivo a single
// point of failure for SMS and SES the single point of failure for
// email. This file generalizes the resolver into a per-channel
// ordered chain: primary → fallback1 → fallback2. On a retryable
// failure we walk to the next provider; on a terminal failure (invalid
// recipient, blocklist) we short-circuit.
//
// One way to wire it:
//
//   1. ChainResolver.Resolve(ctx, brand, channel) returns a
//      ProviderChain pre-bound with the brand's KMS-resolved provider
//      instances in order.
//   2. ProviderChain.Run(ctx, to, subject, body) walks the chain,
//      retries across providers on transient failures, returns the
//      attempt log + the winning provider id (or the terminal error).
//   3. Activities.Deliver consumes (1)+(2) — no other call site.
//
// Per-tenant overrides live in KMS at brand/<slug>/notify-chain/<channel>
// as a JSON array of provider ids; absent → default chain per
// DefaultChainFor.
//
// KMS layout for provider credentials (canonical):
//
//   brand/<slug>/plivo/{auth-id, auth-token, sender-id, sender-id-link, from-email}
//   brand/<slug>/twilio/{account-sid, auth-token, from-phone, messaging-sid}
//   brand/<slug>/ses/{access-key-id, secret-access-key, region, from-address, smtp-user, smtp-password, smtp-host, smtp-port}
//   brand/<slug>/sendgrid/{api-key, from-address, from-name}
//
// Same brand-fallback rule as PlivoResolver: missing brand secrets
// fall through to brand/liquidity/<provider>/* (the fleet default).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/notify"
	"github.com/hanzoai/notify/internal/kmsbridge"
	"github.com/hanzoai/notify/service/amazonses"
	"github.com/hanzoai/notify/service/mail"
	"github.com/hanzoai/notify/service/plivo"
	"github.com/hanzoai/notify/service/sendgrid"
	"github.com/hanzoai/notify/service/twilio"
)

// ChainChannel selects which provider chain to resolve. It is finer-
// grained than types.Channel because email has three distinct routing
// profiles (transactional, OTP, marketing) that often want different
// providers — e.g. SES API for batched transactional but SES SMTP for
// the IAM OTP path because IAM holds the connection open. SMS has a
// single chain today.
type ChainChannel string

const (
	ChainSMS            ChainChannel = "sms"
	ChainEmailTxn       ChainChannel = "email_txn"
	ChainEmailOTP       ChainChannel = "email_otp"
	ChainEmailMarketing ChainChannel = "email_marketing"
)

// canonicalChannel narrows arbitrary inputs to a known ChainChannel.
// Empty / unknown values default to ChainSMS-vs-ChainEmailTxn based on
// the wire-level Channel (caller passes types.Channel("sms"|"email")).
//
// Callers can pass either the wire channel ("sms", "email") or the fine
// ChainChannel string directly ("email_otp"). Both resolve.
func canonicalChannel(s string) ChainChannel {
	switch ChainChannel(strings.ToLower(strings.TrimSpace(s))) {
	case ChainSMS:
		return ChainSMS
	case ChainEmailTxn:
		return ChainEmailTxn
	case ChainEmailOTP:
		return ChainEmailOTP
	case ChainEmailMarketing:
		return ChainEmailMarketing
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sms":
		return ChainSMS
	case "email":
		return ChainEmailTxn
	}
	return ""
}

// DefaultChainFor returns the default ordered provider id list for a
// channel. Per-tenant overrides supersede this; see ChainResolver.
//
// The default chain matches the project spec:
//
//   SMS              → plivo, twilio
//   email_txn        → ses_api, ses_smtp
//   email_otp        → ses_smtp, ses_api
//   email_marketing  → sendgrid, ses_api
//
// All providers are optional at the per-brand level: a missing secret
// for a fallback provider is treated as "this provider not configured
// for this brand" and the chain skips it without erroring (provided at
// least one provider in the chain succeeded or surfaced a terminal
// error).
func DefaultChainFor(ch ChainChannel) []string {
	switch ch {
	case ChainSMS:
		return []string{ProviderPlivo, ProviderTwilio}
	case ChainEmailTxn:
		return []string{ProviderSESAPI, ProviderSESSMTP}
	case ChainEmailOTP:
		return []string{ProviderSESSMTP, ProviderSESAPI}
	case ChainEmailMarketing:
		return []string{ProviderSendGrid, ProviderSESAPI}
	}
	return nil
}

// Canonical provider ids. These are the strings used in KMS-stored
// chain JSON, in telemetry logs, and on the Message row's `provider`
// field. They MUST stay stable — they are part of the wire contract
// with the platform UI's "current effective chain" indicator.
const (
	ProviderPlivo    = "plivo"
	ProviderTwilio   = "twilio"
	ProviderSESAPI   = "ses_api"
	ProviderSESSMTP  = "ses_smtp"
	ProviderSendGrid = "sendgrid"
)

// providerChainKMSPath is the KMS path where per-tenant chain overrides
// live: brand/<slug>/notify-chain/<channel> → JSON array of provider ids.
const providerChainKMSPath = "notify-chain"

// perProviderAttemptTimeout caps any single provider's Send call. A
// hung HTTP socket cannot poison the entire chain — we move on to the
// next provider after this much time.
const perProviderAttemptTimeout = 10 * time.Second

// perSendTotalDeadline caps the whole chain. The route handler may
// already have a longer context (e.g. async via tasks), but we install
// our own ceiling so a misbehaving brand chain can't tie up a worker
// thread indefinitely.
const perSendTotalDeadline = 30 * time.Second

// Attempt is one provider attempt's result, recorded in the per-send
// telemetry. The provider id stays stable across schema migrations;
// success/duration/error are observable knobs the dashboards key on.
type Attempt struct {
	Provider string        `json:"provider"`
	Started  time.Time     `json:"started"`
	Duration time.Duration `json:"duration"`
	Outcome  string        `json:"outcome"` // "ok" | "retryable" | "terminal"
	Error    string        `json:"error,omitempty"`
}

// RunResult is the per-send outcome of executing a ProviderChain. On
// success, Winner is the provider that won (and Attempts ends with
// outcome="ok"). On exhausted-chain failure, Winner is empty and
// Attempts shows every provider that was tried.
type RunResult struct {
	Channel  ChainChannel `json:"channel"`
	Tenant   string       `json:"tenant"`
	Brand    string       `json:"brand"` // brand whose chain was used
	Winner   string       `json:"winner,omitempty"`
	Attempts []Attempt    `json:"attempts"`
}

// ProviderChain is the ordered list of providers attempted for a single
// send. The first provider that succeeds wins; on retryable failure
// the next provider is attempted. On terminal failure (e.g. bad
// recipient, blocklist) we stop the chain.
type ProviderChain struct {
	Channel   ChainChannel
	Tenant    string
	Brand     string
	Providers []ChainProvider
}

// ChainProvider is the narrow surface ProviderChain consumes per
// attempt. The notify library's Notifier covers Send; ID is metadata.
type ChainProvider interface {
	ID() string
	Send(ctx context.Context, subject, body string, to string) error
}

// RawSender is the optional extension a ChainProvider may implement to
// expose a raw-MIME send path. Marketing-class email needs RFC 8058
// List-Unsubscribe headers, and providers like SES whose plain Send
// path cannot inject arbitrary headers wrap this around the SDK's
// raw-message call (e.g. amazonses.AmazonSES.SendRaw → SendRawEmail).
//
// Providers that already pass headers through their SDK natively
// (SendGrid via personalization.AddHeader, SMTP mail via
// email.Email.Headers) can implement this as a thin shim too — but
// for this PR only the SES API provider does, because that's the
// SDK whose SendEmail API does not support headers at all.
type RawSender interface {
	SendRaw(ctx context.Context, subject, body string, isHTML bool, to string, headers map[string]string) error
}

// Run walks the chain. It returns the winning provider id and the
// telemetry trace. If every provider fails it returns ErrChainExhausted
// with the trace attached.
//
// Retry policy (one and only one):
//   - per-attempt context: a 10s deadline derived from the parent
//   - per-attempt outcome:
//       ok        — the provider succeeded; return immediately
//       terminal  — the recipient is invalid; stop, no fallback
//       retryable — anything else; advance to the next provider
//   - whole-chain context: a 30s deadline ceiling
//
// Logger is optional; nil means no per-attempt log line is emitted.
// The structured Attempt list is always returned in RunResult.
func (c *ProviderChain) Run(ctx context.Context, to, subject, body string) (RunResult, error) {
	return c.run(ctx, to, subject, body, false, nil, false)
}

// RunMarketing is Run plus RFC 8058 header injection for the marketing
// class. For each provider attempt the chain prefers the RawSender
// path when the provider implements it — that's how SES carries
// List-Unsubscribe + List-Unsubscribe-Post across the SDK boundary.
// Providers without RawSender fall back to plain Send; the body is
// expected to already carry the visible "Unsubscribe: …" footer so
// even those providers honour the spirit of the request, just not the
// machine-actionable header.
//
// isHTML toggles the MIME Content-Type on the raw path; ignored when
// the provider falls back to plain Send.
func (c *ProviderChain) RunMarketing(ctx context.Context, to, subject, body string, isHTML bool, headers map[string]string) (RunResult, error) {
	return c.run(ctx, to, subject, body, isHTML, headers, true)
}

// run is the shared walker behind Run + RunMarketing.
func (c *ProviderChain) run(ctx context.Context, to, subject, body string, isHTML bool, headers map[string]string, marketing bool) (RunResult, error) {
	res := RunResult{
		Channel:  c.Channel,
		Tenant:   c.Tenant,
		Brand:    c.Brand,
		Attempts: make([]Attempt, 0, len(c.Providers)),
	}
	if len(c.Providers) == 0 {
		return res, ErrNoProviders
	}

	outerCtx, cancel := context.WithTimeout(ctx, perSendTotalDeadline)
	defer cancel()

	var lastErr error
	for _, p := range c.Providers {
		// Respect the outer (whole-chain) deadline before paying any
		// more provider cost.
		if err := outerCtx.Err(); err != nil {
			res.Attempts = append(res.Attempts, Attempt{
				Provider: p.ID(),
				Started:  time.Now().UTC(),
				Outcome:  "retryable",
				Error:    "chain deadline exceeded before attempt",
			})
			lastErr = err
			break
		}

		attemptCtx, attemptCancel := context.WithTimeout(outerCtx, perProviderAttemptTimeout)
		started := time.Now().UTC()
		var err error
		if marketing {
			if raw, ok := p.(RawSender); ok {
				// Raw-MIME path: List-Unsubscribe + List-Unsubscribe-Post
				// land in the envelope. SES needs this because SendEmail
				// cannot inject custom headers.
				err = raw.SendRaw(attemptCtx, subject, body, isHTML, to, headers)
			} else {
				// Provider does not implement RawSender — fall back to
				// plain Send. The body already carries the visible
				// "Unsubscribe: …" footer so the user can still opt out;
				// only the native Gmail/Outlook button is missing.
				err = p.Send(attemptCtx, subject, body, to)
			}
		} else {
			err = p.Send(attemptCtx, subject, body, to)
		}
		dur := time.Since(started)
		attemptCancel()

		attempt := Attempt{
			Provider: p.ID(),
			Started:  started,
			Duration: dur,
		}
		switch {
		case err == nil:
			attempt.Outcome = "ok"
			res.Attempts = append(res.Attempts, attempt)
			res.Winner = p.ID()
			return res, nil
		case classifyError(err) == errTerminal:
			attempt.Outcome = "terminal"
			attempt.Error = err.Error()
			res.Attempts = append(res.Attempts, attempt)
			return res, &ChainError{
				Result: res,
				Cause:  err,
				Reason: "terminal",
			}
		default:
			attempt.Outcome = "retryable"
			attempt.Error = err.Error()
			res.Attempts = append(res.Attempts, attempt)
			lastErr = err
		}
	}

	return res, &ChainError{
		Result: res,
		Cause:  lastErr,
		Reason: "exhausted",
	}
}

// ErrNoProviders is returned when a ProviderChain has no providers to
// try (typically because the brand has not configured any provider for
// the channel and the default chain's providers all failed to construct
// due to missing KMS secrets). Distinct from ChainError so the caller
// can return 503 rather than 502.
var ErrNoProviders = errors.New("provider chain: no providers configured for channel/brand")

// ChainError wraps the underlying cause with the full attempt trace.
// Activities.Deliver records the cause on the Message row and emits the
// trace via the logger.
type ChainError struct {
	Result RunResult
	Cause  error
	Reason string // "exhausted" | "terminal"
}

func (e *ChainError) Error() string {
	if e == nil {
		return "<nil chain error>"
	}
	if e.Cause == nil {
		return fmt.Sprintf("provider chain %s for tenant=%s channel=%s: %d attempts, no provider succeeded", e.Reason, e.Result.Tenant, e.Result.Channel, len(e.Result.Attempts))
	}
	return fmt.Sprintf("provider chain %s for tenant=%s channel=%s: %v (after %d attempts)", e.Reason, e.Result.Tenant, e.Result.Channel, e.Cause, len(e.Result.Attempts))
}

func (e *ChainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// --- Error classification ---

type errClass int

const (
	errRetryable errClass = iota
	errTerminal
)

// classifyError decides whether an error from a provider should walk to
// the next chain entry (retryable) or short-circuit (terminal).
//
// Defaults: anything that smells like a 4xx client error, an invalid
// recipient, or a blocklist hit is terminal. Network errors, 5xx,
// timeouts, and unknown errors are retryable.
//
// We classify on the error message string because the upstream
// providers (Plivo, Twilio, AWS SES SDK, SendGrid) each surface
// non-portable typed errors. A substring match here is the smallest
// thing that works across all of them.
func classifyError(err error) errClass {
	if err == nil {
		return errRetryable
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return errRetryable
	}

	msg := strings.ToLower(err.Error())
	for _, terminal := range []string{
		"invalid number",
		"invalid phone",
		"invalid recipient",
		"invalid 'to'",
		"invalid email",
		"blacklist",
		"blocklist",
		"suppressed",
		"unsubscribed",
		"do not contact",
		"address rejected",
		"address not verified",
		"messagerejected",
		"21211", // twilio: invalid 'to' number
		"21610", // twilio: blocked recipient
		"21612", // twilio: not reachable
		"21614", // twilio: not mobile
		"21617", // twilio: invalid messaging service sid
		"30003", // twilio: unreachable
		"30005", // twilio: unknown destination
		"30007", // twilio: carrier filtered
		"400 ",
		"401 ",
		"403 ",
		"404 ",
		"422 ",
		"status 400",
		"status 401",
		"status 403",
		"status 404",
		"status 422",
		"unauthorized",
		"forbidden",
	} {
		if strings.Contains(msg, terminal) {
			return errTerminal
		}
	}
	return errRetryable
}

// --- ChainResolver: build a ProviderChain for (brand, channel) ---

// ChainResolver constructs ProviderChain instances for a (brand,
// channel) pair. It owns the KMS bridge — every constructed provider
// reads its secrets via the same fall-back path as PlivoResolver
// (brand/<slug>/<provider>/* → brand/liquidity/<provider>/* on miss).
type ChainResolver struct {
	kms *kmsbridge.Client

	// mu guards the per-channel order cache.
	mu    sync.RWMutex
	cache map[string][]string // key: brand+"|"+channel
}

// NewChainResolver returns a ChainResolver bound to a KMS client. A nil
// kms is rejected — the resolver fail-closes at boot rather than at
// first send.
func NewChainResolver(kms *kmsbridge.Client) (*ChainResolver, error) {
	if kms == nil {
		return nil, errors.New("chain resolver: KMS client is required")
	}
	return &ChainResolver{
		kms:   kms,
		cache: make(map[string][]string),
	}, nil
}

// Resolve constructs a ProviderChain for the (brand, channel) pair.
// The order comes from KMS at brand/<slug>/notify-chain/<channel> as a
// JSON array of provider ids; absent → DefaultChainFor(channel). For
// each provider id in order, the resolver builds the provider with the
// brand's KMS secrets (falling back to brand/liquidity/<provider>/* on
// any missing secret), skipping providers the brand has not configured
// (and the Liquidity default has not configured either).
//
// The resolver returns ErrNoProviders if every provider in the resolved
// order failed to construct.
func (r *ChainResolver) Resolve(ctx context.Context, brand string, channel ChainChannel) (*ProviderChain, error) {
	brand = strings.TrimSpace(brand)
	if brand == "" {
		return nil, errors.New("chain resolver: brand is required")
	}
	channel = canonicalChannel(string(channel))
	if channel == "" {
		return nil, errors.New("chain resolver: channel is required")
	}

	order := r.order(brand, channel)
	chain := &ProviderChain{
		Channel:   channel,
		Tenant:    brand,
		Brand:     brand,
		Providers: make([]ChainProvider, 0, len(order)),
	}
	for _, pid := range order {
		p, brandUsed, err := r.buildProvider(ctx, brand, pid)
		if err != nil {
			// Treat construction failure as "this provider not available
			// for this brand" and skip. We never want a missing fallback
			// secret to break a brand that has a working primary.
			continue
		}
		if brandUsed != brand && chain.Brand == brand {
			// Record the fact that at least one provider fell back to
			// the Liquidity default. Useful for telemetry but does not
			// override the chain's nominal brand.
			_ = brandUsed
		}
		chain.Providers = append(chain.Providers, p)
	}
	if len(chain.Providers) == 0 {
		return chain, ErrNoProviders
	}
	return chain, nil
}

// order returns the resolved provider id order for (brand, channel).
// Per-tenant override at brand/<slug>/notify-chain/<channel> wins; on
// miss the function returns DefaultChainFor(channel).
//
// The per-call cost is one KMS read on cache miss. Results are cached
// for the process lifetime — chain reconfiguration takes a process
// bounce, which matches how the platform UI hands edits down today.
func (r *ChainResolver) order(brand string, channel ChainChannel) []string {
	cacheKey := brand + "|" + string(channel)
	r.mu.RLock()
	if cached, ok := r.cache[cacheKey]; ok {
		r.mu.RUnlock()
		return cached
	}
	r.mu.RUnlock()

	resolved := r.fetchOrder(brand, channel)
	r.mu.Lock()
	r.cache[cacheKey] = resolved
	r.mu.Unlock()
	return resolved
}

// InvalidateChainCache drops the cached chain order for (brand,
// channel). The platform UI calls this after writing a new chain so
// the next send picks up the change without a pod restart.
func (r *ChainResolver) InvalidateChainCache(brand string, channel ChainChannel) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.cache, brand+"|"+string(channel))
	r.mu.Unlock()
}

// fetchOrder reads brand/<slug>/notify-chain/<channel> and returns the
// parsed JSON array, falling back to DefaultChainFor on miss / parse
// error / unknown ids. Unknown ids are filtered (not errored) so a bad
// override entry can never break sends — the chain just shortens.
func (r *ChainResolver) fetchOrder(brand string, channel ChainChannel) []string {
	path := providerChainKMSPath + "/" + string(channel)
	raw, err := r.kms.GetSecret(brand, "brand/"+brand+"/"+path)
	if err != nil || strings.TrimSpace(raw) == "" {
		// Try the Liquidity default's override before falling back to
		// the hard-coded default chain.
		if brand != DefaultBrand {
			raw, err = r.kms.GetSecret(DefaultBrand, "brand/"+DefaultBrand+"/"+path)
		}
		if err != nil || strings.TrimSpace(raw) == "" {
			return DefaultChainFor(channel)
		}
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return DefaultChainFor(channel)
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.ToLower(strings.TrimSpace(id))
		if !knownProvider(id) {
			continue
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return DefaultChainFor(channel)
	}
	return out
}

// knownProvider returns true for provider ids the resolver can build.
// New provider ids land here as a one-line edit when the matching
// buildProvider branch ships.
func knownProvider(id string) bool {
	switch id {
	case ProviderPlivo, ProviderTwilio,
		ProviderSESAPI, ProviderSESSMTP,
		ProviderSendGrid:
		return true
	}
	return false
}

// buildProvider constructs a ChainProvider for (brand, providerID),
// resolving credentials via the brand → Liquidity-default fallback.
// The brand whose secrets were used is returned for telemetry.
func (r *ChainResolver) buildProvider(ctx context.Context, brand, providerID string) (ChainProvider, string, error) {
	switch providerID {
	case ProviderPlivo:
		return r.buildPlivo(ctx, brand)
	case ProviderTwilio:
		return r.buildTwilio(ctx, brand)
	case ProviderSESAPI:
		return r.buildSESAPI(ctx, brand)
	case ProviderSESSMTP:
		return r.buildSESSMTP(ctx, brand)
	case ProviderSendGrid:
		return r.buildSendGrid(ctx, brand)
	}
	return nil, "", fmt.Errorf("chain resolver: unknown provider %q", providerID)
}

// readBrandSecret implements the brand→default fallback for a single
// secret field. Returns the value + the brand whose KMS row supplied
// it. A missing brand value is silently fallen back to Liquidity; any
// other error short-circuits (so a transient KMS outage doesn't make
// us send under the wrong identity).
func (r *ChainResolver) readBrandSecret(brand, providerID, field string) (string, string, error) {
	path := "brand/" + brand + "/" + providerID + "/" + field
	val, err := r.kms.GetSecret(brand, path)
	if err == nil {
		return val, brand, nil
	}
	if !isMissingSecret(err) {
		return "", "", fmt.Errorf("kms read %s/%s: %w", brand, path, err)
	}
	if brand == DefaultBrand {
		return "", DefaultBrand, err
	}
	defaultPath := "brand/" + DefaultBrand + "/" + providerID + "/" + field
	val, err = r.kms.GetSecret(DefaultBrand, defaultPath)
	if err != nil {
		return "", DefaultBrand, err
	}
	return val, DefaultBrand, nil
}

// readBrandSecretOptional behaves like readBrandSecret but treats a
// final miss as an empty string rather than an error. Used for fields
// that have sensible defaults (smtp-port, from-name) or are only
// required by some providers.
func (r *ChainResolver) readBrandSecretOptional(brand, providerID, field string) string {
	v, _, _ := r.readBrandSecret(brand, providerID, field)
	return v
}

func (r *ChainResolver) buildPlivo(_ context.Context, brand string) (ChainProvider, string, error) {
	authID, b1, err := r.readBrandSecret(brand, ProviderPlivo, "auth-id")
	if err != nil {
		return nil, b1, fmt.Errorf("plivo: %w", err)
	}
	authToken, _, err := r.readBrandSecret(brand, ProviderPlivo, "auth-token")
	if err != nil {
		return nil, b1, fmt.Errorf("plivo: %w", err)
	}
	// sender-id-otp is preferred for OTP traffic; sender-id is the
	// generic source. Either suffices.
	senderID, _, err := r.readBrandSecret(brand, ProviderPlivo, "sender-id-otp")
	if err != nil {
		senderID, _, err = r.readBrandSecret(brand, ProviderPlivo, "sender-id")
		if err != nil {
			return nil, b1, fmt.Errorf("plivo: %w", err)
		}
	}
	svc, err := plivo.New(
		&plivo.ClientOptions{
			AuthID:     authID,
			AuthToken:  authToken,
			HTTPClient: &http.Client{Timeout: perProviderAttemptTimeout},
		},
		&plivo.MessageOptions{Source: senderID},
	)
	if err != nil {
		return nil, b1, fmt.Errorf("plivo construct: %w", err)
	}
	return &plivoChainProvider{svc: svc}, b1, nil
}

func (r *ChainResolver) buildTwilio(_ context.Context, brand string) (ChainProvider, string, error) {
	accountSID, b1, err := r.readBrandSecret(brand, ProviderTwilio, "account-sid")
	if err != nil {
		return nil, b1, fmt.Errorf("twilio: %w", err)
	}
	authToken, _, err := r.readBrandSecret(brand, ProviderTwilio, "auth-token")
	if err != nil {
		return nil, b1, fmt.Errorf("twilio: %w", err)
	}
	from, _, err := r.readBrandSecret(brand, ProviderTwilio, "from-phone")
	if err != nil {
		// messaging-sid is a per-pool alternative to from-phone.
		from, _, err = r.readBrandSecret(brand, ProviderTwilio, "messaging-sid")
		if err != nil {
			return nil, b1, fmt.Errorf("twilio: %w", err)
		}
	}
	svc, err := twilio.New(accountSID, authToken, from)
	if err != nil {
		return nil, b1, fmt.Errorf("twilio construct: %w", err)
	}
	return &twilioChainProvider{svc: svc}, b1, nil
}

func (r *ChainResolver) buildSESAPI(_ context.Context, brand string) (ChainProvider, string, error) {
	accessKey, b1, err := r.readBrandSecret(brand, "ses", "access-key-id")
	if err != nil {
		return nil, b1, fmt.Errorf("ses_api: %w", err)
	}
	secretKey, _, err := r.readBrandSecret(brand, "ses", "secret-access-key")
	if err != nil {
		return nil, b1, fmt.Errorf("ses_api: %w", err)
	}
	region, _, err := r.readBrandSecret(brand, "ses", "region")
	if err != nil {
		return nil, b1, fmt.Errorf("ses_api: %w", err)
	}
	from, _, err := r.readBrandSecret(brand, "ses", "from-address")
	if err != nil {
		return nil, b1, fmt.Errorf("ses_api: %w", err)
	}
	svc, err := amazonses.New(accessKey, secretKey, region, from)
	if err != nil {
		return nil, b1, fmt.Errorf("ses_api construct: %w", err)
	}
	return &sesAPIChainProvider{svc: svc}, b1, nil
}

func (r *ChainResolver) buildSESSMTP(_ context.Context, brand string) (ChainProvider, string, error) {
	smtpUser, b1, err := r.readBrandSecret(brand, "ses", "smtp-user")
	if err != nil {
		return nil, b1, fmt.Errorf("ses_smtp: %w", err)
	}
	smtpPass, _, err := r.readBrandSecret(brand, "ses", "smtp-password")
	if err != nil {
		return nil, b1, fmt.Errorf("ses_smtp: %w", err)
	}
	from, _, err := r.readBrandSecret(brand, "ses", "from-address")
	if err != nil {
		return nil, b1, fmt.Errorf("ses_smtp: %w", err)
	}
	host := r.readBrandSecretOptional(brand, "ses", "smtp-host")
	if host == "" {
		// Default to the regional SES SMTP endpoint when the host is
		// not pinned. The region field must exist for SES API; reuse it.
		region, _, err := r.readBrandSecret(brand, "ses", "region")
		if err != nil {
			return nil, b1, fmt.Errorf("ses_smtp: %w", err)
		}
		host = "email-smtp." + region + ".amazonaws.com"
	}
	port := r.readBrandSecretOptional(brand, "ses", "smtp-port")
	if port == "" {
		port = "587"
	}
	svc := mail.New(from, host+":"+port)
	svc.AuthenticateSMTP("", smtpUser, smtpPass, host)
	return &sesSMTPChainProvider{svc: svc}, b1, nil
}

func (r *ChainResolver) buildSendGrid(_ context.Context, brand string) (ChainProvider, string, error) {
	apiKey, b1, err := r.readBrandSecret(brand, ProviderSendGrid, "api-key")
	if err != nil {
		return nil, b1, fmt.Errorf("sendgrid: %w", err)
	}
	from, _, err := r.readBrandSecret(brand, ProviderSendGrid, "from-address")
	if err != nil {
		return nil, b1, fmt.Errorf("sendgrid: %w", err)
	}
	fromName := r.readBrandSecretOptional(brand, ProviderSendGrid, "from-name")
	if fromName == "" {
		fromName = from
	}
	svc := sendgrid.New(apiKey, from, fromName)
	return &sendgridChainProvider{svc: svc}, b1, nil
}

// --- ChainProvider adapters ---
//
// Each adapter wraps one provider service from the notify library so it
// satisfies ChainProvider. The library expects AddReceivers + Send;
// here we always single-receiver so the chain stays per-recipient.

type plivoChainProvider struct {
	svc *plivo.Service
}

func (p *plivoChainProvider) ID() string { return ProviderPlivo }
func (p *plivoChainProvider) Send(ctx context.Context, subject, body, to string) error {
	// New svc per send keeps state local — AddReceivers is additive.
	p.svc.AddReceivers(to)
	return p.svc.Send(ctx, subject, body)
}

type twilioChainProvider struct {
	svc *twilio.Service
}

func (p *twilioChainProvider) ID() string { return ProviderTwilio }
func (p *twilioChainProvider) Send(ctx context.Context, subject, body, to string) error {
	p.svc.AddReceivers(to)
	return p.svc.Send(ctx, subject, body)
}

type sesAPIChainProvider struct {
	svc *amazonses.AmazonSES
}

func (p *sesAPIChainProvider) ID() string { return ProviderSESAPI }
func (p *sesAPIChainProvider) Send(ctx context.Context, subject, body, to string) error {
	p.svc.AddReceivers(to)
	return p.svc.Send(ctx, subject, body)
}

// SendRaw runs the marketing-class send through SES SendRawEmail so the
// caller-provided headers (List-Unsubscribe + List-Unsubscribe-Post)
// reach the recipient untouched. isHTML toggles between text/html and
// text/plain content type.
func (p *sesAPIChainProvider) SendRaw(ctx context.Context, subject, body string, isHTML bool, to string, headers map[string]string) error {
	p.svc.AddReceivers(to)
	return p.svc.SendRaw(ctx, subject, body, isHTML, headers)
}

type sesSMTPChainProvider struct {
	svc *mail.Mail
}

func (p *sesSMTPChainProvider) ID() string { return ProviderSESSMTP }
func (p *sesSMTPChainProvider) Send(ctx context.Context, subject, body, to string) error {
	p.svc.AddReceivers(to)
	return p.svc.Send(ctx, subject, body)
}

type sendgridChainProvider struct {
	svc *sendgrid.SendGrid
}

func (p *sendgridChainProvider) ID() string { return ProviderSendGrid }
func (p *sendgridChainProvider) Send(ctx context.Context, subject, body, to string) error {
	p.svc.AddReceivers(to)
	return p.svc.Send(ctx, subject, body)
}

// Compile-time interface checks. Each adapter MUST satisfy
// ChainProvider; the notify.Notifier check is documentation that the
// wrapped service is a real Notifier and not a stub.
var (
	_ ChainProvider  = (*plivoChainProvider)(nil)
	_ ChainProvider  = (*twilioChainProvider)(nil)
	_ ChainProvider  = (*sesAPIChainProvider)(nil)
	_ ChainProvider  = (*sesSMTPChainProvider)(nil)
	_ ChainProvider  = (*sendgridChainProvider)(nil)

	// SES API is the only provider that exposes RawSender for now —
	// SendEmail cannot inject custom headers, so the raw-MIME path is
	// the only way for List-Unsubscribe to ride along.
	_ RawSender = (*sesAPIChainProvider)(nil)
	_ notify.Notifier = (*plivo.Service)(nil)
	_ notify.Notifier = (*twilio.Service)(nil)
	_ notify.Notifier = (*sendgrid.SendGrid)(nil)
	_ notify.Notifier = (*mail.Mail)(nil)

	// The notify.Notifier compile-time check for amazonses.AmazonSES
	// is here as documentation: the library exposes Send via a value
	// receiver so the pointer-receiver assignment is the right one.
	_ notify.Notifier = (*amazonses.AmazonSES)(nil)

	// _ keeps the smtp package imported — mail.AuthenticateSMTP wraps
	// smtp.PlainAuth internally, so a future move to TLS-only auth
	// must update this file too.
	_ = smtp.PlainAuth
)
