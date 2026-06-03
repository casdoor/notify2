// Copyright 2026 The Hanzo Authors. All Rights Reserved.

package tenant

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProvider is the minimal ChainProvider for unit-testing the chain
// walker. Each test wires one of these per slot in the chain with the
// behavior it wants (success, retryable failure, terminal failure,
// hang).
type fakeProvider struct {
	id      string
	err     error
	delay   time.Duration
	calls   int32
}

func (p *fakeProvider) ID() string { return p.id }

func (p *fakeProvider) Send(ctx context.Context, subject, body, to string) error {
	atomic.AddInt32(&p.calls, 1)
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return p.err
}

// TestRun_PrimaryWins covers the happy path: the first provider in the
// chain succeeds, the walker returns immediately, no fallback is
// consulted. This is the >99% case in production — making it boring
// here keeps the dashboard clean.
func TestRun_PrimaryWins(t *testing.T) {
	t.Parallel()

	primary := &fakeProvider{id: "plivo"}
	fallback := &fakeProvider{id: "twilio"}
	chain := &ProviderChain{
		Channel:   ChainSMS,
		Tenant:    "liquidity",
		Brand:     "liquidity",
		Providers: []ChainProvider{primary, fallback},
	}

	res, err := chain.Run(context.Background(), "+15555550100", "subj", "body")
	if err != nil {
		t.Fatalf("Run returned error on happy path: %v", err)
	}
	if res.Winner != "plivo" {
		t.Errorf("Winner = %q, want plivo", res.Winner)
	}
	if got := atomic.LoadInt32(&primary.calls); got != 1 {
		t.Errorf("primary calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&fallback.calls); got != 0 {
		t.Errorf("fallback calls = %d, want 0 (primary won, no fallback)", got)
	}
	if len(res.Attempts) != 1 {
		t.Fatalf("Attempts = %d, want 1", len(res.Attempts))
	}
	if res.Attempts[0].Outcome != "ok" {
		t.Errorf("Attempts[0].Outcome = %q, want ok", res.Attempts[0].Outcome)
	}
	// Duration is observed via time.Since which is monotonic but can
	// report 0ns on fast hardware where the call completes inside
	// timer resolution. Just verify it's not negative.
	if res.Attempts[0].Duration < 0 {
		t.Errorf("Attempts[0].Duration = %v, want >= 0", res.Attempts[0].Duration)
	}
}

// TestRun_PrimaryFails_FallbackWins covers the >99.5%-delivery goal:
// primary trips a retryable error (5xx, transport reset, timeout),
// fallback succeeds. Both providers MUST be called; the winner is the
// fallback id.
func TestRun_PrimaryFails_FallbackWins(t *testing.T) {
	t.Parallel()

	primary := &fakeProvider{id: "plivo", err: errors.New("plivo 502 bad gateway")}
	fallback := &fakeProvider{id: "twilio"}
	chain := &ProviderChain{
		Channel:   ChainSMS,
		Tenant:    "hanzo",
		Brand:     "hanzo",
		Providers: []ChainProvider{primary, fallback},
	}

	res, err := chain.Run(context.Background(), "+15555550100", "subj", "body")
	if err != nil {
		t.Fatalf("Run returned error when fallback won: %v", err)
	}
	if res.Winner != "twilio" {
		t.Errorf("Winner = %q, want twilio", res.Winner)
	}
	if got := atomic.LoadInt32(&primary.calls); got != 1 {
		t.Errorf("primary calls = %d, want 1 (must have been tried)", got)
	}
	if got := atomic.LoadInt32(&fallback.calls); got != 1 {
		t.Errorf("fallback calls = %d, want 1", got)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %d, want 2", len(res.Attempts))
	}
	if res.Attempts[0].Outcome != "retryable" {
		t.Errorf("Attempts[0].Outcome = %q, want retryable", res.Attempts[0].Outcome)
	}
	if res.Attempts[0].Error == "" {
		t.Errorf("Attempts[0].Error empty — must carry primary's error message")
	}
	if res.Attempts[1].Outcome != "ok" {
		t.Errorf("Attempts[1].Outcome = %q, want ok", res.Attempts[1].Outcome)
	}
}

// TestRun_BothFail covers the chain-exhausted error path. Both
// providers fail with retryable errors; the chain returns a ChainError
// whose Reason is "exhausted" and whose Cause is the last error.
func TestRun_BothFail(t *testing.T) {
	t.Parallel()

	primary := &fakeProvider{id: "plivo", err: errors.New("plivo 502")}
	fallback := &fakeProvider{id: "twilio", err: errors.New("twilio connection refused")}
	chain := &ProviderChain{
		Channel:   ChainSMS,
		Tenant:    "zoo",
		Brand:     "zoo",
		Providers: []ChainProvider{primary, fallback},
	}

	res, err := chain.Run(context.Background(), "+15555550100", "subj", "body")
	if err == nil {
		t.Fatalf("Run returned nil error when every provider failed")
	}
	var chainErr *ChainError
	if !errors.As(err, &chainErr) {
		t.Fatalf("err = %T %v, want *ChainError", err, err)
	}
	if chainErr.Reason != "exhausted" {
		t.Errorf("Reason = %q, want exhausted", chainErr.Reason)
	}
	if !strings.Contains(chainErr.Error(), "twilio connection refused") {
		t.Errorf("ChainError.Error() = %q, want it to mention the last cause (twilio connection refused)", chainErr.Error())
	}
	if res.Winner != "" {
		t.Errorf("Winner = %q, want empty (no provider succeeded)", res.Winner)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %d, want 2 (every provider was tried)", len(res.Attempts))
	}
	if got := atomic.LoadInt32(&primary.calls); got != 1 {
		t.Errorf("primary calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&fallback.calls); got != 1 {
		t.Errorf("fallback calls = %d, want 1", got)
	}
}

// TestRun_TerminalRejection_NoFallback documents the short-circuit
// path: when the primary returns an error classified as terminal
// (invalid recipient, blocklist, 4xx), the chain MUST NOT try the
// fallback. Retrying against another provider would just burn money
// and could trigger anti-fraud rules (carriers rate-limit per dest).
func TestRun_TerminalRejection_NoFallback(t *testing.T) {
	t.Parallel()

	primary := &fakeProvider{id: "plivo", err: errors.New("invalid 'To' phone number: +15550000000")}
	fallback := &fakeProvider{id: "twilio"}
	chain := &ProviderChain{
		Channel:   ChainSMS,
		Tenant:    "liquidity",
		Brand:     "liquidity",
		Providers: []ChainProvider{primary, fallback},
	}

	res, err := chain.Run(context.Background(), "+15550000000", "subj", "body")
	if err == nil {
		t.Fatalf("Run returned nil on terminal error — must surface")
	}
	var chainErr *ChainError
	if !errors.As(err, &chainErr) {
		t.Fatalf("err = %T %v, want *ChainError", err, err)
	}
	if chainErr.Reason != "terminal" {
		t.Errorf("Reason = %q, want terminal", chainErr.Reason)
	}
	if res.Winner != "" {
		t.Errorf("Winner = %q, want empty on terminal rejection", res.Winner)
	}
	if got := atomic.LoadInt32(&primary.calls); got != 1 {
		t.Errorf("primary calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&fallback.calls); got != 0 {
		t.Errorf("fallback calls = %d, want 0 (terminal — no retry)", got)
	}
	if len(res.Attempts) != 1 {
		t.Fatalf("Attempts = %d, want 1 (no fallback attempt)", len(res.Attempts))
	}
	if res.Attempts[0].Outcome != "terminal" {
		t.Errorf("Attempts[0].Outcome = %q, want terminal", res.Attempts[0].Outcome)
	}
}

// TestRun_EmptyChain returns ErrNoProviders without crashing. A chain
// can be empty when every provider failed to construct (missing KMS
// secrets at every slot, including the Liquidity fallback). Surfacing
// this as a distinct error lets callers return 503 — that's a config
// problem, not a provider failure.
func TestRun_EmptyChain(t *testing.T) {
	t.Parallel()

	chain := &ProviderChain{
		Channel:   ChainSMS,
		Tenant:    "lux",
		Brand:     "lux",
		Providers: nil,
	}
	_, err := chain.Run(context.Background(), "+15555550100", "subj", "body")
	if err == nil {
		t.Fatalf("Run returned nil on empty chain")
	}
	if !errors.Is(err, ErrNoProviders) {
		t.Errorf("err = %v, want ErrNoProviders", err)
	}
}

// TestRun_ParentContextCanceled hands a pre-canceled context to Run.
// The chain MUST notice and bail out — every provider attempt would
// fail with ctx.Err anyway, but we want the first attempt to short-
// circuit so we don't pay one full attempt's roundtrip just to learn
// the context is dead.
func TestRun_ParentContextCanceled(t *testing.T) {
	t.Parallel()

	primary := &fakeProvider{id: "plivo"}
	fallback := &fakeProvider{id: "twilio"}
	chain := &ProviderChain{
		Channel:   ChainSMS,
		Tenant:    "liquidity",
		Brand:     "liquidity",
		Providers: []ChainProvider{primary, fallback},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := chain.Run(ctx, "+15555550100", "subj", "body")
	if err == nil {
		t.Fatalf("Run returned nil on canceled context")
	}
	// At least one attempt was logged with the cancellation reason; we
	// do not require zero attempts because the chain's outer ctx is
	// derived from the parent inside Run.
	if atomic.LoadInt32(&primary.calls)+atomic.LoadInt32(&fallback.calls) > 1 {
		t.Errorf("multiple providers called on canceled context — must short-circuit after first")
	}
}

// TestClassifyError validates the terminal-vs-retryable taxonomy. Each
// row documents what the upstream SDKs surface and what we want the
// chain to do with it. New error patterns from real production land
// here first, then in classifyError.
func TestClassifyError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want errClass
	}{
		{"nil", nil, errRetryable},
		{"transport reset", errors.New("connection reset by peer"), errRetryable},
		{"5xx", errors.New("plivo: status 502 bad gateway"), errRetryable},
		{"context deadline", context.DeadlineExceeded, errRetryable},
		{"context canceled", context.Canceled, errRetryable},
		{"invalid number", errors.New("invalid number"), errTerminal},
		{"invalid recipient", errors.New("twilio: invalid recipient"), errTerminal},
		{"twilio 21211", errors.New("error 21211: invalid 'To'"), errTerminal},
		{"twilio 21610 blocked", errors.New("error 21610: blocked"), errTerminal},
		{"blacklist", errors.New("phone on blacklist"), errTerminal},
		{"suppressed", errors.New("address suppressed"), errTerminal},
		{"unsubscribed", errors.New("recipient unsubscribed"), errTerminal},
		{"4xx unauthorized", errors.New("status 401 unauthorized"), errTerminal},
		{"4xx forbidden", errors.New("status 403 forbidden"), errTerminal},
		{"ses message rejected", errors.New("MessageRejected: Email address is not verified"), errTerminal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := classifyError(tt.err)
			if got != tt.want {
				t.Errorf("classifyError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestCanonicalChannel checks the alias resolution. Callers may pass
// the wire-level Channel string ("sms", "email") or the fine-grained
// chain channel ("email_otp"); both should resolve to a known value.
func TestCanonicalChannel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want ChainChannel
	}{
		{"sms", ChainSMS},
		{"SMS", ChainSMS},
		{"email", ChainEmailTxn},
		{"EMAIL", ChainEmailTxn},
		{"email_txn", ChainEmailTxn},
		{"email_otp", ChainEmailOTP},
		{"email_marketing", ChainEmailMarketing},
		{" sms ", ChainSMS},
		{"", ""},
		{"voice", ""}, // unsupported channel — caller must fall back to single-provider path
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got := canonicalChannel(tt.in)
			if got != tt.want {
				t.Errorf("canonicalChannel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestDefaultChainFor pins the default chain order. The list is part
// of the wire contract with ops dashboards ("if you see SES SMTP
// winning email_txn sends, SES API is having a bad day") — changes
// land here on purpose.
func TestDefaultChainFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ch   ChainChannel
		want []string
	}{
		{ChainSMS, []string{ProviderPlivo, ProviderTwilio}},
		{ChainEmailTxn, []string{ProviderSESAPI, ProviderSESSMTP}},
		{ChainEmailOTP, []string{ProviderSESSMTP, ProviderSESAPI}},
		{ChainEmailMarketing, []string{ProviderSendGrid, ProviderSESAPI}},
		{"", nil},
	}
	for _, tt := range tests {
		t.Run(string(tt.ch), func(t *testing.T) {
			t.Parallel()
			got := DefaultChainFor(tt.ch)
			if !equalSlice(got, tt.want) {
				t.Errorf("DefaultChainFor(%q) = %v, want %v", tt.ch, got, tt.want)
			}
		})
	}
}

// TestKnownProvider documents the set of provider ids the resolver
// will build. A new id MUST land here at the same time as its
// buildProvider branch; otherwise a brand override that names the new
// id silently filters it out.
func TestKnownProvider(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		ProviderPlivo:    true,
		ProviderTwilio:   true,
		ProviderSESAPI:   true,
		ProviderSESSMTP:  true,
		ProviderSendGrid: true,
		"":               false,
		"mailgun":        false, // library has it but chain doesn't build it yet
	}
	for id, want := range want {
		if got := knownProvider(id); got != want {
			t.Errorf("knownProvider(%q) = %v, want %v", id, got, want)
		}
	}
}

// TestChainError_Unwrap wires the wrapped cause through errors.Is /
// errors.As so callers can still detect specific upstream errors
// (e.g. context.DeadlineExceeded) without having to type-switch on
// *ChainError.
func TestChainError_Unwrap(t *testing.T) {
	t.Parallel()
	cause := errors.New("upstream blew up")
	wrapped := &ChainError{Cause: cause, Reason: "exhausted"}
	if !errors.Is(wrapped, cause) {
		t.Errorf("errors.Is did not unwrap to cause")
	}
	if msg := wrapped.Error(); msg == "" {
		t.Errorf("Error() returned empty string")
	}
	// The nil-receiver branch must not panic and must return a non-
	// empty sentinel so log lines never show an empty error string.
	var nilErr *ChainError
	if got := nilErr.Error(); got == "" {
		t.Errorf("nil receiver Error() returned empty — must return a sentinel")
	}
	if got := nilErr.Unwrap(); got != nil {
		t.Errorf("nil receiver Unwrap() = %v, want nil", got)
	}
}

// equalSlice is a small helper rather than importing reflect — the
// test signal is clearer when the comparison is explicit.
func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRun_ConcurrentSafe documents that a single ProviderChain can be
// invoked concurrently from multiple goroutines. The chain is
// stateless (the providers it wraps own all the state); the test
// double here is, too — so successful concurrent runs prove the
// walker's invariants hold under parallelism.
func TestRun_ConcurrentSafe(t *testing.T) {
	t.Parallel()

	primary := &fakeProvider{id: "plivo"}
	chain := &ProviderChain{
		Channel:   ChainSMS,
		Tenant:    "liquidity",
		Brand:     "liquidity",
		Providers: []ChainProvider{primary},
	}

	var wg sync.WaitGroup
	const goroutines = 50
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := chain.Run(context.Background(), "+15555550100", "subj", "body")
			if err != nil {
				t.Errorf("concurrent Run failed: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&primary.calls); got != goroutines {
		t.Errorf("primary.calls = %d, want %d (every goroutine reached primary)", got, goroutines)
	}
}
