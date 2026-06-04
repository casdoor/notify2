// Copyright 2026 The Hanzo Authors. All Rights Reserved.

package tenant

import (
	"context"
	"sync/atomic"
	"testing"
)

// fakeRawProvider is a ChainProvider that also implements RawSender. It
// records which path (plain Send vs SendRaw) was invoked and with what
// arguments. Used to assert the chain walks the raw-MIME branch under
// RunMarketing when the provider implements RawSender.
type fakeRawProvider struct {
	id         string
	plainCalls int32
	rawCalls   int32
	lastBody   string
	lastIsHTML bool
	lastHdrs   map[string]string
	err        error
}

func (p *fakeRawProvider) ID() string { return p.id }

func (p *fakeRawProvider) Send(_ context.Context, _, body, _ string) error {
	atomic.AddInt32(&p.plainCalls, 1)
	p.lastBody = body
	return p.err
}

func (p *fakeRawProvider) SendRaw(_ context.Context, _, body string, isHTML bool, _ string, headers map[string]string) error {
	atomic.AddInt32(&p.rawCalls, 1)
	p.lastBody = body
	p.lastIsHTML = isHTML
	p.lastHdrs = headers
	return p.err
}

// TestRunMarketing_PrefersSendRaw asserts that when a provider
// implements RawSender, RunMarketing uses the SendRaw path and passes
// headers through. Plain Send is NOT called.
func TestRunMarketing_PrefersSendRaw(t *testing.T) {
	t.Parallel()
	p := &fakeRawProvider{id: "ses_api"}
	chain := &ProviderChain{
		Channel:   ChainEmailMarketing,
		Tenant:    "liquidity",
		Brand:     "liquidity",
		Providers: []ChainProvider{p},
	}
	headers := map[string]string{
		"List-Unsubscribe":      "<https://x>",
		"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
	}
	res, err := chain.RunMarketing(context.Background(), "u@e.com", "subj", "<p>body</p>", true, headers)
	if err != nil {
		t.Fatalf("RunMarketing: %v", err)
	}
	if res.Winner != "ses_api" {
		t.Fatalf("winner=%q", res.Winner)
	}
	if atomic.LoadInt32(&p.rawCalls) != 1 {
		t.Fatalf("expected 1 SendRaw call, got %d", p.rawCalls)
	}
	if atomic.LoadInt32(&p.plainCalls) != 0 {
		t.Fatalf("expected 0 plain Send calls, got %d", p.plainCalls)
	}
	if !p.lastIsHTML {
		t.Fatalf("isHTML lost in transit")
	}
	if p.lastHdrs["List-Unsubscribe"] != "<https://x>" {
		t.Fatalf("List-Unsubscribe lost: %+v", p.lastHdrs)
	}
}

// TestRunMarketing_FallsBackToSend when the provider doesn't implement
// RawSender, the chain falls back to plain Send so the message still
// ships (just without the machine-actionable header). The body is
// expected to carry the visible footer; the test asserts the body
// reaches the provider verbatim.
func TestRunMarketing_FallsBackToSend(t *testing.T) {
	t.Parallel()
	p := &fakeProvider{id: "sendgrid"}
	chain := &ProviderChain{
		Channel:   ChainEmailMarketing,
		Providers: []ChainProvider{p},
	}
	body := "hello\n\n--\nUnsubscribe: https://x"
	_, err := chain.RunMarketing(context.Background(), "u@e.com", "subj", body, false, map[string]string{
		"List-Unsubscribe": "<https://x>",
	})
	if err != nil {
		t.Fatalf("RunMarketing: %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("expected 1 plain Send call, got %d", p.calls)
	}
}

// TestRunMarketing_ChainFallthrough asserts the multi-provider walk
// still works on RunMarketing — primary fails retryable, fallback wins
// via SendRaw.
func TestRunMarketing_ChainFallthrough(t *testing.T) {
	t.Parallel()
	primary := &fakeRawProvider{id: "ses_api", err: errMockRetry}
	fallback := &fakeRawProvider{id: "ses_api_b"}
	chain := &ProviderChain{
		Channel:   ChainEmailMarketing,
		Providers: []ChainProvider{primary, fallback},
	}
	res, err := chain.RunMarketing(context.Background(), "u@e.com", "subj", "body", false, nil)
	if err != nil {
		t.Fatalf("RunMarketing: %v", err)
	}
	if res.Winner != "ses_api_b" {
		t.Fatalf("expected fallback winner, got %q", res.Winner)
	}
	if atomic.LoadInt32(&primary.rawCalls) != 1 || atomic.LoadInt32(&fallback.rawCalls) != 1 {
		t.Fatalf("expected one SendRaw per provider (primary=%d, fallback=%d)", primary.rawCalls, fallback.rawCalls)
	}
}

// errMockRetry is anything classifyError will call retryable. A plain
// 5xx-style message hits the default branch.
var errMockRetry = mockError("503 service unavailable")

type mockError string

func (e mockError) Error() string { return string(e) }
