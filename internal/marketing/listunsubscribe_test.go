package marketing

import (
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/notify/internal/unsubscribe"
)

func TestBuildHeaders(t *testing.T) {
	t.Parallel()
	signer, err := unsubscribe.NewSigner("test-secret")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cfg := Config{Env: "dev", Signer: signer}
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	h, err := cfg.Build("u1", "promotional", now, unsubscribe.Default30Days)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.HasPrefix(h.URL, "https://notify.dev.satschel.com/v1/notify/unsubscribe/") {
		t.Fatalf("unexpected URL host: %s", h.URL)
	}
	if !strings.Contains(h.ListUnsubscribe, "<"+h.URL+">") {
		t.Fatalf("List-Unsubscribe missing HTTPS URL: %s", h.ListUnsubscribe)
	}
	if !strings.Contains(h.ListUnsubscribe, "mailto:unsubscribe+") {
		t.Fatalf("List-Unsubscribe missing mailto: %s", h.ListUnsubscribe)
	}
	if h.ListUnsubscribePost != "List-Unsubscribe=One-Click" {
		t.Fatalf("unexpected List-Unsubscribe-Post: %s", h.ListUnsubscribePost)
	}
}

func TestBuildHeadersProdHost(t *testing.T) {
	t.Parallel()
	signer, _ := unsubscribe.NewSigner("k")
	for _, env := range []string{"", "main", "prod", "production"} {
		cfg := Config{Env: env, Signer: signer}
		h, err := cfg.Build("u1", "", time.Now().UTC(), unsubscribe.Default30Days)
		if err != nil {
			t.Fatalf("Build(%q): %v", env, err)
		}
		if !strings.HasPrefix(h.URL, "https://notify.satschel.com/") {
			t.Fatalf("env=%q: want notify.satschel.com host, got %s", env, h.URL)
		}
	}
}

func TestBuildHeadersTokenRoundTrip(t *testing.T) {
	t.Parallel()
	signer, _ := unsubscribe.NewSigner("k")
	cfg := Config{Env: "test", Signer: signer}
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	h, err := cfg.Build("user-42", "newsletter", now, time.Hour)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Pull the token out of the URL and verify it.
	tok := strings.TrimPrefix(h.URL, "https://notify.test.satschel.com/v1/notify/unsubscribe/")
	p, err := signer.Verify(tok, now)
	if err != nil {
		t.Fatalf("Verify minted token: %v", err)
	}
	if p.UserID != "user-42" || p.Category != "newsletter" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestBuildHeadersNilSigner(t *testing.T) {
	t.Parallel()
	cfg := Config{}
	if _, err := cfg.Build("u1", "", time.Now().UTC(), time.Hour); err == nil {
		t.Fatalf("nil signer should yield error")
	}
}

func TestFooterLine(t *testing.T) {
	t.Parallel()
	h := Headers{URL: "https://notify.satschel.com/v1/notify/unsubscribe/abc"}
	want := "Unsubscribe: https://notify.satschel.com/v1/notify/unsubscribe/abc"
	if h.FooterLine() != want {
		t.Fatalf("FooterLine = %q, want %q", h.FooterLine(), want)
	}
}
