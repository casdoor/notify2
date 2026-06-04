package tasks

import (
	"testing"
	"time"

	"github.com/hanzoai/notify/internal/marketing"
	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/unsubscribe"
)

// TestActivities_signMarketing_PersistsToken locks the two halves of
// the marketing path that don't depend on the chain: token signing and
// token persistence. The unsubscribe handler reads from the same
// notification_unsubscribe_tokens collection, so this is the link
// that lets a recipient click → server → mark consumed.
func TestActivities_signMarketing_PersistsToken(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	mustMakeTenant(t, app, "test-org")

	signer, err := unsubscribe.NewSigner("k")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	acts := NewActivities(app, nil).WithMarketing(&marketing.Config{
		Env:    "dev",
		Signer: signer,
	})

	in := SendInput{
		MessageID:  "m1",
		TenantSlug: "test-org",
		Channel:    "email",
		To:         "u@example.com",
		Subject:    "promo",
		Body:       "<p>hi</p>",
		Category:   marketing.CategoryPromotional,
		UserID:     "user-42",
		IsHTML:     true,
	}

	headers, footerURL, sigErr := acts.signMarketing(in)
	if sigErr != nil {
		t.Fatalf("signMarketing: %v", sigErr)
	}
	if headers[marketing.HeaderListUnsubscribe] == "" {
		t.Fatalf("List-Unsubscribe header missing: %+v", headers)
	}
	if headers[marketing.HeaderListUnsubscribePost] != "List-Unsubscribe=One-Click" {
		t.Fatalf("unexpected List-Unsubscribe-Post: %q", headers[marketing.HeaderListUnsubscribePost])
	}
	if footerURL == "" {
		t.Fatalf("expected non-empty footer URL")
	}

	// Token row must exist.
	token := extractToken(footerURL)
	if token == "" {
		t.Fatalf("could not extract token from %q", footerURL)
	}
	rec, err := app.FindRecordById(schema.UnsubscribeTokens, token)
	if err != nil || rec == nil {
		t.Fatalf("token row not persisted: %v (rec=%v)", err, rec)
	}
	if rec.GetString("user_id") != "user-42" {
		t.Fatalf("user_id mismatch: %q", rec.GetString("user_id"))
	}
	if rec.GetString("tenant") != "test-org" {
		t.Fatalf("tenant mismatch: %q", rec.GetString("tenant"))
	}
	if rec.GetString("category") != marketing.CategoryPromotional {
		t.Fatalf("category mismatch: %q", rec.GetString("category"))
	}

	// And the token must verify against the signer.
	if _, err := signer.Verify(token, time.Now().UTC()); err != nil {
		t.Fatalf("Verify minted token: %v", err)
	}
}

// TestActivities_signMarketing_Idempotent — re-signing for the same
// recipient/category yields a different token (signature carries a
// fresh expiry), but persisting the existing token a second time is
// a no-op rather than a unique-key violation.
func TestActivities_signMarketing_Idempotent(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	mustMakeTenant(t, app, "test-org")
	signer, _ := unsubscribe.NewSigner("k")
	acts := NewActivities(app, nil).WithMarketing(&marketing.Config{Signer: signer})

	in := SendInput{
		MessageID:  "m2",
		TenantSlug: "test-org",
		Channel:    "email",
		Category:   marketing.CategoryNewsletter,
		UserID:     "user-77",
	}

	_, url1, err := acts.signMarketing(in)
	if err != nil {
		t.Fatalf("signMarketing #1: %v", err)
	}
	tok1 := extractToken(url1)

	// Manually persist the same token a second time — must not error
	// (the persist path checks for existing row).
	if err := acts.persistToken(tok1, in, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("persistToken re-insert: %v", err)
	}
}

// TestShouldUseMarketing covers the three-gate decision matrix.
func TestShouldUseMarketing(t *testing.T) {
	t.Parallel()
	signer, _ := unsubscribe.NewSigner("k")
	cfg := &marketing.Config{Signer: signer}

	cases := []struct {
		name string
		cfg  *marketing.Config
		in   SendInput
		want bool
	}{
		{"nil cfg disables", nil, SendInput{Channel: "email", Category: "promotional"}, false},
		{"non-email channel", cfg, SendInput{Channel: "sms", Category: "promotional"}, false},
		{"transactional category", cfg, SendInput{Channel: "email", Category: ""}, false},
		{"otp category", cfg, SendInput{Channel: "email", Category: "iam.otp_sent"}, false},
		{"marketing + email", cfg, SendInput{Channel: "email", Category: "promotional"}, true},
		{"newsletter + email", cfg, SendInput{Channel: "email", Category: "newsletter"}, true},
		{"product_update + email", cfg, SendInput{Channel: "email", Category: "product_update"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Activities{marketingCfg: tc.cfg}
			if got := a.shouldUseMarketing(tc.in); got != tc.want {
				t.Errorf("shouldUseMarketing(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestExtractToken covers the URL → token suffix shim.
func TestExtractToken(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://notify.dev.satschel.com/v1/notify/unsubscribe/ABC123": "ABC123",
		"https://notify.satschel.com/v1/notify/unsubscribe/xyz":        "xyz",
		"https://example.com/no/match":                                  "",
		"":                                                              "",
	}
	for url, want := range cases {
		if got := extractToken(url); got != want {
			t.Errorf("extractToken(%q) = %q, want %q", url, got, want)
		}
	}
}

