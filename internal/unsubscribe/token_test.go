package unsubscribe

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestNewSignerEmptySecretRejected guards the fail-closed boot policy:
// notifyd MUST refuse to construct the signer without NOTIFY_UNSUBSCRIBE_SECRET.
func TestNewSignerEmptySecretRejected(t *testing.T) {
	t.Parallel()
	if _, err := NewSigner(""); err == nil {
		t.Fatalf("empty secret must be rejected")
	}
	if _, err := NewSigner("   "); err == nil {
		t.Fatalf("whitespace-only secret must be rejected")
	}
}

// TestSignVerifyRoundTrip is the canonical happy path: a freshly signed
// token verifies back to the same payload.
func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	s, err := NewSigner("test-secret-bytes")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	exp := now.Add(Default30Days)

	tok, err := s.Sign("user-abc", "promotional", exp)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tok == "" {
		t.Fatalf("Sign returned empty token")
	}
	got, err := s.Verify(tok, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.UserID != "user-abc" || got.Category != "promotional" {
		t.Fatalf("Verify returned %+v, want user_id=user-abc category=promotional", got)
	}
	if !got.ExpiresAt.Equal(exp.Truncate(time.Second)) {
		t.Fatalf("Verify ExpiresAt=%v, want %v", got.ExpiresAt, exp.Truncate(time.Second))
	}
}

// TestSignWithTTL is the convenience wrapper.
func TestSignWithTTL(t *testing.T) {
	t.Parallel()
	s, err := NewSigner("k")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	tok, err := s.SignWithTTL("u1", "", now, time.Hour)
	if err != nil {
		t.Fatalf("SignWithTTL: %v", err)
	}
	p, err := s.Verify(tok, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.UserID != "u1" || p.Category != "" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

// TestSignRejectsBadInput catches the input-validation rules.
func TestSignRejectsBadInput(t *testing.T) {
	t.Parallel()
	s, _ := NewSigner("k")
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

	if _, err := s.Sign("", "promotional", now.Add(time.Hour)); err == nil {
		t.Fatalf("empty user_id must be rejected")
	}
	if _, err := s.Sign("u|x", "promotional", now.Add(time.Hour)); err == nil {
		t.Fatalf("user_id containing fieldSep must be rejected")
	}
	if _, err := s.Sign("u1", "pro|mo", now.Add(time.Hour)); err == nil {
		t.Fatalf("category containing fieldSep must be rejected")
	}
	if _, err := s.Sign("u1", "promo", time.Time{}); err == nil {
		t.Fatalf("zero expires_at must be rejected")
	}
}

// TestVerifyRejectsBadInput covers the parser failure modes.
func TestVerifyRejectsBadInput(t *testing.T) {
	t.Parallel()
	s, _ := NewSigner("k")
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

	cases := []string{
		"",                          // empty
		"not-base64-!@#$",           // bad b64
		"AAAA",                       // too short (< macLen)
		strings.Repeat("A", 200),    // long but no valid HMAC over a parseable body
	}
	for _, in := range cases {
		_, err := s.Verify(in, now)
		if err == nil {
			t.Fatalf("Verify(%q) accepted, want error", in)
		}
	}
}

// TestVerifyRejectsWrongSecret is the security guarantee: a token signed
// under secret A cannot be verified under secret B.
func TestVerifyRejectsWrongSecret(t *testing.T) {
	t.Parallel()
	a, _ := NewSigner("secret-a")
	b, _ := NewSigner("secret-b")
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	tok, err := a.Sign("u1", "promotional", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := b.Verify(tok, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong secret should yield ErrInvalid, got %v", err)
	}
}

// TestVerifyDetectsTampering flips a bit in the payload and asserts the
// MAC catches it.
func TestVerifyDetectsTampering(t *testing.T) {
	t.Parallel()
	s, _ := NewSigner("k")
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	tok, err := s.Sign("u1", "promotional", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Flip the last byte (the timestamp portion of the payload).
	bad := tok[:len(tok)-1]
	if tok[len(tok)-1] != 'A' {
		bad += "A"
	} else {
		bad += "B"
	}
	if _, err := s.Verify(bad, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered token should yield ErrInvalid, got %v", err)
	}
}

// TestVerifyExpired covers the expiry path: a valid HMAC but
// expires_at in the past returns ErrExpired (distinct from ErrInvalid
// so the route can render a friendlier page).
func TestVerifyExpired(t *testing.T) {
	t.Parallel()
	s, _ := NewSigner("k")
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	tok, err := s.Sign("u1", "promotional", now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(tok, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token should yield ErrExpired, got %v", err)
	}
}

// TestSignNilReceiver guards the defensive nil check.
func TestSignNilReceiver(t *testing.T) {
	t.Parallel()
	var s *Signer
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	if _, err := s.Sign("u1", "p", now.Add(time.Hour)); err == nil {
		t.Fatalf("nil signer should reject Sign")
	}
	if _, err := s.Verify("anything", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil signer should reject Verify with ErrInvalid, got %v", err)
	}
}
