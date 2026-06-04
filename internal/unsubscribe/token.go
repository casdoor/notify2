// Package unsubscribe is the HMAC-signed token primitive that backs
// the one-click email unsubscribe endpoints from §5.1 of the
// notification-preferences paper.
//
// Token shape (base64url, no padding):
//
//	body = user_id || "|" || category || "|" || expires_at_unix
//	mac  = HMAC-SHA256(NOTIFY_UNSUBSCRIBE_SECRET, body)
//	tok  = base64url(mac || body)
//
// The first 32 bytes of the decoded token are the MAC; the rest is the
// plaintext payload. Verification recomputes the MAC over the payload
// and constant-time-compares against the prefix. A consumed-state
// check is layered on top via the notification_unsubscribe_tokens
// collection — Sign+Verify are pure (no DB).
//
// Why not JWT: every byte counts in a URL that has to fit in mail
// clients' wrap rules and in the SMS-like List-Unsubscribe-Post space.
// HMAC + a 3-field tuple is the smallest thing that works.
package unsubscribe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// macLen is the SHA-256 digest size in bytes. The token's first macLen
// bytes are the MAC; everything after is the payload.
const macLen = sha256.Size

// fieldSep separates the three payload fields. Pipe is illegal in
// user_id (kebab/uuid) and category (snake_case) so it cleanly delimits.
const fieldSep = "|"

// Default30Days is the standard expiry window — CAN-SPAM requires
// processing within 10 business days, GDPR within 30; the paper §5.1
// pins 30 days.
const Default30Days = 30 * 24 * time.Hour

// Payload is the verified inner state. Empty Category means "unsubscribe
// from all marketing"; the paper §5.1 + the consent-log schema use ""
// for the global-unsub case.
type Payload struct {
	UserID    string
	Category  string
	ExpiresAt time.Time
}

// Signer constructs and verifies tokens with a secret key. The key
// comes from NOTIFY_UNSUBSCRIBE_SECRET — fail-closed boot if missing in
// production mode.
type Signer struct {
	secret []byte
}

// NewSigner returns a Signer for the given secret. Empty secret is
// rejected — every caller should resolve this from env at boot.
func NewSigner(secret string) (*Signer, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("unsubscribe: NOTIFY_UNSUBSCRIBE_SECRET is required")
	}
	return &Signer{secret: []byte(secret)}, nil
}

// Sign returns a base64url token for (userID, category, expiresAt).
// expiresAt is truncated to second precision because the token carries
// a unix timestamp.
func (s *Signer) Sign(userID, category string, expiresAt time.Time) (string, error) {
	if s == nil {
		return "", errors.New("unsubscribe: nil signer")
	}
	if strings.TrimSpace(userID) == "" {
		return "", errors.New("unsubscribe: user_id is required")
	}
	if strings.ContainsAny(userID, fieldSep) {
		return "", fmt.Errorf("unsubscribe: user_id may not contain %q", fieldSep)
	}
	if strings.ContainsAny(category, fieldSep) {
		return "", fmt.Errorf("unsubscribe: category may not contain %q", fieldSep)
	}
	if expiresAt.IsZero() {
		return "", errors.New("unsubscribe: expiresAt is required")
	}
	payload := userID + fieldSep + category + fieldSep + strconv.FormatInt(expiresAt.Unix(), 10)
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(payload))
	mac := h.Sum(nil)
	buf := make([]byte, 0, len(mac)+len(payload))
	buf = append(buf, mac...)
	buf = append(buf, []byte(payload)...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SignWithTTL is a convenience that signs a token expiring `ttl` from
// now. now is injectable for tests.
func (s *Signer) SignWithTTL(userID, category string, now time.Time, ttl time.Duration) (string, error) {
	return s.Sign(userID, category, now.Add(ttl))
}

// Verify decodes + authenticates a token. Returns the verified Payload
// or an error explaining the failure mode.
//
// Errors are intentionally non-leaking — they say "invalid" or
// "expired" without dumping the parsed payload, so a brute-force
// attacker learns no internal state.
func (s *Signer) Verify(token string, now time.Time) (Payload, error) {
	if s == nil {
		return Payload{}, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return Payload{}, ErrInvalid
	}
	if len(raw) <= macLen {
		return Payload{}, ErrInvalid
	}
	mac := raw[:macLen]
	body := raw[macLen:]

	h := hmac.New(sha256.New, s.secret)
	h.Write(body)
	expected := h.Sum(nil)
	if !hmac.Equal(mac, expected) {
		return Payload{}, ErrInvalid
	}

	// Split the body. We require EXACTLY three fields. Splitting on
	// the LAST `fieldSep` once for the timestamp would silently accept
	// pipes in user_id; instead we hard-bound the field count.
	parts := strings.Split(string(body), fieldSep)
	if len(parts) != 3 {
		return Payload{}, ErrInvalid
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return Payload{}, ErrInvalid
	}
	expiresAt := time.Unix(exp, 0).UTC()
	if !expiresAt.After(now) {
		return Payload{}, ErrExpired
	}
	return Payload{
		UserID:    parts[0],
		Category:  parts[1],
		ExpiresAt: expiresAt,
	}, nil
}

// ErrInvalid is returned for any failed decode / HMAC mismatch / bad
// payload shape. Generic by design.
var ErrInvalid = errors.New("unsubscribe: invalid token")

// ErrExpired is returned for tokens whose ExpiresAt is in the past.
// Distinct from ErrInvalid so the route can render a "this link
// expired" page rather than a generic error.
var ErrExpired = errors.New("unsubscribe: token expired")
