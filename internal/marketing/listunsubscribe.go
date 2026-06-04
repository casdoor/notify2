// Package marketing builds the List-Unsubscribe + List-Unsubscribe-Post
// header pair that every marketing-class email carries per §5 of the
// notification-preferences paper.
//
// Callers (the eventual marketing send path) construct a Headers struct
// with a freshly signed token and pass it to the email builder. The
// builder writes both headers verbatim into the outbound message so
// Gmail / Apple Mail / Outlook show the native "Unsubscribe" button.
//
// This is a pure header-construction package: no IO, no DB. Token
// signing happens at the call site so callers can reuse the same
// signer the unsubscribe routes use.
package marketing

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hanzoai/notify/internal/unsubscribe"
)

// HeaderListUnsubscribe and HeaderListUnsubscribePost are the canonical
// RFC 8058 + RFC 2369 header names. Exported so callers can use the
// same constants when injecting into outbound messages.
const (
	HeaderListUnsubscribe     = "List-Unsubscribe"
	HeaderListUnsubscribePost = "List-Unsubscribe-Post"
)

// Headers is the rendered name/value pair for the two RFC 8058 headers.
// Value strings are header-safe (CRLF-free).
type Headers struct {
	ListUnsubscribe     string
	ListUnsubscribePost string
	URL                 string // the HTTPS unsubscribe URL (also in the footer link)
}

// Config is what the caller has to know to build the headers. Env is
// the env-specific subdomain segment ("dev", "test", or "" for prod →
// notify.satschel.com).
type Config struct {
	// Env is dev/test/main/"" (empty == production). Affects the
	// HTTPS hostname only — the mailto bridge is one address per
	// fleet because notify.satschel.com proxies inbound to all envs.
	Env string

	// Signer mints the token. Shared with the unsubscribe routes so
	// emitted links validate at the receive endpoint.
	Signer *unsubscribe.Signer

	// MailtoDomain is the inbound MX-served domain for the mailto:
	// alternative header. Defaults to "notify.satschel.com" when empty.
	MailtoDomain string

	// HTTPSHost overrides the computed notify.{env}.satschel.com host.
	// Used by self-hosted deployments and integration tests.
	HTTPSHost string
}

// Build returns the rendered Headers for (userID, category, ttl). The
// token expires `ttl` from `now`; pass time.Now().UTC() and
// unsubscribe.Default30Days for the canonical 30-day window.
func (c Config) Build(userID, category string, now time.Time, ttl time.Duration) (Headers, error) {
	if c.Signer == nil {
		return Headers{}, fmt.Errorf("marketing: signer is required")
	}
	token, err := c.Signer.SignWithTTL(userID, category, now, ttl)
	if err != nil {
		return Headers{}, fmt.Errorf("marketing: sign token: %w", err)
	}
	host := c.HTTPSHost
	if host == "" {
		host = "notify." + envSegment(c.Env) + "satschel.com"
	}
	mailto := c.MailtoDomain
	if mailto == "" {
		mailto = "notify.satschel.com"
	}

	httpsURL := "https://" + host + "/v1/notify/unsubscribe/" + url.PathEscape(token)
	mailtoURL := "mailto:unsubscribe+" + url.PathEscape(token) + "@" + mailto

	return Headers{
		ListUnsubscribe:     "<" + httpsURL + ">, <" + mailtoURL + ">",
		ListUnsubscribePost: "List-Unsubscribe=One-Click",
		URL:                 httpsURL,
	}, nil
}

// FooterLine is the human-visible "Unsubscribe" link at the bottom of
// the marketing email body. Callers append this verbatim to the body
// text/html. CAN-SPAM §5.A.5 — "clear and conspicuous notice".
func (h Headers) FooterLine() string {
	return "Unsubscribe: " + h.URL
}

// envSegment returns the {env}. URL segment including the trailing
// dot. Production (empty Env) returns empty so the host collapses to
// notify.satschel.com — no double dot, no /main/ noise.
func envSegment(env string) string {
	env = strings.ToLower(strings.TrimSpace(env))
	switch env {
	case "", "main", "prod", "production":
		return ""
	}
	return env + "."
}
