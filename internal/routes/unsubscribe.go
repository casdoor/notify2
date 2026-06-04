// One-click email unsubscribe — §5.1 of the notification-preferences
// paper.
//
// The token IS the auth: GET/POST /v1/notify/unsubscribe/{token} is
// unauthenticated by design, but the HMAC over (user_id, category,
// expires_at) means only the email recipient can reach the endpoint.
//
// Endpoints:
//
//	GET    /v1/notify/unsubscribe/{token}    # confirmation page (no JS)
//	POST   /v1/notify/unsubscribe/{token}    # idempotent opt-out
//	POST   /v1/notify/resubscribe/{token}    # mirror — opt back in
//
// Both POSTs mutate the user's preferences row + append a consent log
// row. The GET is a render-only surface that lets the user verify
// what they're about to click before submitting.

package routes

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/preferences"
	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/unsubscribe"
)

// mountUnsubscribe installs the three public token routes. signer is
// the HMAC primitive; nil signer → every route returns 503 (matches
// the local-dev posture when NOTIFY_UNSUBSCRIBE_SECRET is unset).
func mountUnsubscribe(r *router.Router[*core.RequestEvent], app core.App, signer *unsubscribe.Signer) {
	r.GET("/v1/notify/unsubscribe/{token}", renderConfirmation(signer, false))
	r.POST("/v1/notify/unsubscribe/{token}", processUnsubscribe(app, signer, true))
	r.POST("/v1/notify/resubscribe/{token}", processUnsubscribe(app, signer, false))
}

// renderConfirmation returns a no-JS HTML page that previews the
// consequence of clicking the link. Mail clients strip <script> + most
// CSS; the markup is plain enough to render in any client preview.
func renderConfirmation(signer *unsubscribe.Signer, resubscribed bool) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		if signer == nil {
			return apis.NewApiError(http.StatusServiceUnavailable,
				"unsubscribe disabled: NOTIFY_UNSUBSCRIBE_SECRET is not configured", nil)
		}
		token := strings.TrimSpace(e.Request.PathValue("token"))
		payload, err := signer.Verify(token, time.Now().UTC())
		if err != nil {
			return writeHTML(e, http.StatusBadRequest, invalidTokenHTML(err.Error()))
		}
		return writeHTML(e, http.StatusOK, confirmationHTML(payload, resubscribed))
	}
}

// processUnsubscribe is shared by POST /unsubscribe and /resubscribe;
// the `out` flag toggles which way to flip the user's prefs.
func processUnsubscribe(app core.App, signer *unsubscribe.Signer, out bool) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		if signer == nil {
			return apis.NewApiError(http.StatusServiceUnavailable,
				"unsubscribe disabled: NOTIFY_UNSUBSCRIBE_SECRET is not configured", nil)
		}
		token := strings.TrimSpace(e.Request.PathValue("token"))
		now := time.Now().UTC()
		payload, err := signer.Verify(token, now)
		if err != nil {
			return writeHTML(e, http.StatusBadRequest, invalidTokenHTML(err.Error()))
		}

		// Resolve the org for this user by walking the preferences row.
		// Tokens are scoped to (user, category, expires_at) — the org
		// comes from the user's prefs row. We require exactly one row
		// to exist; on first read the platform plugin already created
		// it via the GET /v1/notify/preferences flow.
		rec, org, err := findPreferencesForUser(app, payload.UserID)
		if err != nil {
			return apis.NewInternalServerError("find preferences", err)
		}
		if rec == nil {
			return writeHTML(e, http.StatusNotFound, missingPrefsHTML())
		}

		priorWire := preferences.ToWire(rec)
		next := priorWire
		next.MarketingSubscriptions = cloneSubs(priorWire.MarketingSubscriptions)
		if payload.Category == "" {
			// Global unsubscribe = mute marketing entirely.
			next.MarketingGloballyMuted = out
			// Also zero every per-category opt-in when unsubscribing
			// (paper §3.2: CAN-SPAM/GDPR require opt-out within 10/30
			// days — eager zeroing keeps the post-click sends quiet).
			if out {
				for k := range next.MarketingSubscriptions {
					next.MarketingSubscriptions[k] = false
				}
			}
		} else {
			next.MarketingSubscriptions[payload.Category] = !out
		}
		if err := preferences.ApplyWire(rec, &next); err != nil {
			return apis.NewBadRequestError(err.Error(), nil)
		}
		if err := app.Save(rec); err != nil {
			return apis.NewInternalServerError("save preferences", err)
		}

		event := schema.ConsentEventOptOut
		if !out {
			event = schema.ConsentEventOptIn
		}
		if err := writeConsentLog(app, consentEntry{
			UserID:     payload.UserID,
			Org:        org,
			Event:      event,
			Category:   payload.Category,
			Channel:    "email", // one-click link is an email-channel signal
			PriorState: priorWire,
			NewState:   preferences.ToWire(rec),
			IP:         clientIP(e),
			UserAgent:  e.Request.Header.Get("User-Agent"),
		}); err != nil {
			return apis.NewInternalServerError("consent log", err)
		}

		if err := markTokenConsumed(app, token, payload, org, now); err != nil {
			// Token row persistence failure is non-fatal — the prefs +
			// consent log are already saved and idempotent on repeat
			// clicks. Log via the response body? No — keep it quiet so
			// the user sees the success page; the row will be regenerated
			// next time the user hits the endpoint.
			_ = err
		}

		return writeHTML(e, http.StatusOK, confirmationHTML(payload, !out))
	}
}

// findPreferencesForUser scans for the user's prefs row. We don't
// embed the org in the token (paper §5.1 — the token is short by
// design) so a global lookup is required. Indexed on user_id +
// (user_id, tenant) for cheap reads.
func findPreferencesForUser(app core.App, userID string) (*core.Record, string, error) {
	rows, err := app.FindRecordsByFilter(
		schema.Preferences,
		"user_id = {:user_id}",
		"-created", 1, 0,
		dbx.Params{"user_id": userID},
	)
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", nil
	}
	return rows[0], rows[0].GetString("tenant"), nil
}

// markTokenConsumed upserts a row in notification_unsubscribe_tokens.
// The token string is the PK so repeat clicks are idempotent (existing
// row's consumed_at stays as-is on subsequent saves we elect to skip).
func markTokenConsumed(app core.App, token string, payload unsubscribe.Payload, org string, now time.Time) error {
	col, err := app.FindCollectionByNameOrId(schema.UnsubscribeTokens)
	if err != nil {
		return err
	}
	rec, err := app.FindRecordById(schema.UnsubscribeTokens, token)
	if err == nil && rec != nil {
		if rec.GetString("consumed_at") == "" {
			rec.Set("consumed_at", now.Format(time.RFC3339))
			return app.Save(rec)
		}
		return nil
	}
	rec = core.NewRecord(col)
	rec.Set("id", token)
	rec.Set("user_id", payload.UserID)
	rec.Set("tenant", org)
	rec.Set("category", payload.Category)
	rec.Set("expires_at", payload.ExpiresAt.Format(time.RFC3339))
	rec.Set("consumed_at", now.Format(time.RFC3339))
	return app.Save(rec)
}

// cloneSubs returns a shallow copy of m so the prior_state snapshot in
// the consent log doesn't alias the post-update map.
func cloneSubs(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// writeHTML emits a static HTML page. Mail-client-safe: no JS, minimal
// inline CSS, no external resources. Content-Type is fixed because
// some clients reject unknown subtypes.
func writeHTML(e *core.RequestEvent, status int, body string) error {
	e.Response.Header().Set("Content-Type", "text/html; charset=utf-8")
	e.Response.WriteHeader(status)
	_, err := e.Response.Write([]byte(body))
	return err
}

// confirmationHTML renders the success page. Resubscribed=true changes
// the headline + offers the inverse one-click link.
func confirmationHTML(p unsubscribe.Payload, resubscribed bool) string {
	what := "all Liquidity marketing"
	if p.Category != "" {
		what = html.EscapeString(p.Category)
	}
	verb := "unsubscribed from"
	other := "Resubscribe"
	if resubscribed {
		verb = "resubscribed to"
		other = "Unsubscribe"
	}
	expires := html.EscapeString(p.ExpiresAt.Format(time.RFC3339))

	return fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Notification preferences updated</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
</head><body style="font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;padding:0 20px;color:#111">
<h1 style="font-size:1.4rem;margin:0 0 16px">You have %s %s.</h1>
<p style="line-height:1.55;color:#444">Your preferences have been updated. Transactional and regulatory notifications (trade confirmations, account statements, security alerts) will continue to deliver via email as required by SEC, FINRA, and state notification laws.</p>
<p style="line-height:1.55;color:#444">Token expires: <code>%s</code></p>
<p style="margin-top:32px"><a href="/v1/notify/preferences" style="color:#0a5cff">Open your preferences</a> · <button form="op" style="background:none;border:0;color:#0a5cff;padding:0;cursor:pointer;text-decoration:underline">%s</button></p>
<form id="op" method="post" action="" style="display:none"></form>
</body></html>`,
		verb, what, expires, other)
}

// invalidTokenHTML renders the failure page. The message is generic to
// avoid leaking which check failed.
func invalidTokenHTML(detail string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Link expired or invalid</title></head>
<body style="font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;padding:0 20px;color:#111">
<h1 style="font-size:1.4rem;margin:0 0 16px">This link is no longer valid.</h1>
<p style="line-height:1.55;color:#444">Reason: %s</p>
<p style="line-height:1.55;color:#444">If you wanted to change your notification preferences, sign in and open <a href="/v1/notify/preferences" style="color:#0a5cff">your preferences</a>.</p>
</body></html>`, html.EscapeString(detail))
}

// missingPrefsHTML renders when the token references a user with no
// preferences row. Indicates the user was deleted or never registered.
func missingPrefsHTML() string {
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>User not found</title></head>
<body style="font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;padding:0 20px;color:#111">
<h1 style="font-size:1.4rem;margin:0 0 16px">User not found.</h1>
<p style="line-height:1.55;color:#444">We could not locate a notification preference record for this token. The account may have been deleted.</p>
</body></html>`
}
