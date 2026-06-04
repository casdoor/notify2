// STOP keyword webhook — §5.2 of the notification-preferences paper.
//
// One endpoint handles Plivo + Twilio inbound webhooks because both
// providers post the same logical payload (from-number, body) just with
// different field names. We parse both shapes; the route doesn't care
// which provider hit it.
//
// On STOP / UNSUBSCRIBE / QUIT / CANCEL / END (case-insensitive):
//
//	1. Look up the user by primary_phone (E.164-normalised).
//	2. Set marketing_globally_muted = true and zero every marketing
//	   subscription.
//	3. Append a consent_log row (event=opt_out, channel=sms).
//	4. Return TwiML / Plivo XML acking the message; the worker tier's
//	   outbound layer sends the confirmation SMS via the existing
//	   provider chain (we never block on the outbound send here).

package routes

import (
	"net/http"
	"strings"
	"time"

	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/preferences"
	"github.com/hanzoai/notify/internal/schema"
)

// stopKeywords is the exact set the TCPA + carrier-best-practice docs
// say a marketing SMS must honour. We match the entire body trimmed of
// whitespace — partial-match would catch "stop talking to me" too which
// would over-trigger.
var stopKeywords = map[string]struct{}{
	"STOP":        {},
	"UNSUBSCRIBE": {},
	"QUIT":        {},
	"CANCEL":      {},
	"END":         {},
}

// inboundSMSPayload is the parsed common shape. Plivo posts From + Text;
// Twilio posts From + Body — we read both keys so one handler covers
// both providers.
type inboundSMSPayload struct {
	From string `json:"from"`
	Body string `json:"body"`
}

// mountSMSInbound installs the Plivo + Twilio webhook. The handler
// accepts form-encoded (both providers' default) AND JSON (test
// harnesses) so the same route serves dev + prod.
func mountSMSInbound(r *router.Router[*core.RequestEvent], app core.App) {
	r.POST("/v1/notify/sms-inbound", func(e *core.RequestEvent) error {
		payload, err := parseInboundSMS(e)
		if err != nil {
			return apis.NewBadRequestError(err.Error(), nil)
		}
		// Normalise the keyword: providers preserve case + may include
		// trailing punctuation. We strip both.
		kw := strings.ToUpper(strings.TrimSpace(strings.Trim(payload.Body, ".!?")))
		if _, hit := stopKeywords[kw]; !hit {
			// Non-keyword inbound is logged-and-acked; we don't dump
			// inbound text into prefs ever. Return 200 so the provider
			// doesn't retry — there is nothing for notify to do.
			return e.JSON(http.StatusOK, map[string]string{"status": "ignored"})
		}

		from := normalizeE164(payload.From)
		if from == "" {
			// Provider sent us garbage — ack so they don't retry, log a
			// hint in the body for ops.
			return e.JSON(http.StatusOK, map[string]string{
				"status": "ignored",
				"reason": "missing or non-E.164 from",
			})
		}

		rec, err := findPreferencesByPhone(app, from)
		if err != nil {
			return apis.NewInternalServerError("lookup user by phone", err)
		}
		if rec == nil {
			// No matching user — dead-letter by acking; ops looks at
			// the inbound provider logs to find the orphan number.
			return e.JSON(http.StatusOK, map[string]string{
				"status": "ignored",
				"reason": "no user for phone",
			})
		}

		priorWire := preferences.ToWire(rec)
		next := priorWire
		next.MarketingGloballyMuted = true
		next.MarketingSubscriptions = cloneSubs(priorWire.MarketingSubscriptions)
		for k := range next.MarketingSubscriptions {
			next.MarketingSubscriptions[k] = false
		}
		if err := preferences.ApplyWire(rec, &next); err != nil {
			return apis.NewInternalServerError(err.Error(), nil)
		}
		if err := app.Save(rec); err != nil {
			return apis.NewInternalServerError("save preferences", err)
		}
		if err := writeConsentLog(app, consentEntry{
			UserID:     rec.GetString("user_id"),
			Org:        rec.GetString("tenant"),
			Event:      schema.ConsentEventOptOut,
			Category:   "", // global
			Channel:    "sms",
			PriorState: priorWire,
			NewState:   preferences.ToWire(rec),
			IP:         clientIP(e),
			UserAgent:  e.Request.Header.Get("User-Agent"),
		}); err != nil {
			return apis.NewInternalServerError("consent log", err)
		}

		// Return a confirmation reply via TwiML/Plivo XML. Both
		// providers accept the same Twilio-style <Response><Message>…
		// envelope when the response content type is text/xml; we
		// emit that shape so a single response satisfies both.
		body := `<?xml version="1.0" encoding="UTF-8"?>
<Response><Message>You have unsubscribed from Liquidity.io marketing SMS. Reply START to resubscribe.</Message></Response>`
		e.Response.Header().Set("Content-Type", "text/xml; charset=utf-8")
		e.Response.WriteHeader(http.StatusOK)
		_, err = e.Response.Write([]byte(body))
		_ = time.Now // explicit import keep — see comment in preferences.go
		return err
	})
}

// parseInboundSMS handles both form-encoded webhooks (the default for
// Plivo + Twilio) and JSON (test harnesses + future webhook variants).
// We coerce to lowercase keys so case differences across providers
// don't matter.
func parseInboundSMS(e *core.RequestEvent) (inboundSMSPayload, error) {
	out := inboundSMSPayload{}

	contentType := e.Request.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		if err := e.BindBody(&out); err != nil {
			return out, err
		}
		return out, nil
	}

	// Form-encoded. Parse + scan for the canonical keys. We accept any
	// case so both Plivo ("From", "Text") and Twilio ("From", "Body")
	// land in the same payload. The lower-case fallback covers
	// hand-rolled clients and curl probes.
	if err := e.Request.ParseForm(); err != nil {
		return out, err
	}
	for _, k := range []string{"From", "from"} {
		if v := e.Request.PostFormValue(k); v != "" {
			out.From = v
			break
		}
	}
	for _, k := range []string{"Body", "body", "Text", "text"} {
		if v := e.Request.PostFormValue(k); v != "" {
			out.Body = v
			break
		}
	}
	return out, nil
}

// findPreferencesByPhone locates the prefs row for the (org, phone)
// pair. The schema has a partial index on (primary_phone) so this is a
// single-row read; the rows are uniquified across orgs by inbound
// number (the same phone can only belong to one org).
func findPreferencesByPhone(app core.App, phone string) (*core.Record, error) {
	rows, err := app.FindRecordsByFilter(
		schema.Preferences,
		"primary_phone = {:phone}",
		"-created", 1, 0,
		dbx.Params{"phone": phone},
	)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// normalizeE164 strips spaces/dashes/parens and prepends '+' when
// absent. Anything that doesn't look E.164 after normalisation returns
// empty.
func normalizeE164(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r == '+':
			return r
		}
		return -1
	}, s)
	if clean == "" {
		return ""
	}
	if clean[0] != '+' {
		clean = "+" + clean
	}
	if len(clean) < 8 || len(clean) > 16 {
		return ""
	}
	return clean
}
