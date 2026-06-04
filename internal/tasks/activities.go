package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/base/core"

	"github.com/hanzoai/notify/internal/marketing"
	"github.com/hanzoai/notify/internal/metering"
	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/tenant"
	"github.com/hanzoai/notify/internal/unsubscribe"
	"github.com/hanzoai/notify/pkg/types"
)

// Activities groups the activity-level side effects so the worker can
// register a typed receiver and call sites can pass a mock during tests.
//
// The app field is the narrow [core.App] interface, not *base.Base — the
// activity only needs storage methods (FindRecordById / Save) and tests
// can therefore drive it with a tests.TestApp without booting a full
// daemon.
//
// Two resolvers, one decision: when a chainResolver is wired and the
// caller did NOT pin a specific provider (in.Provider == ""), Deliver
// uses the per-channel chain (Plivo→Twilio, SES API→SES SMTP, …). When
// either the chain resolver is absent OR the caller pinned a provider
// id, Deliver falls back to the single-provider tenant.Resolver — that
// keeps the legacy "force this exact provider" path working for tests
// and the platform UI's manual probes.
type Activities struct {
	app           core.App
	resolver      *tenant.Resolver
	chainResolver *tenant.ChainResolver

	// marketingCfg holds the RFC 8058 header builder + signer. nil
	// disables List-Unsubscribe injection — every send goes out the
	// transactional path. Required for production marketing email per
	// Gmail / Outlook bulk-sender policy.
	marketingCfg *marketing.Config
}

// NewActivities returns a fresh Activities bound to the app + resolver.
// chain may be nil — single-provider behavior is preserved.
func NewActivities(app core.App, resolver *tenant.Resolver) *Activities {
	return &Activities{app: app, resolver: resolver}
}

// NewActivitiesWithChain returns an Activities that uses chain when the
// caller did not pin a provider id, and falls back to resolver
// otherwise. Either chain or resolver may be nil; at least one must be
// non-nil for sends to succeed.
func NewActivitiesWithChain(app core.App, resolver *tenant.Resolver, chain *tenant.ChainResolver) *Activities {
	return &Activities{app: app, resolver: resolver, chainResolver: chain}
}

// WithMarketing wires the RFC 8058 header builder onto Activities. The
// caller is expected to construct marketing.Config with the same
// unsubscribe.Signer the /v1/notify/unsubscribe routes use so emitted
// links validate at the receive endpoint. nil cfg disables marketing
// injection; the activity then ships every email as transactional.
func (a *Activities) WithMarketing(cfg *marketing.Config) *Activities {
	if a == nil {
		return nil
	}
	a.marketingCfg = cfg
	return a
}

// Deliver is the only activity. It does five things in order:
//
//  1. Look up the message row (created by the route handler before dispatch).
//  2. Resolve a Notifier via tenant.Resolver.
//  3. Call the library Send.
//  4. Update message status (sent / failed).
//  5. Write a meter row.
//
// Idempotency on retries: step 1 reloads the row; if it's already in a
// terminal state (sent / failed), the activity returns the current
// result without re-sending. This handles tasks server replays without
// double-firing the SMS.
func (a *Activities) Deliver(ctx context.Context, in SendInput) (SendResult, error) {
	if a == nil {
		return SendResult{}, fmt.Errorf("activities: nil receiver")
	}
	rec, err := a.app.FindRecordById(schema.Messages, in.MessageID)
	if err != nil || rec == nil {
		return SendResult{}, fmt.Errorf("activities: load message %s: %w", in.MessageID, err)
	}
	if status := rec.GetString("status"); status == schema.MessageStatusSent || status == schema.MessageStatusFailed {
		return SendResult{
			MessageID: in.MessageID,
			Status:    status,
			Provider:  rec.GetString("provider"),
			Error:     rec.GetString("error"),
		}, nil
	}

	// Mark sending.
	rec.Set("status", schema.MessageStatusSending)
	if err := a.app.Save(rec); err != nil {
		return SendResult{}, fmt.Errorf("activities: mark sending: %w", err)
	}

	service, runResult, sendErr := a.send(ctx, in)
	if runResult != nil {
		// Persist the per-attempt trace on the row for forensics.
		// Failure-mode telemetry is the primary use case; success is
		// recorded too so a dashboard can show "Plivo failed twice
		// before Twilio won" without re-resolving the chain.
		if blob, mErr := json.Marshal(runResult); mErr == nil {
			rec.Set("metadata", string(blob))
		}
	}
	if sendErr != nil {
		return a.fail(rec, in, service, sendErr)
	}

	// Mark sent.
	now := time.Now().UTC().Format(time.RFC3339)
	rec.Set("status", schema.MessageStatusSent)
	rec.Set("provider", service)
	rec.Set("sent", now)
	if err := a.app.Save(rec); err != nil {
		return SendResult{}, fmt.Errorf("activities: mark sent: %w", err)
	}

	// Meter the send. Costs are zero in this scaffold; the catalog
	// layer fills them in when it ships.
	if _, err := metering.Write(a.app, metering.Record{
		TenantSlug:        in.TenantSlug,
		Event:             in.Event,
		Provider:          service,
		Channel:           types.Channel(in.Channel),
		Units:             1,
		VendorCostMicros:  0,
		RetailPriceMicros: 0,
		MessageID:         in.MessageID,
	}); err != nil {
		// Metering is non-fatal — the send succeeded; log via the
		// returned result and move on.
		return SendResult{
			MessageID: in.MessageID,
			Status:    schema.MessageStatusSent,
			Provider:  service,
			Error:     fmt.Sprintf("meter write failed (non-fatal): %v", err),
		}, nil
	}
	return SendResult{
		MessageID: in.MessageID,
		Status:    schema.MessageStatusSent,
		Provider:  service,
	}, nil
}

// send picks between the single-provider resolver and the multi-
// provider chain. Decision matrix:
//
//   in.Provider != ""           → single-provider (caller pinned)
//   chainResolver == nil        → single-provider (no chain wired)
//   otherwise                    → chain
//
// On the chain path, marketing-class email (in.Category in the §3.2
// marketing buckets AND in.Channel == "email") routes through the
// chain's RunMarketing — that mints an unsubscribe token, appends a
// visible footer, and injects RFC 8058 List-Unsubscribe headers on
// SES (the only provider whose SDK requires raw-MIME for headers).
// Every other path is unchanged.
//
// Returns the provider id that actually sent (winner), the optional
// chain-run result (nil on single-provider path), and the terminal
// error (nil on success).
func (a *Activities) send(ctx context.Context, in SendInput) (string, *tenant.RunResult, error) {
	if in.Provider != "" || a.chainResolver == nil {
		if a.resolver == nil {
			return "", nil, fmt.Errorf("activities: no resolver configured (single-provider path requires tenant.Resolver)")
		}
		notifier, service, err := a.resolver.Resolve(ctx, in.TenantSlug, in.Channel, in.Provider, []string{in.To})
		if err != nil {
			return "", nil, fmt.Errorf("resolve: %w", err)
		}
		if err := notifier.Send(ctx, in.Subject, in.Body); err != nil {
			return service, nil, err
		}
		return service, nil, nil
	}

	// Marketing-class email goes through the marketing chain so the
	// List-Unsubscribe machinery lands on the recipient. The branch is
	// gated on (a) email channel — SMS/voice/WhatsApp have their own
	// opt-out semantics (STOP keyword), (b) IsMarketing(category), and
	// (c) marketingCfg + signer wired at boot. Misconfiguration in the
	// last case is a fatal at the cmd/notifyd boot, not a quiet
	// downgrade here.
	channel := tenant.ChainChannel(in.Channel)
	if a.shouldUseMarketing(in) {
		channel = tenant.ChainEmailMarketing
	}
	chain, err := a.chainResolver.Resolve(ctx, in.TenantSlug, channel)
	if err != nil {
		return "", nil, fmt.Errorf("chain resolve: %w", err)
	}
	if a.shouldUseMarketing(in) {
		headers, footerURL, sigErr := a.signMarketing(in)
		if sigErr != nil {
			return "", nil, fmt.Errorf("marketing sign: %w", sigErr)
		}
		body := in.Body
		if in.IsHTML {
			body = marketing.AppendHTMLFooter(body, footerURL)
		} else {
			body = marketing.AppendPlainFooter(body, footerURL)
		}
		result, runErr := chain.RunMarketing(ctx, in.To, in.Subject, body, in.IsHTML, headers)
		if runErr != nil {
			return result.Winner, &result, runErr
		}
		return result.Winner, &result, nil
	}
	result, runErr := chain.Run(ctx, in.To, in.Subject, in.Body)
	if runErr != nil {
		return result.Winner, &result, runErr
	}
	return result.Winner, &result, nil
}

// shouldUseMarketing folds the three gates into one predicate: email
// channel, marketing category, marketingCfg wired. Anything else stays
// on the transactional path.
func (a *Activities) shouldUseMarketing(in SendInput) bool {
	if a == nil || a.marketingCfg == nil {
		return false
	}
	if in.Channel != string(types.ChannelEmail) {
		return false
	}
	return marketing.IsMarketing(in.Category)
}

// signMarketing mints a fresh unsubscribe token, persists a
// notification_unsubscribe_tokens row so the consumer endpoint can mark
// it consumed, and returns the (headers, footerURL) pair ready to
// inject into the send.
//
// Token persistence happens BEFORE the send to avoid a race where SES
// accepts the email and Gmail's bulk-sender check sees a valid header
// link, but our DB has no record of the token. The user click would
// then hit /unsubscribe with a known-good HMAC but no row to mark
// consumed, and the route would silently fall through to confirmation
// without an audit trail. Persisting first guarantees the row exists.
func (a *Activities) signMarketing(in SendInput) (map[string]string, string, error) {
	now := time.Now().UTC()
	headers, err := a.marketingCfg.Build(in.UserID, in.Category, now, unsubscribe.Default30Days)
	if err != nil {
		return nil, "", err
	}
	// The token is the suffix of the HTTPS URL the builder constructs.
	// Pulling it back out is cheaper than rebuilding it from scratch
	// and stays in lock-step with whatever path the builder chooses.
	token := extractToken(headers.URL)
	if token == "" {
		return nil, "", fmt.Errorf("marketing: empty token from builder URL %q", headers.URL)
	}
	expiresAt := now.Add(unsubscribe.Default30Days)
	if err := a.persistToken(token, in, expiresAt); err != nil {
		return nil, "", err
	}
	return map[string]string{
		marketing.HeaderListUnsubscribe:     headers.ListUnsubscribe,
		marketing.HeaderListUnsubscribePost: headers.ListUnsubscribePost,
	}, headers.URL, nil
}

// persistToken upserts a row in notification_unsubscribe_tokens so the
// unsubscribe handler can find it on click. Idempotent: a pre-existing
// row for the same token (cosmically unlikely with HMAC + 30-day TTL,
// but covered) is left alone.
//
// "created" is set automatically by the schema's AutodateField; we
// only need to set the mutable columns here.
func (a *Activities) persistToken(token string, in SendInput, expiresAt time.Time) error {
	if rec, _ := a.app.FindRecordById(schema.UnsubscribeTokens, token); rec != nil {
		return nil
	}
	col, err := a.app.FindCollectionByNameOrId(schema.UnsubscribeTokens)
	if err != nil {
		return fmt.Errorf("find unsubscribe collection: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("id", token)
	rec.Set("user_id", in.UserID)
	rec.Set("tenant", in.TenantSlug)
	rec.Set("category", in.Category)
	rec.Set("expires_at", expiresAt.Format(time.RFC3339))
	return a.app.Save(rec)
}

// extractToken returns the path-escaped token suffix of an unsubscribe
// URL. Empty when the URL is malformed; the caller treats that as a
// signing failure rather than silently shipping an unverifiable link.
func extractToken(url string) string {
	const marker = "/v1/notify/unsubscribe/"
	idx := strings.LastIndex(url, marker)
	if idx < 0 {
		return ""
	}
	return url[idx+len(marker):]
}

// fail records the failure on the message row and returns the matching
// SendResult. Returning a nil error from the activity is intentional —
// the workflow keeps the failure as data (in the row), and the tasks
// server records the run as completed; clients see status="failed"
// when they look up the message.
func (a *Activities) fail(rec *core.Record, in SendInput, service string, cause error) (SendResult, error) {
	rec.Set("status", schema.MessageStatusFailed)
	rec.Set("error", cause.Error())
	if service != "" {
		rec.Set("provider", service)
	}
	if saveErr := a.app.Save(rec); saveErr != nil {
		// If we couldn't even record the failure, surface the original
		// to the tasks server so it retries the activity.
		return SendResult{}, fmt.Errorf("activities: cannot persist failure (%v): original=%w", saveErr, cause)
	}
	return SendResult{
		MessageID: in.MessageID,
		Status:    schema.MessageStatusFailed,
		Provider:  service,
		Error:     cause.Error(),
	}, nil
}
