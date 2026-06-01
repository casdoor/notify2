package tasks

import (
	"context"
	"fmt"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"

	"github.com/hanzoai/notify/internal/metering"
	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/tenant"
	"github.com/hanzoai/notify/pkg/types"
)

// Activities groups the activity-level side effects so the worker can
// register a typed receiver and call sites can pass a mock during tests.
type Activities struct {
	app      *base.Base
	resolver *tenant.Resolver
}

// NewActivities returns a fresh Activities bound to the app + resolver.
func NewActivities(app *base.Base, resolver *tenant.Resolver) *Activities {
	return &Activities{app: app, resolver: resolver}
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

	notifier, service, err := a.resolver.Resolve(ctx, in.TenantSlug, in.Channel, in.Provider, []string{in.To})
	if err != nil {
		return a.fail(rec, in, "", fmt.Errorf("resolve: %w", err))
	}
	if err := notifier.Send(ctx, in.Subject, in.Body); err != nil {
		return a.fail(rec, in, service, err)
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
