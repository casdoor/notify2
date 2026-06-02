package tasks

import (
	"context"
	"sync"
	"testing"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tests"

	"github.com/hanzoai/notify/internal/schema"
)

// schemaRegistration ensures the notify migration is registered into
// core.AppMigrations exactly once per test binary. core.AppMigrations
// is a process-global list and Register appends; multiple test files
// calling it would duplicate the migration entry (the migration up
// step is itself idempotent, but the runner would still record N rows
// in the _migrations table). One Once keeps the registration crisp.
var schemaRegistration sync.Once

func registerSchemaOnce() {
	schemaRegistration.Do(func() {
		schema.MustRegister(nil)
	})
}

// TestDeliver_Idempotent_SentShortCircuits documents that the Deliver
// activity is replay-safe on a message whose row is already in the
// terminal "sent" state. The tasks server retries activities on
// transient failures (worker death, panic, timeout); if Deliver had
// already succeeded once, re-running it MUST NOT re-fire the provider
// — otherwise a single user would receive the same SMS twice.
//
// The contract: when status=sent, Deliver returns the existing result
// with no further side effects. We assert that by passing a nil
// resolver — any call into it would panic — and confirming Deliver
// completes cleanly.
func TestDeliver_Idempotent_SentShortCircuits(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	tenantID := mustMakeTenant(t, app, "test-org")
	msgID := mustMakeMessage(t, app, tenantID, schema.MessageStatusSent, "plivo")

	// Nil resolver — Deliver MUST short-circuit before any field access.
	acts := NewActivities(app, nil)

	res, err := acts.Deliver(context.Background(), SendInput{
		MessageID:  msgID,
		TenantSlug: "test-org",
		Channel:    "sms",
		To:         "+15555550100",
		Body:       "hello",
	})
	if err != nil {
		t.Fatalf("Deliver returned error on already-sent row: %v", err)
	}
	if res.Status != schema.MessageStatusSent {
		t.Fatalf("expected status=%q, got %q", schema.MessageStatusSent, res.Status)
	}
	if res.Provider != "plivo" {
		t.Fatalf("expected provider=plivo (carried from row), got %q", res.Provider)
	}
	if res.MessageID != msgID {
		t.Fatalf("expected message id=%q, got %q", msgID, res.MessageID)
	}
}

// TestDeliver_Idempotent_FailedShortCircuits is the same guarantee as
// the sent case but for the failed terminal state. A failed run also
// must not re-attempt — otherwise a permanently-bad recipient (e.g.
// blacklisted number) would chew through retries on every replay.
func TestDeliver_Idempotent_FailedShortCircuits(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	tenantID := mustMakeTenant(t, app, "test-org")
	msgID := mustMakeMessageWithError(t, app, tenantID, schema.MessageStatusFailed, "plivo", "carrier rejected")

	acts := NewActivities(app, nil)

	res, err := acts.Deliver(context.Background(), SendInput{
		MessageID:  msgID,
		TenantSlug: "test-org",
		Channel:    "sms",
		To:         "+15555550100",
		Body:       "hello",
	})
	if err != nil {
		t.Fatalf("Deliver returned error on already-failed row: %v", err)
	}
	if res.Status != schema.MessageStatusFailed {
		t.Fatalf("expected status=%q, got %q", schema.MessageStatusFailed, res.Status)
	}
	if res.Error != "carrier rejected" {
		t.Fatalf("expected error=%q (carried from row), got %q", "carrier rejected", res.Error)
	}
}

// TestDeliver_NilReceiver returns a clear error. Activities pre-validate
// their own receiver so a programming mistake at registration surfaces
// before any storage access.
func TestDeliver_NilReceiver(t *testing.T) {
	t.Parallel()
	var a *Activities
	_, err := a.Deliver(context.Background(), SendInput{MessageID: "x"})
	if err == nil {
		t.Fatalf("expected error from nil receiver, got nil")
	}
}

// --- helpers ---

// newTestApp boots a fresh Base test app with the notify schema applied.
// The migration is registered exactly once per test binary by an init
// shim so parallel tests share the same registration.
func newTestApp(t *testing.T) core.App {
	t.Helper()
	registerSchemaOnce()
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("tests.NewTestApp: %v", err)
	}
	t.Cleanup(app.Cleanup)
	return app
}

// mustMakeTenant inserts a tenants row and returns the slug (which is
// also the row id under the schema's PRIMARY KEY-style id-as-slug rule).
func mustMakeTenant(t *testing.T, app core.App, slug string) string {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(schema.Tenants)
	if err != nil {
		t.Fatalf("find tenants collection: %v", err)
	}
	rec := core.NewRecord(col)
	rec.Set("id", slug)
	rec.Set("name", slug)
	if err := app.Save(rec); err != nil {
		t.Fatalf("save tenant: %v", err)
	}
	return rec.Id
}

// mustMakeMessage inserts a messages row in the given status and
// returns its id. Used to seed terminal-state rows for idempotency
// tests so we never actually wire a provider.
func mustMakeMessage(t *testing.T, app core.App, tenant, status, provider string) string {
	t.Helper()
	return mustMakeMessageWithError(t, app, tenant, status, provider, "")
}

func mustMakeMessageWithError(t *testing.T, app core.App, tenant, status, provider, errMsg string) string {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(schema.Messages)
	if err != nil {
		t.Fatalf("find messages collection: %v", err)
	}
	rec := core.NewRecord(col)
	rec.Set("tenant", tenant)
	rec.Set("channel", "sms")
	rec.Set("provider", provider)
	rec.Set("to", "+15555550100")
	rec.Set("body", "hello")
	rec.Set("status", status)
	rec.Set("error", errMsg)
	if err := app.Save(rec); err != nil {
		t.Fatalf("save message: %v", err)
	}
	return rec.Id
}
