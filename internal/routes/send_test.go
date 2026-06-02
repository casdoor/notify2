package routes

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tests"

	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/tasks"
	"github.com/hanzoai/notify/internal/tenant"
)

// schemaOnce mirrors the helper in tasks/activities_test.go — both test
// packages call schema.MustRegister exactly once per binary so the
// global core.AppMigrations list stays tidy across parallel runs.
var schemaOnce sync.Once

func registerSchema() {
	schemaOnce.Do(func() {
		schema.MustRegister(nil)
	})
}

// stubDispatcher is the in-memory test double for tasks.Dispatcher.
// Tests configure it per-case to assert call shape and return either
// a fixed task id or a synthetic error.
type stubDispatcher struct {
	started  bool
	taskID   string
	err      error
	calls    int
	lastInput tasks.SendInput
	mu       sync.Mutex
}

func (s *stubDispatcher) Dispatch(_ context.Context, in tasks.SendInput) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastInput = in
	if s.err != nil {
		return "", s.err
	}
	return s.taskID, nil
}

func (s *stubDispatcher) Started() bool { return s.started }

// TestSend_AsyncDefault_Returns202 documents the canonical happy path
// after the wiring change: POST /v1/notify/send with no ?sync flag
// enqueues via the Dispatcher and returns 202 Accepted with a
// {message_id, task_id, status: "queued"} payload. The provider is
// never resolved — that happens asynchronously inside the worker.
func TestSend_AsyncDefault_Returns202(t *testing.T) {
	t.Parallel()
	registerSchema()

	disp := &stubDispatcher{started: true, taskID: "wf-async-1"}

	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/send (async)",
		Method:         http.MethodPost,
		URL:            "/v1/notify/send",
		Body:           strings.NewReader(`{"to":["+15555550100"],"channel":"sms","body":"hello"}`),
		Headers:        map[string]string{"X-Org-Id": "test-org"},
		ExpectedStatus: http.StatusAccepted,
		ExpectedContent: []string{
			`"task_id":"wf-async-1"`,
			`"status":"queued"`,
			`"message_id"`,
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountSend(e.Router, app, Config{
				Resolver:   tenant.New(app, nil),
				Dispatcher: disp,
			})
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			if disp.calls != 1 {
				t.Fatalf("expected Dispatch to be called once, got %d", disp.calls)
			}
			if disp.lastInput.TenantSlug != "test-org" {
				t.Fatalf("expected TenantSlug=test-org, got %q", disp.lastInput.TenantSlug)
			}
			if disp.lastInput.Channel != "sms" {
				t.Fatalf("expected Channel=sms, got %q", disp.lastInput.Channel)
			}
			if disp.lastInput.MessageID == "" {
				t.Fatalf("expected non-empty MessageID in Dispatch input")
			}
		},
	}
	scenario.Test(t)
}

// TestSend_SyncQueryFlag_Returns200 documents that ?sync=true switches
// the handler to in-process delivery and returns 200 with the terminal
// result. With no provider configured the activity short-circuits to
// status=failed (resolve error), which is exactly what the wire
// contract promises for sync mode.
func TestSend_SyncQueryFlag_Returns200(t *testing.T) {
	t.Parallel()
	registerSchema()

	disp := &stubDispatcher{started: true, taskID: "should-not-be-used"}

	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/send?sync=true",
		Method:         http.MethodPost,
		URL:            "/v1/notify/send?sync=true",
		Body:           strings.NewReader(`{"to":["+15555550100"],"channel":"sms","body":"hello"}`),
		Headers:        map[string]string{"X-Org-Id": "test-org"},
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{
			`"status":"failed"`,
			`"message_id"`,
		},
		// task_id MUST be absent on the sync path — empty fields are
		// omitted by the JSON encoder (`json:"task_id,omitempty"`).
		NotExpectedContent: []string{`"task_id":"should-not-be-used"`, `"task_id":"wf-`},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountSend(e.Router, app, Config{
				Resolver:   tenant.New(app, nil),
				Dispatcher: disp,
			})
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			if disp.calls != 0 {
				t.Fatalf("expected Dispatch to NOT be called on sync path, got %d", disp.calls)
			}
		},
	}
	scenario.Test(t)
}

// TestSend_AsyncNoDispatcher_Returns503 fails closed when async is
// requested (the default) but the binary booted without a worker. We
// will not silently degrade to sync — that would hide a production
// misconfiguration per hanzoai/tasks CONTRACT.md §3.
func TestSend_AsyncNoDispatcher_Returns503(t *testing.T) {
	t.Parallel()
	registerSchema()

	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/send (no dispatcher)",
		Method:         http.MethodPost,
		URL:            "/v1/notify/send",
		Body:           strings.NewReader(`{"to":["+15555550100"],"channel":"sms","body":"hello"}`),
		Headers:        map[string]string{"X-Org-Id": "test-org"},
		ExpectedStatus: http.StatusServiceUnavailable,
		ExpectedContent: []string{"sync dispatch unavailable", `"status":503`, "hanzoai/tasks worker"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			// Dispatcher omitted on purpose.
			mountSend(e.Router, app, Config{Resolver: tenant.New(app, nil)})
		},
	}
	scenario.Test(t)
}

// TestSend_AsyncDispatcherNotStarted_Returns503 is the same fail-closed
// guarantee but for the case where a worker is configured yet has not
// connected (e.g. tasksd unreachable at boot). The Started() probe is
// the route's single source of truth for async availability.
func TestSend_AsyncDispatcherNotStarted_Returns503(t *testing.T) {
	t.Parallel()
	registerSchema()

	disp := &stubDispatcher{started: false}

	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/send (dispatcher not started)",
		Method:         http.MethodPost,
		URL:            "/v1/notify/send",
		Body:           strings.NewReader(`{"to":["+15555550100"],"channel":"sms","body":"hello"}`),
		Headers:        map[string]string{"X-Org-Id": "test-org"},
		ExpectedStatus: http.StatusServiceUnavailable,
		ExpectedContent: []string{"sync dispatch unavailable", `"status":503`, "hanzoai/tasks worker"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountSend(e.Router, app, Config{
				Resolver:   tenant.New(app, nil),
				Dispatcher: disp,
			})
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			if disp.calls != 0 {
				t.Fatalf("expected Dispatch NOT to be called when Started=false, got %d", disp.calls)
			}
		},
	}
	scenario.Test(t)
}

// TestSend_DispatchError_Returns500 covers the lower-frequency case
// where the dispatcher is connected and Started but the ExecuteWorkflow
// RPC fails (network blip, opcode rejected). The route surfaces the
// error to the client; the caller decides whether to retry.
func TestSend_DispatchError_Returns500(t *testing.T) {
	t.Parallel()
	registerSchema()

	disp := &stubDispatcher{started: true, err: errors.New("tasksd: connection refused")}

	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/send (dispatch fails)",
		Method:         http.MethodPost,
		URL:            "/v1/notify/send",
		Body:           strings.NewReader(`{"to":["+15555550100"],"channel":"sms","body":"hello"}`),
		Headers:        map[string]string{"X-Org-Id": "test-org"},
		ExpectedStatus: http.StatusInternalServerError,
		ExpectedContent: []string{`"status":500`},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountSend(e.Router, app, Config{
				Resolver:   tenant.New(app, nil),
				Dispatcher: disp,
			})
		},
	}
	scenario.Test(t)
}

// TestSend_MissingOrgHeader_Returns401 asserts the auth precondition.
// X-Org-Id comes from the platform plugin (it derives the value from
// the IAM-issued JWT). Without it the request is anonymous, and notify
// has no anonymous send surface.
func TestSend_MissingOrgHeader_Returns401(t *testing.T) {
	t.Parallel()
	registerSchema()

	disp := &stubDispatcher{started: true, taskID: "wf-x"}
	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/send (no X-Org-Id)",
		Method:         http.MethodPost,
		URL:            "/v1/notify/send",
		Body:           strings.NewReader(`{"to":["+15555550100"],"channel":"sms","body":"hello"}`),
		ExpectedStatus: http.StatusUnauthorized,
		ExpectedContent: []string{"X-Org-Id"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			mountSend(e.Router, app, Config{
				Resolver:   tenant.New(app, nil),
				Dispatcher: disp,
			})
		},
	}
	scenario.Test(t)
}

// seedTenant inserts a tenants row so subsequent message inserts (which
// reference it via the `tenant` relation field) succeed.
func seedTenant(t testing.TB, app core.App, slug string) {
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
}
